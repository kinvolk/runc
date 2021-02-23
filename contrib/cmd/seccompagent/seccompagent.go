// +build linux,cgo,seccomp

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"syscall"

	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

/*
#define _GNU_SOURCE
#include <stdio.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>

struct _mydef_seccomp_notif_addfd {
  __u64 id;
  __u32 flags;
  __u32 srcfd;
  __u32 newfd;
  __u32 newfd_flags;
};

#define SECCOMP_IOC_MAGIC		'!'
#define SECCOMP_IO(nr)			_IO(SECCOMP_IOC_MAGIC, nr)
#define SECCOMP_IOR(nr, type)		_IOR(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOW(nr, type)		_IOW(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOWR(nr, type)		_IOWR(SECCOMP_IOC_MAGIC, nr, type)

#ifndef SECCOMP_ADDFD_FLAG_SETFD
#define SECCOMP_ADDFD_FLAG_SETFD (1UL << 0)
#endif

#ifndef SECCOMP_ADDFD_FLAG_SEND
#define SECCOMP_ADDFD_FLAG_SEND	(1UL << 1) // Addfd and return it, atomically
#endif

#ifndef SECCOMP_IOCTL_NOTIF_ADDFD
#define SECCOMP_IOCTL_NOTIF_ADDFD                                              \
  SECCOMP_IOW(3, struct _mydef_seccomp_notif_addfd)
#endif

int replace_fd(__u64 id, int notify_fd, int fd) {
	struct _mydef_seccomp_notif_addfd addfd = {
		.id = id,
		//.flags = 0,
		.flags = SECCOMP_ADDFD_FLAG_SEND,
		.srcfd = fd,
		.newfd = 0,
		.newfd_flags = 0,
	};
	int ret = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);

	//printf("newfd is %d\n", addfd.newfd);

	printf("return code of ioctl is %d\n", ret);
	return ret;
}

*/
import "C"

var (
	socketFile string
	pidFile    string
)

func init() {
	flag.StringVar(&socketFile, "socketfile", "/run/seccomp-agent.socket", "Socket file")
	flag.StringVar(&pidFile, "pid-file", "", "Pid file")
	logrus.SetLevel(logrus.DebugLevel)
}

func handleNewMessage(sockfd int) (*os.File, string, error) {
	MaxNameLen := 4096
	oobSpace := unix.CmsgSpace(4)
	stateBuf := make([]byte, 4096)
	oob := make([]byte, oobSpace)

	n, oobn, _, _, err := unix.Recvmsg(sockfd, stateBuf, oob, 0)
	if err != nil {
		return nil, "", err
	}
	if n >= MaxNameLen || oobn != oobSpace {
		return nil, "", fmt.Errorf("recvfd: incorrect number of bytes read (n=%d oobn=%d)", n, oobn)
	}

	// Truncate.
	stateBuf = stateBuf[:n]
	oob = oob[:oobn]

	state := &specs.ContainerProcessState{}
	err = json.Unmarshal(stateBuf, state)
	if err != nil {
		return nil, "", fmt.Errorf("cannot parse OCI state: %v\n", err)
	}
	logrus.Debugf("received ContinerProcessState: %v\n", string(stateBuf))

	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, "", err
	}
	if len(scms) != 1 {
		return nil, "", fmt.Errorf("recvfd: number of SCMs is not 1: %d", len(scms))
	}
	scm := scms[0]

	fds, err := unix.ParseUnixRights(&scm)
	if err != nil {
		return nil, "", err
	}

	fdIndex := -1
	for i, fdName := range state.Fds {
		if fdName == "seccompFd" {
			fdIndex = i
		} else {
			// close other file descriptors we're not interested in.
			unix.Close(fds[i])
		}
	}

	if fdIndex == -1 {
		return nil, "", fmt.Errorf("seccomp fd not found")
	}

	if len(fds) < fdIndex {
		return nil, "", fmt.Errorf("seccomp fd index out of range")
	}

	fd := uintptr(fds[fdIndex])
	return os.NewFile(fd, "seccomp-fd"), state.Metadata, nil
}

func readArgString(pid uint32, offset int64) (string, error) {
	var buffer = make([]byte, 4096) // PATH_MAX

	memfd, err := unix.Open(fmt.Sprintf("/proc/%d/mem", pid), unix.O_RDONLY, 0777)
	if err != nil {
		return "", err
	}
	defer unix.Close(memfd)

	_, err = unix.Pread(memfd, buffer, offset)
	if err != nil {
		return "", err
	}

	buffer[len(buffer)-1] = 0
	s := buffer[:bytes.IndexByte(buffer, 0)]
	return string(s), nil
}

func runOpenForContainer() int {
	fd, err := syscall.Open("/tmp/devnull2", 0, 0)
	if err != nil {
		return -1
	}

	return fd
}

// notifHandler handles seccomp notifications and responses
func notifHandler(fd libseccomp.ScmpFd, metadata string) {
	defer unix.Close(int(fd))
	for {
		req, err := libseccomp.NotifReceive(fd)
		if err != nil {
			logrus.Errorf("Error in NotifReceive(): %s", err)
			continue
		}
		syscallName, err := req.Data.Syscall.GetName()
		if err != nil {
			logrus.Errorf("Error decoding syscall %v(): %s", req.Data.Syscall, err)
			continue
		}
		logrus.Debugf("Received syscall %q, pid %v, arch %q, args %+v\n", syscallName, req.Pid, req.Data.Arch, req.Data.Args)

		resp := &libseccomp.ScmpNotifResp{
			ID:    req.ID,
			Error: 0,
			Val:   0,
			Flags: libseccomp.NotifRespFlagContinue,
		}

		// TOCTOU check
		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			logrus.Errorf("TOCTOU check failed: req.ID is no longer valid: %s", err)
			//resp.Error = int32(unix.ENOSYS)
			//resp.Val = ^uint64(0) // -1
			continue
		}

		switch syscallName {
		case "openat":
			fileName, err := readArgString(req.Pid, int64(req.Data.Args[1]))
			if err != nil {
				logrus.Debugf("Cannot read argument: %s", err)
			}

			if fileName == "/dev/null2" {
				fileFd := runOpenForContainer()
				//logrus.Debugf("fd of file is %d\n", fileFd)
				if fileFd == -1 {
					logrus.Debugf("failed to open file\n")
					resp.Error = int32(unix.ENOMEDIUM)
					resp.Val = ^uint64(0)
					goto sendResponse
				}

				ret := C.replace_fd(C.ulonglong(req.ID), C.int(fd), C.int(fileFd))
				if int(ret) == -1 {
					logrus.Debugf("replace_fd failed\n")
					resp.Error = int32(unix.ENOMEDIUM)
					resp.Val = ^uint64(0)
				} else {
					resp.Val = uint64(ret)
				}

				resp.Flags = 0 // do not continue with the syscall
				unix.Close(fileFd)
				continue
			}
			goto sendResponse
		}

	sendResponse:
		if err = libseccomp.NotifRespond(fd, resp); err != nil {
			logrus.Errorf("Error in notification response: %s", err)
			continue
		}
	}
}

func main() {
	// Parse arguments
	flag.Parse()
	if flag.NArg() > 0 {
		flag.PrintDefaults()
		logrus.Fatal("Invalid command")
	}

	if err := os.RemoveAll(socketFile); err != nil {
		logrus.Fatalf("Cannot cleanup socket file %s: %v", socketFile, err)
	}

	if pidFile != "" {
		pid := fmt.Sprintf("%d\n", os.Getpid())
		if err := ioutil.WriteFile(pidFile, []byte(pid), 0644); err != nil {
			logrus.Fatalf("Cannot write pid file %s: %v", pidFile, err)
		}
	}

	logrus.Info("Waiting for seccomp file descriptors")
	l, err := net.Listen("unix", socketFile)
	if err != nil {
		logrus.Fatalf("Cannot listen on %s: %s", socketFile, err)
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			logrus.Errorf("Cannot accept connection: %s", err)
			continue
		}
		socket, err := conn.(*net.UnixConn).File()
		conn.Close()
		if err != nil {
			logrus.Errorf("Cannot get socket: %v\n", err)
			continue
		}
		newFd, metadata, err := handleNewMessage(int(socket.Fd()))
		socket.Close()
		if err != nil {
			logrus.Errorf("Error receiving seccomp file descriptor: %v", err)
			continue
		}
		logrus.Infof("Received new seccomp fd: %v\n", newFd.Fd())
		go notifHandler(libseccomp.ScmpFd(newFd.Fd()), metadata)
	}
}
