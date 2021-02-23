package main

import (
	"fmt"
	//"runtime"
	"time"

	"syscall"
)

func main() {
	//runtime.LockOSThread()
	for {
	again:
		fd, err := syscall.Openat(0, "/dev/null2", 0, 0)
		if err != nil {
			if err == syscall.EINTR {
				fmt.Printf("interrumpted\n")
				goto again
			}

			fmt.Printf("failed to open file\n")
			time.Sleep(1 * time.Second)
		}

		if fd > 0 {
			fmt.Printf("fd was: %d\n", fd)
			syscall.Close(fd)
		}

		//time.Sleep(1 * time.Second)
	}
}
