#!/usr/bin/env bats

load helpers

function setup() {
	teardown_busybox
	setup_busybox

	# Prepare source folders for bind mount
	mkdir -p "$BUSYBOX_BUNDLE"/source-{accessible,inaccessible}/dir
	touch "$BUSYBOX_BUNDLE"/source-{accessible,inaccessible}/dir/foo.txt
	chmod 750 "$BUSYBOX_BUNDLE"/source-inaccessible
	mkdir -p "$BUSYBOX_BUNDLE"/rootfs/{proc,sys,tmp}
	mkdir -p "$BUSYBOX_BUNDLE"/rootfs/tmp/mount

	if [ "$ROOTLESS" -eq 0 ]; then
		update_config ' .linux.namespaces += [{"type": "user"}]
			| .linux.uidMappings += [{"hostID": 100000, "containerID": 0, "size": 65534}]
			| .linux.gidMappings += [{"hostID": 100000, "containerID": 0, "size": 65534}] '
	fi
}

function teardown() {
	teardown_busybox
}

@test "userns with simple mount" {
	update_config ' .process.args += ["-c", "stat /tmp/mount/foo.txt"] '
	update_config ' .mounts += [{"source": "source-accessible/dir", "destination": "/tmp/mount", "options": ["bind"]}] '

	runc run test_busybox
	[ "$status" -eq 0 ]
}

@test "userns with inaccessible mount" {
	update_config ' .process.args += ["-c", "stat /tmp/mount/foo.txt"] '
	update_config ' .mounts += [{"source": "source-inaccessible/dir", "destination": "/tmp/mount", "options": ["bind"]}] '

	runc run test_busybox
	[ "$status" -eq 0 ]
}

# exec + bindmounts + user ns is a special case in the code. Test that it works.
@test "userns with inaccessible mount + exec" {
	update_config ' .mounts += [{"source": "source-inaccessible/dir", "destination": "/tmp/mount", "options": ["bind"]}] '

	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	runc exec --pid-file pid.txt test_busybox stat /tmp/mount/foo.txt
	[ "$status" -eq 0 ]
}
