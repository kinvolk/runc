#!/usr/bin/env bats

load helpers

function setup() {
	teardown_seccompagent
	setup_seccompagent

	teardown_busybox
	setup_busybox
}

function teardown() {
	teardown_seccompagent
	teardown_busybox
}

@test "runc run (seccomp notify tests)" {
	requires root
	requires no_systemd
	# to fetch the seccomp fd, runc uses the pidfd_getfd system call,
	# available in Linux >= 5.6
	# https://github.com/torvalds/linux/commit/8649c322f75c96e7ced2fec201e123b2b073bf09
	if [[ "$KERNEL_MAJOR" -lt 5 || ("$KERNEL_MAJOR" -eq 5 && "$KERNEL_MINOR" -lt 6) ]]; then
		skip "requires kernel 5.6"
	fi

	# The agent intercepts mkdir syscalls and creates the folder appending
	# "-bar" (listenerMetadata below) to the name.
	update_config '.process.args = ["/bin/sh", "-c", "mkdir /dev/shm/foo && stat /dev/shm/foo-bar"] |
		.linux.seccomp = {
			"defaultAction":"SCMP_ACT_ALLOW",
			"listenerPath": "'"$SECCCOMP_AGENT_SOCKET"'",
			"listenerMetadata": "bar",
			"architectures":["SCMP_ARCH_X86","SCMP_ARCH_X32"],
			"syscalls":[{"names":["mkdir"], "action":"SCMP_ACT_NOTIFY"}]
		}'

	runc run test_busybox
	[ "$status" -eq 0 ]
}
