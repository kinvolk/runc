#!/usr/bin/env bats

load helpers

function setup() {
  teardown_busybox
  setup_busybox
  mkdir -p "$BUSYBOX_BUNDLE"/source-{accessible,inaccessible}/dir
  chmod 750 "$BUSYBOX_BUNDLE"/source-inaccessible
  mkdir -p "$BUSYBOX_BUNDLE"/rootfs/{proc,sys,tmp}
  mkdir -p "$BUSYBOX_BUNDLE"/rootfs/tmp/{accessible,inaccessible}
  update_config ' .process.args += ["-c", "echo HelloWorld"] '
  update_config ' .linux.namespaces += [{"type": "user"}]
		| .linux.uidMappings += [{"hostID": 100000, "containerID": 0, "size": 65534}]
		| .linux.gidMappings += [{"hostID": 100000, "containerID": 0, "size": 65534}] '
  # TODO: not sure why it is necessary?
  update_config '(.. | select(.readonly? != null)) .readonly |= false'
}

function teardown() {
  teardown_busybox
  teardown_running_container test_userns_with_simple_mount
  teardown_running_container test_userns_with_difficult_mount
}

@test "userns without mount" {
  # TODO: implement another test for rootless container with runc_rootless_idmap()
  requires root
  runc run test_userns_without_mount
  [ "$status" -eq 0 ]

  [[ "${output}" == *"HelloWorld"* ]]
}

@test "userns with simple mount" {
  # TODO: implement another test for rootless container with runc_rootless_idmap()
  requires root
  update_config ' .mounts += [{"source": "source-accessible/dir", "destination": "/tmp/accessible", "options": ["bind"]}] '

  runc run test_userns_with_simple_mount
  [ "$status" -eq 0 ]

  [[ "${output}" == *"HelloWorld"* ]]
}

@test "userns with inaccessible mount" {
  # TODO: implement another test for rootless container with runc_rootless_idmap()
  # NOTE: this scenario does not currently work in a rootless container
  requires root
  update_config ' .mounts += [{"source": "source-inaccessible/dir", "destination": "/tmp/inaccessible", "options": ["bind"]}] '

  runc run test_userns_with_difficult_mount
  [ "$status" -eq 0 ]

  [[ "${output}" == *"HelloWorld"* ]]
}
