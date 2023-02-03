package configs

import (
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/user"
)

type Mount struct {
	// Source path for the mount.
	Source string `json:"source"`

	// Destination path for the mount inside the container.
	Destination string `json:"destination"`

	// Device the mount is for.
	Device string `json:"device"`

	// Mount flags.
	Flags int `json:"flags"`

	// Propagation Flags
	PropagationFlags []int `json:"propagation_flags"`

	// Mount data applied to the mount.
	Data string `json:"data"`

	// Relabel source if set, "z" indicates shared, "Z" indicates unshared.
	Relabel string `json:"relabel"`

	// RecAttr represents mount properties to be applied recursively (AT_RECURSIVE), see mount_setattr(2).
	RecAttr *unix.MountAttr `json:"rec_attr"`

	// Extensions are additional flags that are specific to runc.
	Extensions int `json:"extensions"`

	// UID/GID mappings used for changing file owners w/o calling chown, fs should support it.
	// Every mount point could have its own mapping.
	UIDMaps []user.IDMap `json:"uidMappings"`
	GIDMaps []user.IDMap `json:"gidMappings"`
}

func (m *Mount) IsBind() bool {
	return m.Flags&unix.MS_BIND != 0
}

// TODO: rename to IsIDMap(). We are using capital ID in other parts.
func (m *Mount) IsIdMap() bool {
	return m.IsBind() && (len(m.UIDMaps) > 0 || len(m.GIDMaps) > 0)
}
