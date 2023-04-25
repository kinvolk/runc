#ifndef IDMAP_H
#define IDMAP_H

#include <sys/mount.h>
// Centos-7 doesn't have this file nor the __has_include() directive, so let's
// just leave this commented out and we can uncomment when it hits EOL (2024-06-30).
//#include <linux/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

/* mount_setattr() */
#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP 0x00100000
#endif

#ifndef MOUNT_ATTR_SIZE_VER0
struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};
#define MOUNT_ATTR_SIZE_VER0    32
#endif

/* open_tree() */
#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif

#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif

// XXX: rata.
// We can't avoid the defines of __NR_open_tree and __NR_mount_setattr.
// The thing is:
//  * If we include linux/mount.h, then compilation on centos-7 fails. We can't
//  use the __has_include() directive there as it seems the gcc version used
//  doesn't support it.
//  * So we need to not include linux/mount.h. But that means that we need to
//  define the "struct mount_attr" and the constants: MOUNT_ATTR_IDMAP,
//  OPEN_TREE_CLONE, OPEN_TREE_CLOEXEC. But sadly, even doing that is not
//  enough, as then __NR_open_tree nor __NR_mount_setattr isn't defined either.
//
//  So, basically, it seems we need to keep the defines here as long as we
//  support centos-7.
//
#if defined(__NR_open_tree)
#warning "Not defined __NR_open_tree"
#endif
#if defined(__NR_mount_setattr)
#warning "Not defined __NR_mount_setattr"
#endif
#if defined(MOUNT_ATTR_SIZE_VER0)
#warning "Not defined MOUNT_ATTR_SIZE_VER0"
#endif

/* Try again, using ifdef, just in case */
#ifdef __NR_open_tree
#warning "Not defined __NR_open_tree test 2"
#endif
#ifdef __NR_mount_setattr
#warning "Not defined __NR_mount_setattr test 2"
#endif
#ifdef MOUNT_ATTR_SIZE_VER0
#warning "Not defined MOUNT_ATTR_SIZE_VER0 test 2"
#endif


#if defined(__NR_open_tree) && defined(__NR_mount_setattr) && defined(MOUNT_ATTR_SIZE_VER0)
#define HAVE_IDMAP
#else
// TODO: Remove this, this is only for debugging.
#warning "Doesn't support idmap?"
#endif

#if 0
#ifndef __NR_mount_setattr
	#if defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_mount_setattr (442 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_mount_setattr (442 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_mount_setattr (442 + 5000)
		#endif
	#else
		#define __NR_mount_setattr 442
	#endif
#endif
#ifndef MOUNT_ATTR_SIZE_VER0
struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};
#endif

/* open_tree() */
#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif

#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif

#ifndef __NR_open_tree
	#if defined __alpha__
		#define __NR_open_tree 538
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_open_tree 4428
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_open_tree 6428
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_open_tree 5428
		#endif
	#elif defined __ia64__
		#define __NR_open_tree (428 + 1024)
	#else
		#define __NR_open_tree 428
	#endif
#endif

#endif // IF 0

static inline int sys_mount_setattr(int dfd, const char *path, unsigned int flags, struct mount_attr *attr, size_t size)
{
#ifdef HAVE_IDMAP
	return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
	//return mount_setattr(dfd, path, flags, attr, size);
#else
	// TODO: see what we want to do here. Maybe move bail to another header
	// and call it from here?
	return -1;
#endif
}

static inline int sys_open_tree(int dfd, const char *filename, unsigned int flags)
{
#ifdef HAVE_IDMAP
	return syscall(__NR_open_tree, dfd, filename, flags);
	//return open_tree(dfd, filename, flags);
#else
	return -1;
#endif

}

#endif // IDMAP_H
