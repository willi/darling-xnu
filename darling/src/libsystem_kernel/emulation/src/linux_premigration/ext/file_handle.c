#include <darling/emulation/linux_premigration/ext/file_handle.h>

#include <sys/errno.h>
#include <libsimple/lock.h>

#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fileid.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>

// CarbonCore's FSRef: an object by its volume and object ID, as an FSRef is on macOS, resolved to a path with
// fileid_find() (fsgetpath()'s lookup), in any process. The process that made a reference also keeps the path it was
// made from, which answers first while it still names the object: it also finds objects fileid_find() can't (a file of
// Darling's prefix overlay, whose device no mount is of), and the references a process holds outlast the fileid cache's
// entries, one per hash.

#ifndef __NR_fstatat64
#	define __NR_fstatat64 __NR_newfstatat
#endif

extern void free(void* ptr);
extern char* strdup(const char* s);

struct SavedRef
{
	char* path; // a Linux path
	int gen;
};

static struct SavedRef g_savedRefs[200];
static int g_nextSavedRef = 0, g_nextGen = 0;
static libsimple_lock_t g_savedRefLock = LIBSIMPLE_LOCK_INITIALIZER;

VISIBLE
int sys_name_to_handle(const char* name, RefData* ref, int follow)
{
	int ret;
	struct linux_stat st;

	struct vchroot_expand_args vc;
	vc.flags = follow ? VCHROOT_FOLLOW : 0;
	vc.dfd = get_perthread_wd();

	strcpy(vc.path, name);
	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, vc.path, &st, follow ? 0 : LINUX_AT_SYMLINK_NOFOLLOW);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	unsigned long long mount_id = 0;
	mounts_id(LINUX_AT_FDCWD, vc.path, follow ? 0 : LINUX_AT_SYMLINK_NOFOLLOW, &mount_id);
	ref->mount_id = MOUNT_ID_FILEID;
	ref->id.volume = mounts_volume(st.st_dev);
	ref->id.mount = (uint32_t) mount_id;
	ref->id.objid = st.st_ino;

	char* path = strdup(vc.path);
	libsimple_lock_lock(&g_savedRefLock);

	if (g_savedRefs[g_nextSavedRef].path)
		free(g_savedRefs[g_nextSavedRef].path);

	ref->id.gen = g_nextGen++;
	g_savedRefs[g_nextSavedRef].path = path;
	g_savedRefs[g_nextSavedRef].gen = ref->id.gen;
	ref->id.index = g_nextSavedRef;

	g_nextSavedRef = (g_nextSavedRef + 1) % (sizeof(g_savedRefs) / sizeof(g_savedRefs[0]));

	libsimple_lock_unlock(&g_savedRefLock);

	return 0;
}

// the path this process made the reference from, if it still names the object: 1, or 0
static int saved_path(const RefData* ref, char name[4096])
{
	int found = 0;
	struct linux_stat st;
	unsigned int n = sizeof(g_savedRefs) / sizeof(g_savedRefs[0]);

	if (ref->id.index < 0 || (unsigned int) ref->id.index >= n)
		return 0;

	libsimple_lock_lock(&g_savedRefLock);
	const struct SavedRef* saved = &g_savedRefs[ref->id.index];
	if (saved->path && saved->gen == ref->id.gen)
		found = vchroot_unexpand_into(saved->path, name, 4096) == 0 &&
			LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, saved->path, &st, LINUX_AT_SYMLINK_NOFOLLOW) == 0 &&
			mounts_volume(st.st_dev) == ref->id.volume && st.st_ino == ref->id.objid;
	libsimple_lock_unlock(&g_savedRefLock);
	return found;
}

VISIBLE
int sys_handle_to_name(RefData* ref, char name[4096])
{
	if (ref->mount_id != MOUNT_ID_FILEID)
		return -ENOENT;
	if (saved_path(ref, name))
		return 0;

	long ret = fileid_find(ref->id.volume, ref->id.mount, ref->id.objid, name, 4096);
	return ret < 0 ? (int) ret : 0;
}

// Opens the object the reference is to (no longer needs CAP_DAC_READ_SEARCH)
VISIBLE
int sys_open_by_handle(RefData* ref, int flags)
{
	char name[4096];
	int ret = sys_handle_to_name(ref, name);
	if (ret < 0)
		return ret;
	return sys_open(name, flags, 0);
}
