#include <darling/emulation/xnu_syscall/bsd/helper/misc/fileid_cache.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#ifndef __NR_fstatat64
#	define __NR_fstatat64 __NR_newfstatat
#endif

// A small table, one entry per (dev, ino) hash, the newest note winning. stat() is on every hot path, so an entry is
// taken with a compare-and-swap and never waited for: a busy entry (another thread's, or an interrupted note of this
// one's, under a signal handler) is a skipped note or a miss. No lock, no system call, no signal mask to change.
#define SLOTS 64
#define PATH_SIZE 1024

struct slot
{
	int busy;
	unsigned long long dev, ino;
	char path[PATH_SIZE];
};

static struct slot slots[SLOTS];

static struct slot* slot_for(unsigned long long dev, unsigned long long ino)
{
	unsigned long long h = (ino ^ (dev << 17) ^ (dev >> 7)) * 0x9E3779B97F4A7C15ull;
	return &slots[(h >> 58) % SLOTS];
}

static int take(struct slot* s)
{
	int free = 0;
	return __atomic_compare_exchange_n(&s->busy, &free, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static void give(struct slot* s)
{
	__atomic_store_n(&s->busy, 0, __ATOMIC_RELEASE);
}

void fileid_cache_note(unsigned long long dev, unsigned long long ino, const char* linux_path)
{
	unsigned long n = 0;

	if (!linux_path || linux_path[0] != '/')
		return;
	while (linux_path[n] && n < PATH_SIZE)
		n++;
	if (n >= PATH_SIZE)
		return;

	struct slot* s = slot_for(dev, ino);
	if (!take(s))
		return;
	s->dev = dev;
	s->ino = ino;
	for (unsigned long i = 0; i <= n; i++)
		s->path[i] = linux_path[i];
	give(s);
}

int fileid_cache_find(unsigned long long dev, unsigned long long ino, char* linux_path, unsigned long size)
{
	struct slot* s = slot_for(dev, ino);
	int found = 0;

	if (!take(s))
		return 0;
	if (s->path[0] && s->dev == dev && s->ino == ino)
	{
		unsigned long i;
		for (i = 0; i < size && s->path[i]; i++)
			linux_path[i] = s->path[i];
		if (i < size)
		{
			linux_path[i] = '\0';
			found = 1;
		}
	}
	give(s);
	if (!found)
		return 0;

	// the path may since name another object, or nothing
	struct linux_stat st;
	if (LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, linux_path, &st, LINUX_AT_SYMLINK_NOFOLLOW) < 0)
		return 0;
	return (unsigned int) st.st_dev == dev && st.st_ino == ino;
}
