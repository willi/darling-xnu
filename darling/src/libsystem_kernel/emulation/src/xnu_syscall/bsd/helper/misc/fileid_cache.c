#include <darling/emulation/xnu_syscall/bsd/helper/misc/fileid_cache.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#ifndef __NR_fstatat64
#	define __NR_fstatat64 __NR_newfstatat
#endif

// A small table, one entry per (dev, ino) hash, the newest note winning. getattrlist() is on hot paths, so an entry is
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

// objects found not to be there, for ABSENT_NS: a stale ID asked for again (LaunchServices' records of an earlier boot)
// isn't searched for each time. A note of the object clears its entry; the one wrong answer left is "not there" for an
// object another process made in the last ABSENT_NS.
#define ABSENT_SLOTS 16
#define ABSENT_NS 2000000000ll

struct absent
{
	int busy;
	unsigned long long dev, ino;
	long long until;
};

static struct absent absents[ABSENT_SLOTS];

static struct slot* slot_for(unsigned long long dev, unsigned long long ino);

static unsigned hash(unsigned long long dev, unsigned long long ino)
{
	return ((ino ^ (dev << 17) ^ (dev >> 7)) * 0x9E3779B97F4A7C15ull) >> 58;
}

static int take(int* busy)
{
	int free = 0;
	return __atomic_compare_exchange_n(busy, &free, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static void give(int* busy)
{
	__atomic_store_n(busy, 0, __ATOMIC_RELEASE);
}

static long long now_ns(void)
{
	struct { long tv_sec, tv_nsec; } ts;
	if (LINUX_SYSCALL(__NR_clock_gettime, 1 /* CLOCK_MONOTONIC */, &ts) < 0)
		return 0;
	return ts.tv_sec * 1000000000ll + ts.tv_nsec;
}

void fileid_cache_note_absent(unsigned long long dev, unsigned long long ino)
{
	dev = mounts_volume(dev);
	struct absent* a = &absents[hash(dev, ino) % ABSENT_SLOTS];
	long long t = now_ns();
	if (!t || !take(&a->busy))
		return;
	a->dev = dev;
	a->ino = ino;
	a->until = t + ABSENT_NS;
	give(&a->busy);
}

int fileid_cache_absent(unsigned long long dev, unsigned long long ino)
{
	dev = mounts_volume(dev);
	struct absent* a = &absents[hash(dev, ino) % ABSENT_SLOTS];
	int found = 0;
	long long t = now_ns();
	if (!t || !take(&a->busy))
		return 0;
	found = a->until && a->dev == dev && a->ino == ino && t < a->until;
	give(&a->busy);
	return found;
}

static void forget_absent(unsigned long long dev, unsigned long long ino)
{
	struct absent* a = &absents[hash(dev, ino) % ABSENT_SLOTS];
	if (!take(&a->busy))
		return;
	if (a->dev == dev && a->ino == ino)
		a->until = 0;
	give(&a->busy);
}

static struct slot* slot_for(unsigned long long dev, unsigned long long ino)
{
	return &slots[hash(dev, ino) % SLOTS];
}

void fileid_cache_note(unsigned long long dev, unsigned long long ino, const char* linux_path)
{
	unsigned long n = 0;

	dev = mounts_volume(dev);

	if (!linux_path || linux_path[0] != '/')
		return;
	while (linux_path[n] && n < PATH_SIZE)
		n++;
	if (n >= PATH_SIZE)
		return;

	forget_absent(dev, ino);
	struct slot* s = slot_for(dev, ino);
	if (!take(&s->busy))
		return;
	s->dev = dev;
	s->ino = ino;
	for (unsigned long i = 0; i <= n; i++)
		s->path[i] = linux_path[i];
	give(&s->busy);
}

int fileid_cache_find(unsigned long long dev, unsigned long long ino, char* linux_path, unsigned long size)
{
	dev = mounts_volume(dev);
	struct slot* s = slot_for(dev, ino);
	int found = 0;

	if (!take(&s->busy))
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
	give(&s->busy);
	if (!found)
		return 0;

	// the path may since name another object, or nothing
	struct linux_stat st;
	if (LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, linux_path, &st, LINUX_AT_SYMLINK_NOFOLLOW) < 0)
		return 0;
	return mounts_volume(st.st_dev) == dev && st.st_ino == ino;
}

void fileid_cache_atfork_child(void)
{
	// the child has only the thread that forked: an entry another thread held then would stay busy for good
	for (int i = 0; i < SLOTS; i++)
		give(&slots[i].busy);
	for (int i = 0; i < ABSENT_SLOTS; i++)
		give(&absents[i].busy);
}
