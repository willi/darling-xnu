#include <darling/emulation/xnu_syscall/bsd/helper/network/nosigpipe.h>

#include <stddef.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <libsimple/lock.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/sigsafe_lock.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/mman/duct_mman.h>
#include <darling/emulation/conversion/network/recvmsg.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockutil.h>

#define LINUX_SYS_SENDMSG 16
#define LINUX_MSG_NOSIGNAL 0x4000
#define LINUX_SIGPIPE 13
#define LINUX_ENOTSOCK 88

// Descriptor number -> the cookie of the socket it had when SO_NOSIGPIPE was set on it (0: none), in pages made as
// descriptors need them and kept. Read without the lock (a write looks its descriptor up), written under it.
#define PAGE_FDS 1024
#define PAGES (NOSIGPIPE_FDS_MAX / PAGE_FDS)

static unsigned long long* pages[PAGES];
static libsimple_lock_t nosigpipe_lock = LIBSIMPLE_LOCK_INITIALIZER;
volatile int nosigpipe_fds;

void socket_nosigpipe_atfork_child(void)
{
	// the child has only the forking thread: nobody holds the lock. Its descriptors are the parent's.
	libsimple_lock_init(&nosigpipe_lock);
}

static unsigned long long* slot(int fd)
{
	if (fd < 0 || fd >= NOSIGPIPE_FDS_MAX)
		return NULL;
	unsigned long long* page = __atomic_load_n(&pages[fd / PAGE_FDS], __ATOMIC_ACQUIRE);
	return page != NULL ? &page[fd % PAGE_FDS] : NULL;
}

static unsigned long long* slot_make_locked(int fd)
{
	unsigned long long* s = slot(fd);

	if (s != NULL || fd < 0 || fd >= NOSIGPIPE_FDS_MAX)
		return s;
#ifdef __NR_mmap2
	long page = LINUX_SYSCALL6(__NR_mmap2, 0, PAGE_FDS * sizeof(*s), LINUX_PROT_READ | LINUX_PROT_WRITE,
		LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
#else
	long page = LINUX_SYSCALL6(__NR_mmap, 0, PAGE_FDS * sizeof(*s), LINUX_PROT_READ | LINUX_PROT_WRITE,
		LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
#endif
	if ((unsigned long) page > -4096UL)
		return NULL;
	__atomic_store_n(&pages[fd / PAGE_FDS], (unsigned long long*) page, __ATOMIC_RELEASE);
	return slot(fd);
}

static void slot_set_locked(unsigned long long* s, unsigned long long cookie)
{
	if (*s == 0 && cookie != 0)
		__atomic_add_fetch(&nosigpipe_fds, 1, __ATOMIC_RELAXED);
	else if (*s != 0 && cookie == 0)
		__atomic_sub_fetch(&nosigpipe_fds, 1, __ATOMIC_RELAXED);
	__atomic_store_n(s, cookie, __ATOMIC_RELEASE);
}

// Whether some descriptor has SO_NOSIGPIPE for the socket cookie names
static int cookie_flagged_locked(unsigned long long cookie)
{
	for (int p = 0; p < PAGES && nosigpipe_fds != 0; p++) {
		if (pages[p] == NULL)
			continue;
		for (int i = 0; i < PAGE_FDS; i++) {
			if (pages[p][i] == cookie)
				return 1;
		}
	}
	return 0;
}

// Whether fd's socket has SO_NOSIGPIPE: set through fd, or through another descriptor for it (then fd learns it)
static int socket_flagged(int fd, unsigned long long cookie)
{
	unsigned long long mask = sigsafe_lock(&nosigpipe_lock);
	unsigned long long* s = slot(fd);
	int flagged = s != NULL && *s == cookie;

	if (!flagged && cookie_flagged_locked(cookie)) {
		flagged = 1;
		s = slot_make_locked(fd);
		if (s != NULL)
			slot_set_locked(s, cookie);
	}
	sigsafe_unlock(&nosigpipe_lock, mask);
	return flagged;
}

long socket_nosigpipe_set(int fd, int on)
{
	unsigned long long cookie, mask;
	long ret = linux_socket_cookie(fd, &cookie);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = 0;
	mask = sigsafe_lock(&nosigpipe_lock);
	if (on) {
		unsigned long long* s = slot_make_locked(fd);
		if (s != NULL)
			slot_set_locked(s, cookie);
		else if (fd < NOSIGPIPE_FDS_MAX)
			ret = -ENOBUFS;
	} else {
		// the socket's flag, whichever descriptors it was set or learnt through
		for (int p = 0; p < PAGES; p++) {
			if (pages[p] == NULL)
				continue;
			for (int i = 0; i < PAGE_FDS; i++) {
				if (pages[p][i] == cookie)
					slot_set_locked(&pages[p][i], 0);
			}
		}
	}
	sigsafe_unlock(&nosigpipe_lock, mask);
	return ret;
}

long socket_nosigpipe_get(int fd, int* on)
{
	unsigned long long cookie;
	long ret = linux_socket_cookie(fd, &cookie);

	if (ret < 0)
		return errno_linux_to_bsd(ret);
	*on = NOSIGPIPE_ACTIVE() && socket_flagged(fd, cookie);
	return 0;
}

static void forget(int fd, unsigned long long cookie)
{
	unsigned long long mask = sigsafe_lock(&nosigpipe_lock);
	unsigned long long* s = slot(fd);

	if (s != NULL && *s == cookie)
		slot_set_locked(s, 0);
	sigsafe_unlock(&nosigpipe_lock, mask);
}

int socket_nosigpipe_write(int fd, const struct iovec* iov, int iovcnt, long* result)
{
	unsigned long long* s = slot(fd);
	unsigned long long cookie = s != NULL ? __atomic_load_n(s, __ATOMIC_ACQUIRE) : 0;
	struct linux_msghdr msg = { .msg_iov = (struct iovec*) iov, .msg_iovlen = iovcnt };
	long ret;

	if (cookie == 0)
		return 0;

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SENDMSG, ((long[6]) { fd, &msg, LINUX_MSG_NOSIGNAL }));
#else
	ret = LINUX_SYSCALL(__NR_sendmsg, fd, &msg, LINUX_MSG_NOSIGNAL);
#endif

	// the number was closed some way that didn't forget it, and reused for something else: write() it as before
	if (ret == -LINUX_ENOTSOCK) {
		forget(fd, cookie);
		return 0;
	}
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	*result = ret;
	return 1;
}

long socket_send_done(int fd, long ret, int msg_nosignal, int linux_raised)
{
	unsigned long long cookie;

	if (ret != -EPIPE || msg_nosignal || linux_raised)
		return ret;
	if (NOSIGPIPE_ACTIVE() && linux_socket_cookie(fd, &cookie) == 0 && socket_flagged(fd, cookie))
		return ret;

	// XNU's psignal(p, SIGPIPE): to the process
	LINUX_SYSCALL(__NR_kill, LINUX_SYSCALL0(__NR_getpid), LINUX_SIGPIPE);
	return ret;
}

void socket_nosigpipe_close(int fd)
{
	unsigned long long* s = slot(fd);

	if (s == NULL || __atomic_load_n(s, __ATOMIC_ACQUIRE) == 0)
		return;
	unsigned long long mask = sigsafe_lock(&nosigpipe_lock);
	slot_set_locked(s, 0);
	sigsafe_unlock(&nosigpipe_lock, mask);
}

void socket_nosigpipe_dup(int fd, int copy)
{
	unsigned long long* s = slot(fd);

	if (s == NULL || copy == fd || __atomic_load_n(s, __ATOMIC_ACQUIRE) == 0)
		return;
	unsigned long long mask = sigsafe_lock(&nosigpipe_lock);
	unsigned long long* c = slot_make_locked(copy);
	if (c != NULL && *s != 0)
		slot_set_locked(c, *s);
	sigsafe_unlock(&nosigpipe_lock, mask);
}
