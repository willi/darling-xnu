#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>
#include <libsimple/lock.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define LINUX_SOL_SOCKET 1
#define LINUX_SO_ERROR 4
#define LINUX_SO_COOKIE 57
#define LINUX_SOL_TCP 6
#define LINUX_TCP_INFO 11
#define LINUX_SYS_GETPEERNAME 7
#define LINUX_SYS_GETSOCKOPT 15
#define LINUX_SIG_BLOCK 0
#define LINUX_SIG_SETMASK 2

#define LINUX_POLLIN 0x0001
#define LINUX_POLLOUT 0x0004
#define LINUX_POLLERR 0x0008
#define LINUX_POLLHUP 0x0010
#define LINUX_POLLNVAL 0x0020
#define LINUX_POLLRDHUP 0x2000

// Linux's TCP states (include/net/tcp_states.h)
enum {
	LINUX_TCP_ESTABLISHED = 1,
	LINUX_TCP_SYN_SENT,
	LINUX_TCP_SYN_RECV,
	LINUX_TCP_FIN_WAIT1,
	LINUX_TCP_FIN_WAIT2,
	LINUX_TCP_TIME_WAIT,
	LINUX_TCP_CLOSE,
	LINUX_TCP_CLOSE_WAIT,
	LINUX_TCP_LAST_ACK,
	LINUX_TCP_LISTEN,
	LINUX_TCP_CLOSING,
};

// the start of Linux's struct tcp_info, up to tcpi_segs_out (Linux 4.2)
struct linux_tcp_info {
	uint8_t state;
	uint8_t other[135];
	uint32_t segs_out;
};

struct linux_pollfd {
	int fd;
	short events;
	short revents;
};

struct linux_timespec {
	long tv_sec;
	long tv_nsec;
};

static long linux_getsockopt(int fd, int level, int name, void* value, unsigned int* len)
{
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETSOCKOPT, ((long[6]) { fd, level, name, value, len, 0 }));
#else
	return LINUX_SYSCALL(__NR_getsockopt, fd, level, name, value, len);
#endif
}

static long linux_getpeername(int fd)
{
	char addr[128];
	unsigned int len = sizeof(addr);
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETPEERNAME, ((long[6]) { fd, addr, &len }));
#else
	return LINUX_SYSCALL(__NR_getpeername, fd, addr, &len);
#endif
}

static long socket_cookie(int fd, unsigned long long* cookie)
{
	unsigned int len = sizeof(*cookie);
	return linux_getsockopt(fd, LINUX_SOL_SOCKET, LINUX_SO_COOKIE, cookie, &len);
}

// The errors taken from Linux and not yet from here: a socket's newest, with the order they came in, so that a full
// table drops the oldest. Every access takes the lock, which blocks signals while held (as ulock_wait.c's table
// does), so a signal handler's read() can't deadlock on it.
struct held_error {
	unsigned long long cookie; // 0: free (Linux's socket cookies start at 1)
	unsigned long long order;
	int error;
};

static struct held_error held_errors[SOCKET_ERRORS_MAX];
static unsigned long long held_order;
static libsimple_lock_t held_errors_lock = LIBSIMPLE_LOCK_INITIALIZER;
volatile int socket_errors_held;

static unsigned long long held_lock(void)
{
	unsigned long long all = ~0ull, old;

	LINUX_SYSCALL(__NR_rt_sigprocmask, LINUX_SIG_BLOCK, &all, &old, sizeof(all));
	libsimple_lock_lock(&held_errors_lock);
	return old;
}

static void held_unlock(unsigned long long old)
{
	libsimple_lock_unlock(&held_errors_lock);
	LINUX_SYSCALL(__NR_rt_sigprocmask, LINUX_SIG_SETMASK, &old, NULL, sizeof(old));
}

void socket_errors_atfork_child(void)
{
	// the child has only the forking thread: nobody holds the lock. It keeps the errors: its sockets are the parent's.
	libsimple_lock_init(&held_errors_lock);
}

static struct held_error* held_find_locked(unsigned long long cookie)
{
	for (int i = 0; i < SOCKET_ERRORS_MAX; i++) {
		if (held_errors[i].cookie == cookie)
			return &held_errors[i];
	}
	return NULL;
}

static void held_drop_locked(struct held_error* h)
{
	h->cookie = 0;
	__atomic_sub_fetch(&socket_errors_held, 1, __ATOMIC_RELEASE);
}

static void held_put(unsigned long long cookie, int error)
{
	unsigned long long mask = held_lock();
	struct held_error* h = held_find_locked(cookie);

	if (h == NULL) {
		h = held_find_locked(0);
		if (h == NULL) {
			h = &held_errors[0];
			for (int i = 1; i < SOCKET_ERRORS_MAX; i++) {
				if (held_errors[i].order < h->order)
					h = &held_errors[i];
			}
		} else {
			__atomic_add_fetch(&socket_errors_held, 1, __ATOMIC_RELEASE);
		}
		h->cookie = cookie;
		h->order = ++held_order;
	}
	h->error = error;
	held_unlock(mask);
}

// the error held for the socket; cleared if take
static int held_get(unsigned long long cookie, int take)
{
	int error = 0;
	unsigned long long mask = held_lock();
	struct held_error* h = held_find_locked(cookie);

	if (h != NULL) {
		error = h->error;
		if (take)
			held_drop_locked(h);
	}
	held_unlock(mask);
	return error;
}

// XNU's so_state for a TCP socket in Linux state info->state. A socket that is closed (or in TIME_WAIT, which Linux
// reports as closed) after sending anything has been disconnected (XNU's tcp_close() calls soisdisconnected());
// one that has sent nothing is new.
static unsigned tcp_state(const struct linux_tcp_info* info)
{
	switch (info->state) {
	case LINUX_TCP_ESTABLISHED:
		return SOSTATE_ISCONNECTED;
	case LINUX_TCP_CLOSE_WAIT:
		return SOSTATE_ISCONNECTED | SOSTATE_CANTRCVMORE;
	case LINUX_TCP_FIN_WAIT1:
	case LINUX_TCP_FIN_WAIT2:
		return SOSTATE_ISCONNECTED | SOSTATE_CANTSENDMORE;
	case LINUX_TCP_CLOSING:
	case LINUX_TCP_LAST_ACK:
		return SOSTATE_ISCONNECTED | SOSTATE_CANTRCVMORE | SOSTATE_CANTSENDMORE;
	case LINUX_TCP_TIME_WAIT:
	case LINUX_TCP_CLOSE:
		return info->segs_out ? SOSTATE_ISDISCONNECTED | SOSTATE_CANTRCVMORE | SOSTATE_CANTSENDMORE : 0;
	default: // SYN_SENT, SYN_RECV, LISTEN
		return 0;
	}
}

int socket_state(int fd, unsigned* state, int* error)
{
	unsigned long long cookie;
	struct linux_pollfd pfd = { .fd = fd, .events = LINUX_POLLIN | LINUX_POLLOUT | LINUX_POLLRDHUP };
	struct linux_timespec now = { 0, 0 };
	struct linux_tcp_info info;
	unsigned int len = sizeof(info);
	long ret;

	ret = socket_cookie(fd, &cookie);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_ppoll, &pfd, 1, &now, NULL, 8);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	// Linux reports a socket error (sk_err) as POLLERR; take it, and hold it until XNU's would be taken
	if (pfd.revents & LINUX_POLLERR) {
		int linux_error = 0;
		unsigned int elen = sizeof(linux_error);
		if (linux_getsockopt(fd, LINUX_SOL_SOCKET, LINUX_SO_ERROR, &linux_error, &elen) == 0 && linux_error != 0)
			held_put(cookie, errno_linux_to_bsd(linux_error));
	}
	*error = SOCKET_ERRORS_HELD() ? held_get(cookie, 0) : 0;

	if (linux_getsockopt(fd, LINUX_SOL_TCP, LINUX_TCP_INFO, &info, &len) == 0 && len >= sizeof(info)) {
		*state = tcp_state(&info) | SOSTATE_EVCONNINFO;
	} else {
		// Other sockets: one with a peer is connected until it hangs up (Linux: both directions shut down), then
		// disconnected. A new stream socket hangs up too, but has no peer. Linux doesn't report a shutdown of only
		// the sending direction.
		*state = 0;
		if (linux_getpeername(fd) == 0) {
			if (pfd.revents & LINUX_POLLHUP)
				*state = SOSTATE_ISDISCONNECTED | SOSTATE_CANTRCVMORE | SOSTATE_CANTSENDMORE;
			else
				*state = SOSTATE_ISCONNECTED;
		}
	}

	// the receiving direction shut down (the peer's FIN, or shutdown(SHUT_RD))
	if (pfd.revents & LINUX_POLLRDHUP)
		*state |= SOSTATE_CANTRCVMORE;

	return 0;
}

int socket_error_take(int fd, int error)
{
	unsigned long long cookie;

	if (socket_cookie(fd, &cookie) < 0)
		return error;

	// one error per socket, as XNU has: Linux's, if it has a newer one
	int held = held_get(cookie, 1);
	return error != 0 ? error : held;
}

long socket_error_read(int fd, long ret, int peek)
{
	unsigned long long cookie;

	if (ret > 0 || socket_cookie(fd, &cookie) < 0)
		return ret;

	int held = held_get(cookie, !peek);
	return held != 0 ? -held : ret;
}
