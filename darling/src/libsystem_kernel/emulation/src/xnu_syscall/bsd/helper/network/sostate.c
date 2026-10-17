#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>
#include <libsimple/lock.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/sigsafe_lock.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockutil.h>

#define LINUX_SOL_SOCKET 1
#define LINUX_SO_ERROR 4
#define LINUX_SYS_GETPEERNAME 7

#define LINUX_POLLIN 0x0001
#define LINUX_POLLOUT 0x0004
#define LINUX_POLLERR 0x0008
#define LINUX_POLLHUP 0x0010
#define LINUX_POLLRDHUP 0x2000

struct linux_pollfd {
	int fd;
	short events;
	short revents;
};

struct linux_timespec {
	long tv_sec;
	long tv_nsec;
};

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

// The sockets remembered: the error each holds (taken from Linux, not yet by the program), and the errors each has had,
// for EVFILT_SOCK's hints. Every access takes the lock, which blocks signals while held (sigsafe_lock.h).
struct socket_entry {
	unsigned long long cookie; // 0: free (Linux's socket cookies start at 1)
	unsigned long long order;  // when it was remembered: a full table forgets the oldest
	int held;                  // the held error (a BSD errno), 0 if none
	int last;                  // the newest error the socket has had
	unsigned int errors;       // how many it has had
};

static struct socket_entry entries[SOCKET_ENTRIES_MAX];
static unsigned long long entries_order;
static libsimple_lock_t entries_lock = LIBSIMPLE_LOCK_INITIALIZER;
volatile int socket_errors_held;
volatile int socket_errors_taking;
volatile int socket_entries_used;
volatile int socket_watchers;

void socket_watch(int delta)
{
	__atomic_add_fetch(&socket_watchers, delta, __ATOMIC_SEQ_CST);
}

void socket_errors_atfork_child(void)
{
	// the child has only the forking thread: nobody holds the lock, or is taking an error. It keeps the errors:
	// its sockets are the parent's.
	libsimple_lock_init(&entries_lock);
	socket_errors_taking = 0;
}

static struct socket_entry* find_locked(unsigned long long cookie)
{
	for (int i = 0; i < SOCKET_ENTRIES_MAX; i++) {
		if (entries[i].cookie == cookie)
			return &entries[i];
	}
	return NULL;
}

static void unhold_locked(struct socket_entry* e)
{
	if (e->held != 0) {
		e->held = 0;
		__atomic_sub_fetch(&socket_errors_held, 1, __ATOMIC_SEQ_CST);
	}
}

static void forget_locked(struct socket_entry* e)
{
	unhold_locked(e);
	e->cookie = 0;
	__atomic_sub_fetch(&socket_entries_used, 1, __ATOMIC_SEQ_CST);
}

// The socket's entry, made if it has none
static struct socket_entry* entry_locked(unsigned long long cookie)
{
	struct socket_entry* e = find_locked(cookie);

	if (e != NULL)
		return e;
	e = find_locked(0);
	if (e == NULL) {
		e = &entries[0];
		for (int i = 1; i < SOCKET_ENTRIES_MAX; i++) {
			if (entries[i].order < e->order)
				e = &entries[i];
		}
		forget_locked(e);
	}
	e->cookie = cookie;
	e->order = ++entries_order;
	e->held = 0;
	e->last = 0;
	e->errors = 0;
	__atomic_add_fetch(&socket_entries_used, 1, __ATOMIC_SEQ_CST);
	return e;
}

static void hold_locked(struct socket_entry* e, int error)
{
	if (e->held == 0)
		__atomic_add_fetch(&socket_errors_held, 1, __ATOMIC_SEQ_CST);
	e->held = error;
}

static void count_locked(struct socket_entry* e, int error)
{
	e->last = error;
	e->errors++;
}

// An entry that no longer holds an error and whose errors nobody counts is forgotten
static void tidy_locked(struct socket_entry* e)
{
	if (e->held == 0 && socket_watchers == 0)
		forget_locked(e);
}

// The errors Linux sets on a socket (sk_err) for its peer or the network
static int socket_error(int error)
{
	switch (error) {
	case ECONNREFUSED:
	case ECONNRESET:
	case ECONNABORTED:
	case EPIPE:
	case ETIMEDOUT:
	case EHOSTUNREACH:
	case ENETUNREACH:
	case EHOSTDOWN:
	case ENETDOWN:
		return 1;
	default:
		return 0;
	}
}

// A TCP socket's error as XNU's TCP would have set it: Linux sets EPIPE for a reset in CLOSE_WAIT, where XNU's
// tcp_input() sets ECONNRESET as in the other synchronized states
static int tcp_error(int error)
{
	return error == EPIPE ? ECONNRESET : error;
}

static int is_tcp(int fd)
{
	struct linux_tcp_info info;
	return linux_tcp_info(fd, &info) == 0;
}

// XNU's so_state for a TCP socket in Linux state info->state. A socket that is closed (or in TIME_WAIT, which Linux
// reports as closed) after any segment went either way has been disconnected (XNU's tcp_close() calls
// soisdisconnected()); one that has seen none is new.
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
		return (info->segs_out || info->segs_in) ? SOSTATE_ISDISCONNECTED | SOSTATE_CANTRCVMORE | SOSTATE_CANTSENDMORE
			: 0;
	default: // SYN_SENT, SYN_RECV, LISTEN
		return 0;
	}
}

// Takes a closed TCP socket's error from Linux and holds it. Readers that found nothing in Linux meanwhile see
// socket_errors_taking, and wait for the lock to find it held.
static void take_tcp_error(int fd, unsigned long long cookie)
{
	int linux_error = 0;
	unsigned int len = sizeof(linux_error);
	unsigned long long mask;

	__atomic_add_fetch(&socket_errors_taking, 1, __ATOMIC_SEQ_CST);
	mask = sigsafe_lock(&entries_lock);
	if (linux_getsockopt(fd, LINUX_SOL_SOCKET, LINUX_SO_ERROR, &linux_error, &len) == 0 && linux_error != 0) {
		int error = tcp_error(errno_linux_to_bsd(linux_error));
		struct socket_entry* e = entry_locked(cookie);
		hold_locked(e, error);
		count_locked(e, error);
	}
	sigsafe_unlock(&entries_lock, mask);
	__atomic_sub_fetch(&socket_errors_taking, 1, __ATOMIC_SEQ_CST);
}

int socket_state(int fd, struct socket_state_4libkqueue* st)
{
	unsigned long long cookie;
	struct linux_pollfd pfd = { .fd = fd, .events = LINUX_POLLIN | LINUX_POLLOUT | LINUX_POLLRDHUP };
	struct linux_timespec now = { 0, 0 };
	struct linux_tcp_info info;
	long ret;

	ret = linux_socket_cookie(fd, &cookie);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_ppoll, &pfd, 1, &now, NULL, 8);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	st->error = 0;
	st->errors = 0;
	st->last_error = 0;

	if (linux_tcp_info(fd, &info) == 0) {
		st->state = tcp_state(&info) | SOSTATE_EVCONNINFO;
		// Linux reports a socket error (sk_err) as POLLERR. A closed TCP socket's is why it closed.
		if ((pfd.revents & LINUX_POLLERR) && info.state == LINUX_TCP_CLOSE)
			take_tcp_error(fd, cookie);
	} else {
		// Other sockets: one with a peer is connected until it hangs up (Linux: both directions shut down), then
		// disconnected. A new stream socket hangs up too, but has no peer. Linux doesn't report a shutdown of only
		// the sending direction.
		st->state = 0;
		if (linux_getpeername(fd) == 0) {
			if (pfd.revents & LINUX_POLLHUP)
				st->state = SOSTATE_ISDISCONNECTED | SOSTATE_CANTRCVMORE | SOSTATE_CANTSENDMORE;
			else
				st->state = SOSTATE_ISCONNECTED;
		}
	}

	// the receiving direction shut down (the peer's FIN, or shutdown(SHUT_RD))
	if (pfd.revents & LINUX_POLLRDHUP)
		st->state |= SOSTATE_CANTRCVMORE;

	if (SOCKET_ENTRIES_USED()) {
		unsigned long long mask = sigsafe_lock(&entries_lock);
		struct socket_entry* e = find_locked(cookie);
		if (e != NULL) {
			st->error = e->held;
			st->errors = e->errors;
			st->last_error = e->last;
		}
		sigsafe_unlock(&entries_lock, mask);
	}

	return 0;
}

// Linux returned error, its own, to the program: the socket's one error is now that, so the held one goes; counted
// for EVFILT_SOCK
static void linux_gave_error(unsigned long long cookie, int error)
{
	unsigned long long mask = sigsafe_lock(&entries_lock);
	struct socket_entry* e = find_locked(cookie);

	if (e == NULL && socket_watchers != 0)
		e = entry_locked(cookie);
	if (e != NULL) {
		unhold_locked(e);
		count_locked(e, error);
		tidy_locked(e);
	}
	sigsafe_unlock(&entries_lock, mask);
}

// The held error, cleared unless peek; 0 if none
static int held_error(unsigned long long cookie, int peek)
{
	int error = 0;
	unsigned long long mask = sigsafe_lock(&entries_lock);
	struct socket_entry* e = find_locked(cookie);

	if (e != NULL && e->held != 0) {
		error = e->held;
		if (!peek) {
			unhold_locked(e);
			tidy_locked(e);
		}
	}
	sigsafe_unlock(&entries_lock, mask);
	return error;
}

int socket_error_take(int fd, int error)
{
	unsigned long long cookie;

	if (linux_socket_cookie(fd, &cookie) < 0)
		return error;

	if (error != 0) {
		if (error == EPIPE && is_tcp(fd))
			error = tcp_error(error);
		linux_gave_error(cookie, error);
		return error;
	}
	return held_error(cookie, 0);
}

long socket_error_read(int fd, long ret, int peek)
{
	unsigned long long cookie;

	// no data: XNU's soreceive() returns the pending error before end of file or EWOULDBLOCK
	if (ret == 0 || ret == -EAGAIN || ret == -ENOTCONN) {
		if (!SOCKET_ERRORS_HELD() || linux_socket_cookie(fd, &cookie) < 0)
			return ret;
		int held = held_error(cookie, peek);
		return held != 0 ? -held : ret;
	}

	if (!socket_error(-ret) || linux_socket_cookie(fd, &cookie) < 0)
		return ret;
	if (ret == -EPIPE) {
		// reads fail with EPIPE only on a TCP socket reset in CLOSE_WAIT
		if (!is_tcp(fd))
			return ret;
		ret = -tcp_error(EPIPE);
	}
	linux_gave_error(cookie, -ret);
	return ret;
}

long socket_error_send(int fd, long ret)
{
	struct linux_tcp_info info;
	unsigned long long cookie;
	int error = -ret;

	// XNU's sosendcheck() fails a send on a disconnected socket with EPIPE, before looking at so_error, which stays;
	// Linux's TCP returns (and clears) the error that closed the socket
	if (error == EPIPE || !socket_error(error))
		return ret;
	if (linux_tcp_info(fd, &info) < 0 || info.state != LINUX_TCP_CLOSE || linux_socket_cookie(fd, &cookie) < 0)
		return ret;

	unsigned long long mask = sigsafe_lock(&entries_lock);
	struct socket_entry* e = entry_locked(cookie);
	hold_locked(e, tcp_error(error));
	count_locked(e, e->held);
	sigsafe_unlock(&entries_lock, mask);
	return -EPIPE;
}

void socket_errors_close(int fd)
{
	unsigned long long cookie;

	if (linux_socket_cookie(fd, &cookie) < 0)
		return;

	unsigned long long mask = sigsafe_lock(&entries_lock);
	struct socket_entry* e = find_locked(cookie);
	if (e != NULL)
		forget_locked(e);
	sigsafe_unlock(&entries_lock, mask);
}
