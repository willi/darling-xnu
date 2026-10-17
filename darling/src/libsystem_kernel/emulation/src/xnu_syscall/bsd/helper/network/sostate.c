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
#include <darling/emulation/xnu_syscall/bsd/impl/network/getpeername.h>

#define LINUX_SOL_SOCKET 1
#define LINUX_SO_ERROR 4

#define LINUX_POLLIN 0x0001
#define LINUX_POLLOUT 0x0004
#define LINUX_POLLERR 0x0008
#define LINUX_POLLHUP 0x0010
#define LINUX_POLLRDHUP 0x2000

// shutdown()'s how, the same on XNU and Linux
#define SHUT_RD 0
#define SHUT_WR 1

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

// The sockets remembered: those holding an error (taken from Linux, not yet by the program), and those EVFILT_SOCK
// knotes watch, with what the knotes need. Every access takes the lock, which blocks signals while held
// (sigsafe_lock.h).
struct socket_entry {
	unsigned long long cookie; // 0: free (Linux's socket cookies start at 1)
	unsigned long long order;  // when it was remembered: a full table forgets the oldest
	int held;                  // the held error (a BSD errno), 0 if none
	int watchers;              // the EVFILT_SOCK knotes watching it
	// While watched: the hint sequence number of its newest error raising NOTE_CONNRESET, and NOTE_TIMEOUT (0 if
	// none). A sequence shared by all sockets, so that an entry forgotten and made again never repeats a value.
	unsigned int resets;
	unsigned int timeouts;
	unsigned char shut;        // SOSTATE_CANTRCVMORE, SOSTATE_CANTSENDMORE: shut down while watched
	// A send's EPIPE on it is only that (it can't send), not a reset whose error the send cleared: it has been shut
	// down for sending, its error was seen, or it was watched too late to tell (socket_error_send)
	unsigned char epipe_plain;
};

static struct socket_entry entries[SOCKET_ENTRIES_MAX];
static unsigned long long entries_order;
static unsigned int hint_seq;
static libsimple_lock_t entries_lock = LIBSIMPLE_LOCK_INITIALIZER;
volatile int socket_errors_held;
volatile int socket_errors_taking;
volatile int socket_entries_used;
volatile int socket_watchers;

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

// An entry that holds no error and that no knote watches is forgotten
static void tidy_locked(struct socket_entry* e)
{
	if (e->held == 0 && e->watchers == 0)
		forget_locked(e);
}

// The socket's entry, made if it has none. A full table forgets the oldest entry, one that is only watched (losing
// hints) before one holding an error (losing the error).
static struct socket_entry* entry_locked(unsigned long long cookie)
{
	struct socket_entry* e = find_locked(cookie);

	if (e != NULL)
		return e;
	e = find_locked(0);
	if (e == NULL) {
		e = &entries[0];
		for (int i = 1; i < SOCKET_ENTRIES_MAX; i++) {
			struct socket_entry* c = &entries[i];
			if ((c->held != 0) < (e->held != 0) || ((c->held != 0) == (e->held != 0) && c->order < e->order))
				e = c;
		}
		forget_locked(e);
	}
	e->cookie = cookie;
	e->order = ++entries_order;
	e->held = 0;
	e->watchers = 0;
	e->resets = 0;
	e->timeouts = 0;
	e->shut = 0;
	e->epipe_plain = 0;
	__atomic_add_fetch(&socket_entries_used, 1, __ATOMIC_SEQ_CST);
	return e;
}

static void hold_locked(struct socket_entry* e, int error)
{
	if (e->held == 0)
		__atomic_add_fetch(&socket_errors_held, 1, __ATOMIC_SEQ_CST);
	e->held = error;
}

// The socket had error: counted for its knotes' hints (XNU's TCP posts NOTE_CONNRESET from tcp_input()'s RST
// handling, NOTE_TIMEOUT from tcp_timers()' drops, which also time out with the unreachable errors)
static void errored_locked(struct socket_entry* e, int error)
{
	e->epipe_plain = 1;
	if (e->watchers == 0)
		return;
	switch (error) {
	case ECONNREFUSED:
	case ECONNRESET:
		e->resets = ++hint_seq;
		break;
	case ETIMEDOUT:
	case EHOSTUNREACH:
	case ENETUNREACH:
	case EHOSTDOWN:
	case ENETDOWN:
		e->timeouts = ++hint_seq;
		break;
	}
}

void socket_errors_atfork_child(void)
{
	// The child has only the forking thread: nobody holds the lock, or is taking an error. It keeps the held errors:
	// its sockets are the parent's. It has no knotes: libkqueue's kqueue_atfork() drops the parent's kqueues without
	// deleting their knotes, so nothing would ever stop their watches.
	libsimple_lock_init(&entries_lock);
	socket_errors_taking = 0;
	socket_watchers = 0;
	for (int i = 0; i < SOCKET_ENTRIES_MAX; i++) {
		if (entries[i].cookie != 0) {
			entries[i].watchers = 0;
			tidy_locked(&entries[i]);
		}
	}
}

// The errors Linux sets on a socket (sk_err) for its peer or the network
static int is_socket_error(int error)
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

// Whether a TCP socket in this state certainly hasn't been shut down for sending (it sent no FIN): a later EPIPE
// from Linux on it, once it's closed, is then a reset after the peer's FIN
static int tcp_not_shut(const struct linux_tcp_info* info)
{
	switch (info->state) {
	case LINUX_TCP_SYN_SENT:
	case LINUX_TCP_ESTABLISHED:
	case LINUX_TCP_CLOSE_WAIT:
		return 1;
	case LINUX_TCP_CLOSE:
		return !(info->segs_out || info->segs_in); // new
	default:
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
		errored_locked(e, error);
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
	st->resets = 0;
	st->timeouts = 0;

	if (linux_tcp_info(fd, &info) == 0) {
		st->state = tcp_state(&info) | SOSTATE_EVCONNINFO;
		// Linux reports a socket error (sk_err) as POLLERR. A closed TCP socket's is why it closed.
		if ((pfd.revents & LINUX_POLLERR) && info.state == LINUX_TCP_CLOSE)
			take_tcp_error(fd, cookie);
	} else {
		// Other sockets: one with a peer is connected until it hangs up (Linux: both directions shut down), then
		// disconnected. A new stream socket hangs up too, but has no peer. Linux doesn't report a shutdown of only
		// the sending direction: a watched socket's own shutdown() is remembered.
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
			st->state |= e->shut;
			st->error = e->held;
			st->resets = e->resets;
			st->timeouts = e->timeouts;
		}
		sigsafe_unlock(&entries_lock, mask);
	}

	return 0;
}

int socket_error(int fd, int linux_error)
{
	struct linux_tcp_info info;
	unsigned long long cookie;
	int error = 0;

	if (!linux_error && !SOCKET_ERRORS_HELD())
		return 0;
	if (linux_socket_cookie(fd, &cookie) < 0)
		return 0;
	if (linux_error && linux_tcp_info(fd, &info) == 0 && info.state == LINUX_TCP_CLOSE)
		take_tcp_error(fd, cookie);
	if (SOCKET_ENTRIES_USED()) {
		unsigned long long mask = sigsafe_lock(&entries_lock);
		struct socket_entry* e = find_locked(cookie);
		if (e != NULL)
			error = e->held;
		sigsafe_unlock(&entries_lock, mask);
	}
	return error;
}

void socket_watch(int fd, int delta)
{
	struct linux_tcp_info info;
	unsigned long long cookie, mask;
	int plain = 1;

	// the gates open before the entry is made, and close after it's gone
	if (delta > 0)
		__atomic_add_fetch(&socket_watchers, 1, __ATOMIC_SEQ_CST);

	if (linux_socket_cookie(fd, &cookie) == 0) {
		if (delta > 0 && linux_tcp_info(fd, &info) == 0)
			plain = !tcp_not_shut(&info);
		mask = sigsafe_lock(&entries_lock);
		struct socket_entry* e = delta > 0 ? entry_locked(cookie) : find_locked(cookie);
		if (e != NULL) {
			if (delta > 0) {
				e->watchers++;
				e->epipe_plain |= plain;
			} else if (e->watchers > 0) {
				e->watchers--;
				tidy_locked(e);
			}
		}
		sigsafe_unlock(&entries_lock, mask);
	}

	if (delta < 0)
		__atomic_sub_fetch(&socket_watchers, 1, __ATOMIC_SEQ_CST);
}

void socket_shutdown(int fd, int how)
{
	unsigned long long cookie;

	if (linux_socket_cookie(fd, &cookie) < 0)
		return;

	unsigned long long mask = sigsafe_lock(&entries_lock);
	struct socket_entry* e = find_locked(cookie);
	if (e != NULL && e->watchers > 0) {
		// XNU's soshutdown(): sorflush() for reading, the protocol's pru_shutdown() (socantsendmore()) for sending
		if (how != SHUT_WR)
			e->shut |= SOSTATE_CANTRCVMORE;
		if (how != SHUT_RD) {
			e->shut |= SOSTATE_CANTSENDMORE;
			e->epipe_plain = 1;
		}
	}
	sigsafe_unlock(&entries_lock, mask);
}

// Linux returned error, its own, to the program: the socket's one error is now that, so the held one goes
static void linux_gave_error(unsigned long long cookie, int error)
{
	unsigned long long mask = sigsafe_lock(&entries_lock);
	struct socket_entry* e = find_locked(cookie);

	if (e != NULL) {
		unhold_locked(e);
		errored_locked(e, error);
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

long socket_error_read(int fd, long ret, int peek, int eof)
{
	struct linux_tcp_info info;
	unsigned long long cookie;

	// no data: XNU's soreceive() returns the pending error before end of file or EWOULDBLOCK
	if (ret == 0 || ret == -EAGAIN || ret == -ENOTCONN) {
		// A reset after the peer's FIN closes a TCP socket with an error (Linux: EPIPE), but Linux's tcp_recvmsg()
		// returns end of file first, leaving the error: taken here
		if (ret == 0 && eof && linux_tcp_info(fd, &info) == 0 && info.state == LINUX_TCP_CLOSE
				&& linux_socket_cookie(fd, &cookie) == 0)
			take_tcp_error(fd, cookie);
		if (!SOCKET_ERRORS_HELD() || linux_socket_cookie(fd, &cookie) < 0)
			return ret;
		int held = held_error(cookie, peek);
		return held != 0 ? -held : ret;
	}

	if (!is_socket_error(-ret) || linux_socket_cookie(fd, &cookie) < 0)
		return ret;
	linux_gave_error(cookie, -ret);
	return ret;
}

long socket_error_send(int fd, long ret)
{
	struct linux_tcp_info info;
	unsigned long long cookie;
	struct socket_entry* e;
	int error = -ret, watched;

	// XNU's sosendcheck() fails a send on a disconnected socket with EPIPE, before looking at so_error, which stays;
	// Linux's TCP returns (and clears) the error that closed the socket
	if (!is_socket_error(error))
		return ret;
	if (linux_tcp_info(fd, &info) < 0 || info.state != LINUX_TCP_CLOSE || linux_socket_cookie(fd, &cookie) < 0)
		return ret;

	unsigned long long mask = sigsafe_lock(&entries_lock);
	if (error == EPIPE) {
		// Linux's EPIPE is also its error for a reset after the peer's FIN, which the send cleared; the two can be
		// told apart on a watched socket that hasn't been shut down for sending
		e = find_locked(cookie);
		if (e == NULL || e->watchers == 0 || e->epipe_plain) {
			sigsafe_unlock(&entries_lock, mask);
			return ret;
		}
		error = ECONNRESET;
	} else
		e = entry_locked(cookie);
	hold_locked(e, tcp_error(error));
	errored_locked(e, e->held);
	watched = e->watchers > 0;
	sigsafe_unlock(&entries_lock, mask);

	// a knote that looked while the error was neither in Linux nor held looks again
	if (watched)
		SOCKET_CHANGED(fd);
	return -EPIPE;
}

void socket_errors_forget(unsigned long long cookie)
{
	if (cookie == 0)
		return;

	unsigned long long mask = sigsafe_lock(&entries_lock);
	struct socket_entry* e = find_locked(cookie);
	if (e != NULL) {
		unhold_locked(e);
		tidy_locked(e);
	}
	sigsafe_unlock(&entries_lock, mask);
}

unsigned long long socket_errors_cookie(int fd)
{
	unsigned long long cookie;

	return linux_socket_cookie(fd, &cookie) == 0 ? cookie : 0;
}

void socket_errors_close(int fd)
{
	socket_errors_forget(socket_errors_cookie(fd));
}
