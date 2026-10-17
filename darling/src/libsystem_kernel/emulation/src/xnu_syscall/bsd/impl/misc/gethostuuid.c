#include <darling/emulation/xnu_syscall/bsd/impl/misc/gethostuuid.h>

#include <stdbool.h>
#include <sys/fcntl.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/getentropy.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getpid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/link.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/unlink.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/write.h>

// XNU's gethostuuid() returns the platform UUID IOKit has, the same for every process on the machine and across its
// restarts (an iOS Simulator's processes get their Mac's). Darling's host is the Linux system's machine ID. A
// container's is often empty (Debian's images ship an empty /etc/machine-id, which systemd would fill at boot), so
// then the prefix makes one up once and keeps it.
#define HOSTUUID_PREFIX_PATH "/private/var/db/darling-hostuuid"

static const char* const machine_id_paths[] = {
	"/Volumes/SystemRoot/etc/machine-id",
	"/Volumes/SystemRoot/var/lib/dbus/machine-id",
	HOSTUUID_PREFIX_PATH,
};

// The UUID, once found: the first thread to find it fills the cache (FILLING), and the others read it once READY
enum { CACHE_EMPTY, CACHE_FILLING, CACHE_READY };
static unsigned char cached_uuid[16];
static int cache_state;

static int hvalue(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F')
		return 10 + (c - 'A');
	return -1;
}

// A machine ID's format (machine-id(5)): 32 hexadecimal digits and a newline
static bool read_machine_id(const char* path, unsigned char uuid[16])
{
	char buf[34];
	long n, fd = sys_open_nocancel(path, O_RDONLY | O_CLOEXEC, 0);

	if (fd < 0)
		return false;
	n = sys_read_nocancel(fd, buf, sizeof(buf));
	close_internal(fd);

	if (n < 32 || n > 33 || (n == 33 && buf[32] != '\n'))
		return false;
	for (int i = 0; i < 16; i++) {
		int hi = hvalue(buf[i * 2]), lo = hvalue(buf[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return false;
		uuid[i] = (unsigned char) (hi << 4 | lo);
	}
	return true;
}

// Makes the prefix's machine ID, unless another process just did: written to a file of this process's own, then
// linked into place, so readers never see a partial one and the first link wins.
static void make_prefix_machine_id(void)
{
	static const char hex[] = "0123456789abcdef";
	unsigned char id[16];
	char text[33], tmp[sizeof(HOSTUUID_PREFIX_PATH) + 16];
	long fd;

	if (sys_getentropy(id, sizeof(id)) != 0)
		return;
	// a random (version 4) UUID, as machine-id(5) asks of a new one
	id[6] = (id[6] & 0x0f) | 0x40;
	id[8] = (id[8] & 0x3f) | 0x80;
	for (int i = 0; i < 16; i++) {
		text[i * 2] = hex[id[i] >> 4];
		text[i * 2 + 1] = hex[id[i] & 15];
	}
	text[32] = '\n';

	__simple_sprintf(tmp, "%s.%d", HOSTUUID_PREFIX_PATH, (int) sys_getpid());
	fd = sys_open_nocancel(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return;
	bool written = sys_write_nocancel(fd, text, sizeof(text)) == sizeof(text);
	close_internal(fd);
	if (written)
		sys_link(tmp, HOSTUUID_PREFIX_PATH);
	sys_unlink(tmp);
}

long sys_gethostuuid(unsigned char* uuid_buf, void* timeout)
{
	unsigned char uuid[16];
	bool found = false;

	// XNU copies the timeout in before it asks IOKit, and the UUID out after
	if (timeout == NULL || uuid_buf == NULL)
		return -EFAULT;

	if (__atomic_load_n(&cache_state, __ATOMIC_ACQUIRE) == CACHE_READY) {
		__builtin_memcpy(uuid_buf, cached_uuid, sizeof(cached_uuid));
		return 0;
	}

	for (int i = 0; i < sizeof(machine_id_paths) / sizeof(machine_id_paths[0]) && !found; i++)
		found = read_machine_id(machine_id_paths[i], uuid);
	if (!found) {
		make_prefix_machine_id();
		found = read_machine_id(HOSTUUID_PREFIX_PATH, uuid);
	}
	// XNU's answer when IOKit has no platform UUID
	if (!found)
		return -EWOULDBLOCK;

	int expected = CACHE_EMPTY;
	if (__atomic_compare_exchange_n(&cache_state, &expected, CACHE_FILLING, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		__builtin_memcpy(cached_uuid, uuid, sizeof(uuid));
		__atomic_store_n(&cache_state, CACHE_READY, __ATOMIC_RELEASE);
	}
	__builtin_memcpy(uuid_buf, uuid, sizeof(uuid));
	return 0;
}
