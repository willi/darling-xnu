#include <darling/emulation/xnu_syscall/bsd/impl/misc/gethostuuid.h>

#include <stdbool.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/_types/_timespec.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/sha256.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/getentropy.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchmod.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fsync.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/link.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/rename.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/unlink.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/write.h>

// XNU's gethostuuid() returns the platform UUID IOKit has, the same for every process on the machine and across its
// restarts (an iOS Simulator's processes get their Mac's). Darling's host is the Linux system's machine ID, hashed as
// machine-id(5) asks of applications, so the host's own ID never reaches Darwin code.
//
// A container's machine ID is often empty (Debian's images ship an empty /etc/machine-id, which systemd would fill at
// boot). Then the prefix makes one up once and keeps it. Should the host gain a machine ID later, the host's is the
// one used from then on: a prefix's made-up ID only stands in for the host's.
#define HOSTUUID_PREFIX_PATH "/private/var/db/darling-hostuuid"

static const char* const host_machine_id_paths[] = {
	"/Volumes/SystemRoot/etc/machine-id",
	"/Volumes/SystemRoot/var/lib/dbus/machine-id",
};

// The application ID the host's machine ID is hashed with (the message of the HMAC below); changing it changes every
// Darling host's UUID
static const unsigned char darling_app_id[16] = {
	0xae, 0xcc, 0x84, 0x54, 0x64, 0xdd, 0x41, 0xad, 0xa1, 0x3c, 0x55, 0xf0, 0xbd, 0xea, 0x2e, 0x24,
};

// The UUID, once found: the first thread to find it fills the cache (FILLING), and the others read it once READY
enum { CACHE_EMPTY, CACHE_FILLING, CACHE_READY };
static unsigned char cached_uuid[16];
static int cache_state;

enum machine_id { ID_OK, ID_NONE, ID_INVALID };

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

// A machine ID's format (machine-id(5)): 32 hexadecimal digits and a newline. All zeros is no ID (systemd's
// sd_id128_is_null()).
static enum machine_id read_machine_id(const char* path, unsigned char uuid[16])
{
	char buf[34];
	long n, fd = sys_open_nocancel(path, O_RDONLY | O_CLOEXEC, 0);
	unsigned char any = 0;

	if (fd < 0)
		return ID_NONE;
	n = sys_read_nocancel(fd, buf, sizeof(buf));
	close_internal(fd);

	if (n < 32 || n > 33 || (n == 33 && buf[32] != '\n'))
		return ID_INVALID;
	for (int i = 0; i < 16; i++) {
		int hi = hvalue(buf[i * 2]), lo = hvalue(buf[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return ID_INVALID;
		uuid[i] = (unsigned char) (hi << 4 | lo);
		any |= uuid[i];
	}
	return any ? ID_OK : ID_INVALID;
}

// A random (version 4) UUID's bits, as machine-id(5) asks of a new ID
static void make_v4(unsigned char id[16])
{
	id[6] = (id[6] & 0x0f) | 0x40;
	id[8] = (id[8] & 0x3f) | 0x80;
}

// systemd's sd_id128_get_machine_app_specific(): HMAC-SHA256 keyed by the machine ID, of the application's ID, its
// first 16 bytes made a version 4 UUID
static void app_specific_id(const unsigned char machine_id[16], unsigned char uuid[16])
{
	unsigned char pad[64], inner[SHA256_BLOCK_SIZE], outer[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;

	for (int i = 0; i < 64; i++)
		pad[i] = (i < 16 ? machine_id[i] : 0) ^ 0x36;
	sha256_init(&ctx);
	sha256_update(&ctx, pad, sizeof(pad));
	sha256_update(&ctx, darling_app_id, sizeof(darling_app_id));
	sha256_final(&ctx, inner);

	for (int i = 0; i < 64; i++)
		pad[i] = (i < 16 ? machine_id[i] : 0) ^ 0x5c;
	sha256_init(&ctx);
	sha256_update(&ctx, pad, sizeof(pad));
	sha256_update(&ctx, inner, sizeof(inner));
	sha256_final(&ctx, outer);

	__builtin_memcpy(uuid, outer, 16);
	make_v4(uuid);
}

static void hex(char* out, const unsigned char* bytes, int n)
{
	static const char digits[] = "0123456789abcdef";

	for (int i = 0; i < n; i++) {
		out[i * 2] = digits[bytes[i] >> 4];
		out[i * 2 + 1] = digits[bytes[i] & 15];
	}
}

// Makes the prefix's machine ID, unless another process or thread just did. It's written to a file of this call's
// own (a random name, created anew), then linked into place, so readers never see a partial ID and the first link
// wins. Should the file in place be no ID (cut short by a crash, say), this one replaces it; two processes that find
// it so at once may each read its own before the other's rename, a difference that lasts until they restart.
static void make_prefix_machine_id(bool replace)
{
	unsigned char random[16 + 8];
	char text[33], tmp[sizeof(HOSTUUID_PREFIX_PATH) + 1 + 16];
	long fd;

	if (sys_getentropy(random, sizeof(random)) != 0)
		return;
	make_v4(random);
	hex(text, random, 16);
	text[32] = '\n';

	__builtin_memcpy(tmp, HOSTUUID_PREFIX_PATH, sizeof(HOSTUUID_PREFIX_PATH) - 1);
	tmp[sizeof(HOSTUUID_PREFIX_PATH) - 1] = '.';
	hex(tmp + sizeof(HOSTUUID_PREFIX_PATH), random + 16, 8);
	tmp[sizeof(tmp) - 1] = '\0';

	fd = sys_open_nocancel(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0444);
	if (fd < 0)
		return;
	// machine-id(5)'s mode, whatever the umask of the process that happens to make it
	sys_fchmod(fd, 0444);
	bool written = sys_write_nocancel(fd, text, sizeof(text)) == sizeof(text) && sys_fsync_nocancel(fd) == 0;
	close_internal(fd);

	if (written && replace)
		sys_rename(tmp, HOSTUUID_PREFIX_PATH);
	else if (written)
		sys_link(tmp, HOSTUUID_PREFIX_PATH);
	sys_unlink(tmp);
}

// Copies between the caller's memory and this code's as XNU's copyin()/copyout() do: a bad address fails (EFAULT)
// instead of faulting here. Where process_vm_readv()/process_vm_writev() are refused (a seccomp filter, say), the
// memory is copied as it is.
static bool copy_user(void* to, const void* from, unsigned long len, bool out)
{
	struct { const void* base; unsigned long len; } local = { out ? from : to, len }, remote = { out ? to : from, len };
	long ret;

	if (to == NULL || from == NULL)
		return false;
	ret = LINUX_SYSCALL(out ? __NR_process_vm_writev : __NR_process_vm_readv, LINUX_SYSCALL0(__NR_getpid), &local, 1,
		&remote, 1, 0);
	if (ret == -LINUX_ENOSYS || ret == -LINUX_EPERM) {
		__builtin_memcpy(to, from, len);
		return true;
	}
	return ret == (long) len;
}

static bool find_uuid(unsigned char uuid[16])
{
	unsigned char id[16];
	enum machine_id prefix;

	for (int i = 0; i < sizeof(host_machine_id_paths) / sizeof(host_machine_id_paths[0]); i++) {
		if (read_machine_id(host_machine_id_paths[i], id) == ID_OK) {
			app_specific_id(id, uuid);
			return true;
		}
	}

	prefix = read_machine_id(HOSTUUID_PREFIX_PATH, uuid);
	if (prefix != ID_OK) {
		make_prefix_machine_id(prefix == ID_INVALID);
		prefix = read_machine_id(HOSTUUID_PREFIX_PATH, uuid);
	}
	return prefix == ID_OK;
}

long sys_gethostuuid(unsigned char* uuid_buf, void* timeout)
{
	unsigned char uuid[16];
	struct timespec ts;

	// XNU copies the timeout in before it asks IOKit, and the UUID out after
	if (!copy_user(&ts, timeout, sizeof(ts), false))
		return -EFAULT;

	if (__atomic_load_n(&cache_state, __ATOMIC_ACQUIRE) == CACHE_READY) {
		__builtin_memcpy(uuid, cached_uuid, sizeof(uuid));
	} else {
		// XNU's answer when IOKit has no platform UUID
		if (!find_uuid(uuid))
			return -EWOULDBLOCK;

		int expected = CACHE_EMPTY;
		if (__atomic_compare_exchange_n(&cache_state, &expected, CACHE_FILLING, false, __ATOMIC_ACQUIRE,
				__ATOMIC_RELAXED)) {
			__builtin_memcpy(cached_uuid, uuid, sizeof(uuid));
			__atomic_store_n(&cache_state, CACHE_READY, __ATOMIC_RELEASE);
		}
	}

	if (!copy_user(uuid_buf, uuid, sizeof(uuid), true))
		return -EFAULT;
	return 0;
}
