#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_kern.h>

#include <sys/errno.h>

#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_proc.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/getrlimit.h>
#include <darling/emulation/linux_premigration/ext/sysinfo.h>
#include <darling/emulation/linux_premigration/ext/syslog.h>
#include <darling/emulation/linux_premigration/ext/sys/utsname.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/bsd/impl/time/gettimeofday.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/common/libsystem.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/duct_errno.h>

#include <darling-config.h>

enum {
	_KERN_MSGBUF = 1000,
	_KERN_OSPRODUCTVERSION,
	_KERN_BOOTARGS,
	_KERN_BOOTSESSIONUUID,

	_KERN_SEMMNS = 1000,
};

static sysctl_handler(handle_msgbuf);
static sysctl_handler(handle_proc);
static sysctl_handler(handle_procargs32);
static sysctl_handler(handle_argmax);
static sysctl_handler(handle_boottime);
static sysctl_handler(handle_ostype);
static sysctl_handler(handle_hostname);
static sysctl_handler(handle_domainname);
static sysctl_handler(handle_osrelease);
static sysctl_handler(handle_version);
static sysctl_handler(handle_osversion);
static sysctl_handler(handle_maxproc);
static sysctl_handler(handle_netboot);
static sysctl_handler(handle_safeboot);
static sysctl_handler(handle_usrstack32);
static sysctl_handler(handle_usrstack64);
static sysctl_handler(handle_sysv_semmns);
static sysctl_handler(handle_osproductversion);
static sysctl_handler(handle_osrevision);
static sysctl_handler(handle_bootargs);
static sysctl_handler(handle_bootsessionuuid);
static sysctl_handler(handle_hostid);

extern int _sysctl_proc(int what, int flag, struct kinfo_proc* out, unsigned long* buflen);
extern int _sysctl_procargs(int pid, char* buf, unsigned long* buflen);
extern int strlcpy(char* dst, const char* src, __SIZE_TYPE__ dst_size);
extern __SIZE_TYPE__ strlen(const char* str);

const struct known_sysctl sysctls_kern_sysv[] = {
	{ .oid = _KERN_SEMMNS, .type = CTLTYPE_INT, .exttype = "I", .name = "semmns", .handler = handle_sysv_semmns },
	{ .oid = -1 }
};

const struct known_sysctl sysctls_kern[] = {
	{ .oid = _KERN_MSGBUF, .type = CTLTYPE_STRING, .exttype = "S", .name = "msgbuf", .handler = handle_msgbuf },
	{ .oid = KERN_PROC, .type = CTLTYPE_STRUCT, .exttype = "", .name = "proc", .handler = handle_proc },
	{ .oid = KERN_PROCARGS2, .type = CTLTYPE_STRUCT, .exttype = "", .name = "procargs2", .handler = handle_procargs32 },
	{ .oid = KERN_ARGMAX, .type = CTLTYPE_INT, .exttype = "I", .name = "argmax", .handler = handle_argmax },
	{ .oid = KERN_MAXPROC, .type = CTLTYPE_INT, .exttype = "I", .name = "maxproc", .handler = handle_maxproc },
	{ .oid = KERN_NETBOOT, .type = CTLTYPE_INT, .exttype = "I", .name = "netboot", .handler = handle_netboot },
	{ .oid = KERN_SAFEBOOT, .type = CTLTYPE_INT, .exttype = "I", .name = "safeboot", .handler = handle_safeboot },
	{ .oid = KERN_BOOTTIME, .type = CTLTYPE_STRUCT, .exttype = "S,timeval", .name = "boottime", .handler = handle_boottime },
	{ .oid = KERN_OSTYPE, .type = CTLTYPE_STRING, .exttype = "S", .name = "ostype", .handler = handle_ostype },
	{ .oid = KERN_HOSTNAME, .type = CTLTYPE_STRING, .exttype = "S", .name = "hostname", .handler = handle_hostname },
	{ .oid = KERN_HOSTID, .type = CTLTYPE_INT, .exttype = "I", .name = "hostid", .handler = handle_hostid },
	{ .oid = KERN_DOMAINNAME, .type = CTLTYPE_STRING, .exttype = "S", .name = "domainname", .handler = handle_domainname },
	{ .oid = KERN_OSRELEASE, .type = CTLTYPE_STRING, .exttype = "S", .name = "osrelease", .handler = handle_osrelease },
	{ .oid = KERN_VERSION, .type = CTLTYPE_STRING, .exttype = "S", .name = "version", .handler = handle_version },
	{ .oid = KERN_OSVERSION, .type = CTLTYPE_STRING, .exttype = "S", .name = "osversion", .handler = handle_osversion },
	{ .oid = KERN_USRSTACK32, .type = CTLTYPE_INT, .exttype = "I", .name = "usrstack", .handler = handle_usrstack32 },
	{ .oid = KERN_USRSTACK64, .type = CTLTYPE_QUAD, .exttype = "Q", .name = "usrstack64", .handler = handle_usrstack64 },
	{ .oid = _KERN_OSPRODUCTVERSION, .type = CTLTYPE_STRING, .exttype = "S", .name = "osproductversion", .handler = handle_osproductversion },
	{ .oid = KERN_OSREV, .type = CTLTYPE_INT, .exttype = "I", .name = "osrevision", .handler = handle_osrevision },
	{ .oid = _KERN_BOOTARGS, .type = CTLTYPE_STRING, .exttype = "S", .name = "bootargs", .handler = handle_bootargs },
	{ .oid = _KERN_BOOTSESSIONUUID, .type = CTLTYPE_STRING, .exttype = "S", .name = "bootsessionuuid", .handler = handle_bootsessionuuid },
	{ .oid = KERN_SYSV, .type = CTLTYPE_NODE, .exttype = "", .name = "sysv", .subctls = sysctls_kern_sysv },
	{ .oid = -1 }
};

sysctl_handler(handle_msgbuf)
{
	if (*oldlen <= 8)
	{
		// Caller is asking for buffer size
		if (*oldlen < sizeof(int))
			return -EINVAL;

		*((int*) old) = __linux_syslog(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0);
	}
	else
	{
		// Caller is asking for buffer contents
		int ret;

		ret = __linux_syslog(SYSLOG_ACTION_READ_ALL, (char*) old, *oldlen);
		if (ret < 0)
			return errno_linux_to_bsd(ret);

		*oldlen = ret;
	}
	return 0;
}

sysctl_handler(handle_proc)
{
	if (nlen < 4)
		return -ENOENT;
	return _sysctl_proc(name[2], name[3], (struct kinfo_proc*) old, oldlen);
}

sysctl_handler(handle_procargs32)
{
	if (nlen < 3)
		return -ENOENT;
	return _sysctl_procargs(name[2], (char*) old, oldlen);
}

sysctl_handler(handle_argmax)
{
	struct xnu_rlimit lim;
	int r;
	int* ovalue = (int*) old;

	r = sys_getrlimit(BSD_RLIMIT_STACK, &lim);
	if (r < 0)
		return r;

	if (ovalue != NULL)
		*ovalue = lim.rlim_cur / 4;
	*oldlen = sizeof(int);
	return 0;
}

#define LINUX_CLOCK_REALTIME 0
#define LINUX_CLOCK_BOOTTIME 7

// what /proc/stat's btime is, to the nanosecond: the wall clock less the time since boot
static long long boot_time_ns(void)
{
	struct { long long tv_sec; long tv_nsec; } now, up;

	if (LINUX_SYSCALL(__NR_clock_gettime, LINUX_CLOCK_REALTIME, &now) < 0 ||
		LINUX_SYSCALL(__NR_clock_gettime, LINUX_CLOCK_BOOTTIME, &up) < 0)
		return -1;
	return (now.tv_sec - up.tv_sec) * 1000000000LL + (now.tv_nsec - up.tv_nsec);
}

// when the system booted, in seconds since the epoch: Linux's own answer (btime in /proc/stat), which, unlike the time
// less the uptime (both in whole seconds, and changing at different moments), is the same every time it's asked.
// CLOCK_MONOTONIC is the time of day less this, and went back and forth by a second.
long long sysctl_boot_time(void)
{
	static long long btime = -1;
	static const char key[] = "\nbtime ";
	char buf[1024];
	unsigned int matched = 0;
	long long value = 0, ns = boot_time_ns();
	int fd, n, digits = 0;

	// read once, so every call agrees; and again once the wall clock has been set, as Linux's answer then moves
	// (the nanosecond answer is the cached second plus under one, give or take the time between the two clocks)
	if (btime >= 0 && (ns < 0 || (ns / 1000000 - btime * 1000 > -1500 && ns / 1000000 - btime * 1000 < 2500)))
		return btime;

	fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, "/proc/stat", LINUX_O_RDONLY | LINUX_O_CLOEXEC, 0);
	if (fd < 0)
		return fd;
	while ((n = LINUX_SYSCALL(__NR_read, fd, buf, sizeof(buf))) > 0)
	{
		for (int i = 0; i < n; i++)
		{
			char c = buf[i];
			if (matched < sizeof(key) - 1)
				matched = (c == key[matched]) ? matched + 1 : (c == key[0]);
			else if (c >= '0' && c <= '9')
				value = value * 10 + (c - '0'), digits++;
			else
				goto done;
		}
	}
done:
	close_internal(fd);
	if (!digits)
		return -LINUX_ENOENT;
	btime = value;
	return btime;
}

sysctl_handler(handle_boottime)
{
	// Fill in struct timeval { tv_sec, tv_usec }
	struct bsd_timeval* tv;
	long long btime = sysctl_boot_time();

	if (btime < 0)
		return errno_linux_to_bsd(btime);

	tv = (struct bsd_timeval*) old;
	if (tv != NULL)
	{
		if (*oldlen < sizeof(*tv))
			return -EINVAL;
		tv->tv_sec = btime;
		// a whole second, as Linux gives it: the same in every process, and in every call (libc's
		// _mach_boottime_usec() loops until two calls agree)
		tv->tv_usec = 0;
	}
	*oldlen = sizeof(*tv);

	return 0;
}

sysctl_handler(handle_ostype)
{
	const char* s = EMULATED_SYSNAME;

	copyout_string(s, (char*) old, oldlen);
	return 0;
}

// The kernel's boot-args: Darling has none. The simulator's launchd_sim won't start without the string.
sysctl_handler(handle_bootargs)
{
	copyout_string("", (char*) old, oldlen);
	return 0;
}

// The UUID XNU makes at each boot, which libtrace (os_log) won't run without: Linux's boot ID, in XNU's upper case.
sysctl_handler(handle_bootsessionuuid)
{
	char uuid[37];
	int fd, rd, i;

	fd = sys_open_nocancel("/proc/sys/kernel/random/boot_id", BSD_O_RDONLY, 0);
	if (fd < 0)
		return fd;
	rd = sys_read_nocancel(fd, uuid, sizeof(uuid) - 1);
	close_internal(fd);
	if (rd < (int) sizeof(uuid) - 1)
		return -ENOENT;

	uuid[sizeof(uuid) - 1] = '\0';
	for (i = 0; uuid[i]; i++)
	{
		if (uuid[i] >= 'a' && uuid[i] <= 'f')
			uuid[i] -= 'a' - 'A';
	}

	copyout_string(uuid, (char*) old, oldlen);
	return 0;
}

sysctl_handler(handle_osrelease)
{
	const char* s = __libkernel_has_apple_libsystem() ? SIMULATOR_HOST_RELEASE : EMULATED_RELEASE;

	copyout_string(s, (char*) old, oldlen);
	return 0;
}

sysctl_handler(handle_version)
{
	const char* s = __libkernel_has_apple_libsystem() ? SIMULATOR_HOST_VERSION : EMULATED_VERSION;

	copyout_string(s, (char*) old, oldlen);
	return 0;
}

sysctl_handler(handle_osversion)
{
	const char* s = __libkernel_has_apple_libsystem() ? SIMULATOR_HOST_OSVERSION : EMULATED_OSVERSION;

	copyout_string(s, (char*) old, oldlen);
	return 0;
}


static struct linux_utsname lu;
struct linux_utsname* need_uname(void)
{
#ifndef VARIANT_DYLD
	// Cache __linux_uname results
	if (!lu.sysname[0])
	{
		__linux_uname(&lu);
	}
#endif
	return &lu;
}

sysctl_handler(handle_hostname)
{
	int rv = 0;
	
	need_uname();
	copyout_string(lu.nodename, (char*) old, oldlen);
	
	if (_new && newlen > 0)
	{
		rv = LINUX_SYSCALL(__NR_sethostname, _new, newlen);
		if (rv < 0)
			rv = errno_linux_to_bsd(rv);
	}
	
	return rv;
}

sysctl_handler(handle_domainname)
{
	int rv = 0;
	
	need_uname();
	copyout_string(lu.domainname, (char*) old, oldlen);
	
	if (_new && newlen > 0)
	{
		rv = LINUX_SYSCALL(__NR_setdomainname, _new, newlen);
		if (rv < 0)
			rv = errno_linux_to_bsd(rv);
	}
	
	return rv;
}

sysctl_handler(handle_maxproc)
{
	char buf[16];
	int fd = sys_open_nocancel("/proc/sys/kernel/pid_max", BSD_O_RDONLY, 0);
	int value = 1024;
	int* ovalue = (int*) old;
	
	if (!oldlen)
		return -EINVAL;
	
	if (fd >= 0)
	{
		int rd = sys_read_nocancel(fd, buf, sizeof(buf) - 1);
		close_internal(fd);
		
		if (rd > 0)
		{
			buf[rd] = '\0';
			value = __simple_atoi(buf, NULL);
		}
	}
	
	if (ovalue != NULL)
		*ovalue = value;
	*oldlen = sizeof(int);
	
	return 0;
}

sysctl_handler(handle_netboot)
{
	int* ovalue = (int*) old;
	if (!oldlen)
		return -EINVAL;

	if (*oldlen >= sizeof(int))
		*ovalue = 0;
	*oldlen = sizeof(int);

	return 0;
}

sysctl_handler(handle_safeboot)
{
	int* ovalue = (int*) old;
	if (!oldlen)
		return -EINVAL;

	if (*oldlen >= sizeof(int))
		*ovalue = 0;
	*oldlen = sizeof(int);

	return 0;
}

sysctl_handler(handle_sysv_semmns)
{
	int* ovalue = (int*) old;
	if (!oldlen)
		return -EINVAL;
	if (*oldlen >= sizeof(int))
		*ovalue = -1;
	*oldlen = sizeof(int);
	return 0;
}

sysctl_handler(handle_usrstack32)
{
	unsigned int* ovalue = (unsigned int*) old;
	if (ovalue)
		*ovalue = __darling_thread_get_stack();
	*oldlen = sizeof(*ovalue);
	return 0;
}

sysctl_handler(handle_usrstack64)
{
	unsigned long long* ovalue = (unsigned long long*) old;
	if (ovalue)
		*ovalue = __darling_thread_get_stack();
	*oldlen = sizeof(*ovalue);
	return 0;
}

static sysctl_handler(handle_osproductversion) {
	copyout_string(__libkernel_has_apple_libsystem() ? SIMULATOR_HOST_OSPRODUCTVERSION : EMULATED_OSPRODUCTVERSION,
			(char*)old, oldlen);
	return 0;
};

// Apple no longer changes this value
// https://lists.apple.com/archives/darwin-dev/2005/Jul/msg00029.html
#define EMULATED_OSREVISION 199506

static sysctl_handler(handle_osrevision) {
	int* ovalue = (int*)old;
	if (ovalue)
		*ovalue = EMULATED_OSREVISION;
	*oldlen = sizeof(*ovalue);
	return 0;
}

// XNU's kern.hostid (kern_sysctl.c): a system-wide int, 0 until root sets it. libbsm's audit_set_terminal_host() reads
// it for every audit token's terminal. A write is EPERM, which XNU also answers to a writer that isn't root (the
// sysctl is CTLFLAG_RW without CTLFLAG_ANYBODY); only a root writer differs. Nothing here writes it. Making it
// writable would mean keeping the value in darlingserver, not in this process.
static sysctl_handler(handle_hostid) {
	int* ovalue = (int*)old;
	if (_new && newlen > 0)
		return -EPERM;
	if (!oldlen)
		return -EINVAL;
	if (ovalue && *oldlen >= sizeof(int))
		*ovalue = 0;
	*oldlen = sizeof(int);
	return 0;
}
