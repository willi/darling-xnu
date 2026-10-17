#include <darling/emulation/xnu_syscall/bsd/impl/misc/mac_syscall.h>

#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/linux_path.h>

extern int strcmp(const char *s1, const char *s2);

// libsystem_sandbox's sandbox_check() and its variants
#define SANDBOX_CALL_CHECK 2
// libsystem_sandbox's sandbox_passthrough_access(fd, mode)
#define SANDBOX_CALL_PASSTHROUGH_ACCESS 12

// R_OK | W_OK | X_OK, which Linux shares
#define ACCESS_MODE_MASK 07

struct sandbox_passthrough_access_args
{
	int64_t fd;
	uint64_t mode;
};

// What the file's permissions allow the caller, by its effective ids. The low bits of the mode are access()'s
// (CFPreferences asks about a directory with W_OK | 0x100; that high bit's meaning isn't known).
static long sandbox_passthrough_access(const struct sandbox_passthrough_access_args* args)
{
	return linux_path_access((int) args->fd, "", args->mode & ACCESS_MODE_MASK, LINUX_AT_EACCESS | LINUX_AT_EMPTY_PATH);
}

// Darling registers no MAC policies, so this fails like XNU's __mac_syscall() with no policy of that name. The
// exceptions are the Sandbox calls that ask what a process may do: every Darling process is unsandboxed, and
// Sandbox.kext answers those for an unsandboxed process by the ordinary permissions alone.
long sys_mac_syscall(const char* policy, int call, void* arg)
{
	if (policy == NULL)
		return -EFAULT;
	if (strcmp(policy, "Sandbox") != 0)
		return -ENOPOLICY;

	switch (call)
	{
		case SANDBOX_CALL_CHECK:
			// Its callers zero the result before the call, so leaving it untouched answers "allowed". Without
			// this, sandbox_check() returns -1 and CFPreferences, for one, stops talking to cfprefsd.
			return 0;
		case SANDBOX_CALL_PASSTHROUGH_ACCESS:
			// cfprefsd checks that it may write a preferences file's directory with this
			if (arg == NULL)
				return -EFAULT;
			return sandbox_passthrough_access(arg);
		default:
			return -ENOPOLICY;
	}
}
