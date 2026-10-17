#ifndef _SYSCTL_KERN_H
#define _SYSCTL_KERN_H

#include <darling/emulation/xnu_syscall/bsd/impl/misc/sysctl.h>

extern const struct known_sysctl sysctls_kern[];

struct linux_utsname* need_uname(void);

// kern.boottime's seconds: Linux's boot time, in seconds since the epoch; or a negative Linux errno
long long sysctl_boot_time(void);

#endif // _SYSCTL_KERN_H
