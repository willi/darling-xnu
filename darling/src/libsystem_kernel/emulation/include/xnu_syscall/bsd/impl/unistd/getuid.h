#ifndef LINUX_GETUID_H
#define LINUX_GETUID_H

#include <stdint.h>

long sys_getuid(void);

void __getuidgid(int32_t* uid, int32_t* gid);
long __setuidgid(int32_t uid, int32_t gid);

// The Linux process's real uid: the one Linux checks permissions as (faccessat() without AT_EACCESS), and the owner
// Linux's stat() reports. It isn't sys_getuid(), the uid darlingserver keeps for the process: setuid() changes only
// that one (Linux's ids don't change), and stat() reports it as every file's owner.
int linux_real_uid(void);

#endif // LINUX_GETUID_H
