#ifndef LINUX_PROC_INFO_H
#define LINUX_PROC_INFO_H

#include <stdint.h>

long sys_proc_info(uint32_t callnum, int32_t pid, uint32_t flavor,
		uint64_t arg, void* buffer, int32_t bufsize);
long sys_proc_info_extended_id(int32_t callnum, int32_t pid, uint32_t flavor, uint32_t flags, uint64_t ext_id,
		uint64_t arg, void* buffer, int32_t bufsize);

// sys/proc_info.h has these only for PRIVATE; proc_identity_check() takes them
#ifndef PIF_COMPARE_IDVERSION
#define PIF_COMPARE_IDVERSION 0x01
#endif
#ifndef PIF_COMPARE_UNIQUEID
#define PIF_COMPARE_UNIQUEID 0x02
#endif

// 0 if the process pid names now has the pid version (PIF_COMPARE_IDVERSION) or unique id (PIF_COMPARE_UNIQUEID)
// ext_id, -ESRCH if not, as XNU checks an audit token's or an extended id's process; another negative BSD errno if
// darlingserver can't say
long proc_identity_check(int32_t pid, uint32_t flags, uint64_t ext_id);

#endif // LINUX_PROC_INFO_H
