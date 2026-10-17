#include <darling/emulation/xnu_syscall/bsd/impl/psynch/psynch_cvclrprepost.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/simple.h>

#include <darlingserver/rpc.h>

long sys_psynch_cvclrprepost(void* cv, uint32_t cvgen, uint32_t cvugen, uint32_t cvsgen, uint32_t prepocnt, uint32_t preposeq, uint32_t flags)
{
	uint32_t retval;
	int ret = dserver_rpc_psynch_cvclrprepost(cv, cvgen, cvugen, cvsgen, prepocnt, preposeq, flags, &retval);

	if (ret < 0) {
		__simple_printf("psynch_cvclrprepost failed internally: %d", ret);
		__simple_abort();
	}

	// the server answers XNU's error (positive, with psynch's ECVCLEARED/ECVPREPOST bits in it) as the result code: an
	// error here, as XNU returns it with the carry flag set. Returned as a result, libpthread took a timed-out wait's
	// 316 (ECVCLEARED | ETIMEDOUT) for the wait's sequence bits, its condition variable's words drifted, and a later
	// wait failed with EINVAL (std's Condvar::wait_timeout asserts on that, and aborted backboardd). Both as long: the
	// conditional of an int and a uint32_t is unsigned, which would make the error a large result again.
	return (ret) ? (long) -ret : (long) retval;
}
