#include <darling/emulation/xnu_syscall/bsd/impl/mman/madvise.h>

#include <sys/errno.h>
#include <sys/mman.h>

#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define MADV_FREE 5
#define MADV_FREE_REUSABLE 7
#define MADV_FREE_REUSE 8

// Linux's page on x86_64
#define LINUX_PAGE_SIZE 4096UL
#define LINUX_MADV_COLD 20

long sys_madvise(void* addr, unsigned long len, int advice)
{
	int ret;

	if (advice == MADV_FREE_REUSABLE || advice == MADV_FREE_REUSE)
		advice = MADV_FREE;

	// advice < 0 are identical between OS X and Linux
	// advice >= 5 are specific to OS X/BSD
	if (advice >= 5)
		return 0;

	// XNU's MADV_DONTNEED is a hint that keeps the data (VM_BEHAVIOR_DONTNEED deactivates the pages); Linux's
	// discards private pages, so anonymous memory reads back as zeroes. Linux's MADV_COLD is the hint XNU's is.
	int linux_advice = advice == MADV_DONTNEED ? LINUX_MADV_COLD : advice;

	// XNU advises the whole pages the range touches (mach_vm_behavior_set() truncates the start and rounds the end to
	// the page); Linux fails an address that isn't page-aligned with EINVAL. LaunchServices' prewarming
	// (madvise(MADV_WILLNEED) on a property list in its database) failed that way for every record it read.
	unsigned long start = (unsigned long) addr & ~(LINUX_PAGE_SIZE - 1);
	unsigned long off = (unsigned long) addr - start;
	if (len > 0) {
		// a range that wraps past the end of memory is invalid, as on Linux and XNU
		if (len > ~0UL - off)
			return -EINVAL;
		len += off;
	}

	ret = LINUX_SYSCALL(__NR_madvise, start, len, linux_advice);

	// a kernel before 5.4 has no MADV_COLD; the hint is only a hint
	if (ret == -LINUX_EINVAL && linux_advice == LINUX_MADV_COLD)
		ret = 0;
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
