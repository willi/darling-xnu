#include <darling/emulation/xnu_syscall/bsd/impl/mman/madvise.h>

#include <sys/errno.h>
#include <sys/mman.h>

#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define MADV_FREE 5
#define MADV_FREE_REUSABLE 7
#define MADV_FREE_REUSE 8

// Linux's page on x86_64 (mmap() here assumes the same)
#define LINUX_PAGE_SIZE 4096UL

long sys_madvise(void* addr, unsigned long len, int advice)
{
	int ret;

	if (advice == MADV_FREE_REUSABLE || advice == MADV_FREE_REUSE)
		advice = MADV_FREE;

	// advice < 0 are identical between OS X and Linux
	// advice >= 5 are specific to OS X/BSD
	if (advice >= 5)
		return 0;

	// XNU advises the whole pages the range touches (mach_vm_behavior_set() truncates the start and rounds the end to
	// the page); Linux fails an address that isn't page-aligned with EINVAL. LaunchServices' prewarming
	// (madvise(MADV_WILLNEED) on a property list in its database) failed that way for every record it read.
	// Only the pure hints are widened: Linux's MADV_DONTNEED discards private pages, so it must not reach past the
	// caller's range.
	if (advice != MADV_DONTNEED) {
		unsigned long start = (unsigned long) addr & ~(LINUX_PAGE_SIZE - 1);
		unsigned long off = (unsigned long) addr - start;
		if (len > 0) {
			// a range that wraps past the end of memory is invalid, as on Linux and XNU
			if (len > ~0UL - off)
				return -EINVAL;
			len += off;
		}
		addr = (void*) start;
	}

	ret = LINUX_SYSCALL(__NR_madvise, addr, len, advice);

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
