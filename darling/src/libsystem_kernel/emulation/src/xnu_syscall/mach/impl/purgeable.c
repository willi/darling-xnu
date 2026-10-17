#include <darling/emulation/xnu_syscall/mach/impl/purgeable.h>

#include <stdbool.h>
#include <mach/mach_init.h>
#include <libsimple/lock.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/sigsafe_lock.h>
#include <darling/emulation/conversion/mman/duct_mman.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define LINUX_MREMAP_MAYMOVE 1
#define PAGE_MASK_4K ((uintptr_t) 4095)

struct region {
	uintptr_t start, end;
	int state;              // VM_PURGABLE_NONVOLATILE, _VOLATILE or _EMPTY
	bool volatile_empty;    // VM_PURGABLE_DEBUG_EMPTY: made volatile, it's emptied at once
};

// The process's purgeable regions, in memory of their own (no malloc here), unsorted: a process has few
static struct region* regions;
static size_t capacity;
volatile int purgeable_regions;
static libsimple_lock_t purgeable_lock = LIBSIMPLE_LOCK_INITIALIZER;

void purgeable_atfork_child(void)
{
	libsimple_lock_init(&purgeable_lock);
}

static bool grow_locked(void)
{
	size_t bytes = capacity * sizeof(struct region), more = bytes ? bytes * 2 : 4096;
	long p;

	if (regions == NULL)
#ifdef __NR_mmap2
		p = LINUX_SYSCALL6(__NR_mmap2, 0, more, LINUX_PROT_READ | LINUX_PROT_WRITE,
			LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
#else
		p = LINUX_SYSCALL6(__NR_mmap, 0, more, LINUX_PROT_READ | LINUX_PROT_WRITE,
			LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
#endif
	else
		p = LINUX_SYSCALL(__NR_mremap, regions, bytes, more, LINUX_MREMAP_MAYMOVE);
	if ((unsigned long) p > -4096UL)
		return false;
	regions = (struct region*) p;
	capacity = more / sizeof(struct region);
	return true;
}

static void remove_at_locked(size_t i)
{
	regions[i] = regions[purgeable_regions - 1];
	__atomic_store_n(&purgeable_regions, purgeable_regions - 1, __ATOMIC_RELAXED);
}

static bool append_locked(struct region r)
{
	if (purgeable_regions == capacity && !grow_locked())
		return false;
	regions[purgeable_regions] = r;
	__atomic_store_n(&purgeable_regions, purgeable_regions + 1, __ATOMIC_RELAXED);
	return true;
}

// Takes [start, end) out of the regions, keeping what's left of a region on either side of it
static void forget_locked(uintptr_t start, uintptr_t end)
{
	for (size_t i = 0; i < purgeable_regions;) {
		struct region r = regions[i];

		if (r.end <= start || r.start >= end) {
			i++;
			continue;
		}
		remove_at_locked(i);
		if (r.start < start) {
			struct region left = r;
			left.end = start;
			append_locked(left);
		}
		if (r.end > end) {
			struct region right = r;
			right.start = end;
			append_locked(right);
		}
	}
}

void purgeable_add(uintptr_t start, size_t size)
{
	uintptr_t end = (start + size + PAGE_MASK_4K) & ~PAGE_MASK_4K;
	unsigned long long mask = sigsafe_lock(&purgeable_lock);

	forget_locked(start, end);
	append_locked((struct region) { .start = start, .end = end, .state = VM_PURGABLE_NONVOLATILE });
	sigsafe_unlock(&purgeable_lock, mask);
}

void purgeable_forget_slow(uintptr_t start, size_t size)
{
	uintptr_t end = (start + size + PAGE_MASK_4K) & ~PAGE_MASK_4K;
	unsigned long long mask = sigsafe_lock(&purgeable_lock);

	forget_locked(start & ~PAGE_MASK_4K, end);
	sigsafe_unlock(&purgeable_lock, mask);
}

// vm_object_purge(): the pages go, and read as zeros again
static void purge_locked(struct region* r)
{
	LINUX_SYSCALL3(__NR_madvise, r->start, r->end - r->start, LINUX_MADV_DONTNEED);
	r->state = VM_PURGABLE_EMPTY;
}

// vm_object_purgable_control() for a user's VM_PURGABLE_SET_STATE: the new state, with the old one returned
static void set_state_locked(struct region* r, int* state)
{
	int old_state = r->state, new_state = *state & VM_PURGABLE_STATE_MASK;

	if (*state & VM_PURGABLE_DEBUG_EMPTY)
		r->volatile_empty = true;
	if (new_state == VM_PURGABLE_VOLATILE && (old_state == VM_PURGABLE_EMPTY || r->volatile_empty))
		new_state = VM_PURGABLE_EMPTY;

	if (new_state == VM_PURGABLE_EMPTY)
		purge_locked(r);
	else
		r->state = new_state;
	*state = old_state;
}

// Whether the page at `address` is mapped: msync() fails with ENOMEM where nothing is (MS_ASYNC does nothing else)
static bool mapped(uintptr_t address)
{
	return LINUX_SYSCALL3(__NR_msync, address, 4096, LINUX_MS_ASYNC) == 0;
}

// mach_vm_purgable_control() and vm_map_purgable_control()
kern_return_t _kernelrpc_mach_vm_purgable_control_trap_impl(mach_port_name_t target, mach_vm_offset_t address,
		vm_purgable_t control, int* state)
{
	kern_return_t kr;

	// another task's memory isn't this process's to look at, as for the other VM traps here
	if (target != 0 && target != mach_task_self())
		return KERN_FAILURE;

	if (control == VM_PURGABLE_SET_STATE_FROM_KERNEL)
		return KERN_INVALID_ARGUMENT;
	if (control != VM_PURGABLE_SET_STATE && control != VM_PURGABLE_GET_STATE && control != VM_PURGABLE_PURGE_ALL)
		return KERN_INVALID_ARGUMENT;
	if (state == NULL)
		return KERN_INVALID_ADDRESS;

	unsigned long long mask = sigsafe_lock(&purgeable_lock);

	if (control == VM_PURGABLE_PURGE_ALL) {
		// all volatile objects: this process's, the only ones it has
		for (size_t i = 0; i < purgeable_regions; i++)
			if (regions[i].state == VM_PURGABLE_VOLATILE)
				purge_locked(&regions[i]);
		kr = KERN_SUCCESS;
		goto out;
	}

	if (control == VM_PURGABLE_SET_STATE
		&& ((*state & ~VM_PURGABLE_ALL_MASKS) != 0 || (*state & VM_PURGABLE_STATE_MASK) == VM_PURGABLE_DENY)) {
		kr = KERN_INVALID_ARGUMENT;
		goto out;
	}

	uintptr_t page = (uintptr_t) address & ~PAGE_MASK_4K;
	struct region* r = NULL;
	for (size_t i = 0; i < purgeable_regions && r == NULL; i++)
		if (page >= regions[i].start && page < regions[i].end)
			r = &regions[i];

	if (r == NULL) {
		// an address with no mapping, or memory that isn't purgeable
		kr = mapped(page) ? KERN_INVALID_ARGUMENT : KERN_INVALID_ADDRESS;
		goto out;
	}

	if (control == VM_PURGABLE_GET_STATE)
		*state = r->state;
	else
		set_state_locked(r, state);
	kr = KERN_SUCCESS;

out:
	sigsafe_unlock(&purgeable_lock, mask);
	return kr;
}
