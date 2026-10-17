#include <darling/emulation/xnu_syscall/mach/impl/purgeable.h>

#include <mach/mach_init.h>
#include <libsimple/lock.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/common/sigsafe_lock.h>
#include <darling/emulation/conversion/mman/duct_mman.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define LINUX_MREMAP_MAYMOVE 1
#define PAGE_MASK_4K ((uintptr_t) 4095)

// A range of a purgeable object. XNU's object is one, whatever becomes of the map entries it backs: the ranges a
// partial unmap leaves of an allocation share its object, and its state.
struct region {
	uintptr_t start, end;
	unsigned int object;
	int state;              // VM_PURGABLE_NONVOLATILE, _VOLATILE or _EMPTY
	bool volatile_empty;    // VM_PURGABLE_DEBUG_EMPTY: made volatile, it's emptied at once
};

// The process's purgeable ranges, in memory of their own (no malloc here), unsorted: a process has few. Unlocked, only
// the count and the hull (the ranges all lie within [hull_start, hull_end)) are read, to skip the lock.
static struct region* regions;
static size_t capacity;
static int count;
static uintptr_t hull_start, hull_end;
static unsigned int next_object;
static libsimple_lock_t purgeable_lock = LIBSIMPLE_LOCK_INITIALIZER;

void purgeable_atfork_child(void)
{
	// another thread may have been growing the table: it's left to the child, unused
	regions = NULL;
	capacity = 0;
	__atomic_store_n(&count, 0, __ATOMIC_SEQ_CST);
	hull_start = hull_end = 0;
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

// Room for n more ranges; without it, the purgeable memory that doesn't fit stops being tracked (it reads as not
// purgeable), and that's said
static bool reserve_locked(size_t n)
{
	while (count + n > capacity) {
		if (!grow_locked()) {
			__simple_printf("purgeable: no memory for the table of purgeable memory\n");
			return false;
		}
	}
	return true;
}

static void append_locked(struct region r)
{
	if (!reserve_locked(1))
		return;
	regions[count] = r;
	if (count == 0 || r.start < hull_start)
		__atomic_store_n(&hull_start, r.start, __ATOMIC_SEQ_CST);
	if (count == 0 || r.end > hull_end)
		__atomic_store_n(&hull_end, r.end, __ATOMIC_SEQ_CST);
	__atomic_store_n(&count, count + 1, __ATOMIC_SEQ_CST);
}

// Takes [start, end) out of the ranges, keeping what's left of a range on either side of it
static void forget_locked(uintptr_t start, uintptr_t end)
{
	for (size_t i = 0; i < count;) {
		struct region r = regions[i];

		if (r.end <= start || r.start >= end) {
			i++;
			continue;
		}
		// one range out, and up to two in: room for the second first, so that a split can't lose its other half
		reserve_locked(1);
		regions[i] = regions[count - 1];
		__atomic_store_n(&count, count - 1, __ATOMIC_SEQ_CST);
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
	if (count == 0) {
		__atomic_store_n(&hull_start, 0, __ATOMIC_SEQ_CST);
		__atomic_store_n(&hull_end, 0, __ATOMIC_SEQ_CST);
	}
}

void purgeable_add(uintptr_t start, size_t size)
{
	uintptr_t end = (start + size + PAGE_MASK_4K) & ~PAGE_MASK_4K;
	unsigned long long mask = sigsafe_lock(&purgeable_lock);

	forget_locked(start, end);
	append_locked((struct region) { .start = start, .end = end, .object = ++next_object,
		.state = VM_PURGABLE_NONVOLATILE });
	sigsafe_unlock(&purgeable_lock, mask);
}

bool purgeable_unmap_begin(uintptr_t start, size_t size, unsigned long long* mask)
{
	uintptr_t end = start + size;

	// Unlocked: a range can't become purgeable here meanwhile, as the caller has it mapped (or, for MAP_FIXED, takes
	// the address for itself)
	if (__atomic_load_n(&count, __ATOMIC_SEQ_CST) == 0)
		return false;
	if (end <= __atomic_load_n(&hull_start, __ATOMIC_SEQ_CST) || start >= __atomic_load_n(&hull_end, __ATOMIC_SEQ_CST))
		return false;
	*mask = sigsafe_lock(&purgeable_lock);
	return true;
}

void purgeable_unmap_end(bool locked, unsigned long long mask, bool done, uintptr_t start, size_t size)
{
	if (!locked)
		return;
	if (done)
		forget_locked(start & ~PAGE_MASK_4K, (start + size + PAGE_MASK_4K) & ~PAGE_MASK_4K);
	sigsafe_unlock(&purgeable_lock, mask);
}

// vm_object_purge(): the pages go, and read as zeros again
static void purge_locked(struct region* r)
{
	LINUX_SYSCALL3(__NR_madvise, r->start, r->end - r->start, LINUX_MADV_DONTNEED);
	r->state = VM_PURGABLE_EMPTY;
}

// vm_object_purgable_control() for a user's VM_PURGABLE_SET_STATE, on the whole object r is a range of: the new state,
// with the old one in *state
static kern_return_t set_state_locked(struct region* r, int* state)
{
	int old_state = r->state, new_state = *state & VM_PURGABLE_STATE_MASK;
	bool latch = (*state & VM_PURGABLE_DEBUG_EMPTY) != 0;
	unsigned int object = r->object;

	for (size_t i = 0; i < count; i++)
		if (regions[i].object == object && latch)
			regions[i].volatile_empty = true;
	if (new_state == VM_PURGABLE_DENY)
		return KERN_INVALID_ARGUMENT;
	if (new_state == VM_PURGABLE_VOLATILE && (old_state == VM_PURGABLE_EMPTY || r->volatile_empty))
		new_state = VM_PURGABLE_EMPTY;

	for (size_t i = 0; i < count; i++) {
		if (regions[i].object != object)
			continue;
		if (new_state == VM_PURGABLE_EMPTY)
			purge_locked(&regions[i]);
		else
			regions[i].state = new_state;
	}
	*state = old_state;
	return KERN_SUCCESS;
}

// Whether the page at `address` is mapped: msync() fails with ENOMEM where nothing is (MS_ASYNC does nothing else)
static bool mapped(uintptr_t address)
{
	return LINUX_SYSCALL3(__NR_msync, address, 4096, LINUX_MS_ASYNC) == 0;
}

// The trap (_kernelrpc_mach_vm_purgable_control_trap), mach_vm_purgable_control() and vm_map_purgable_control()
kern_return_t _kernelrpc_mach_vm_purgable_control_trap_impl(mach_port_name_t target, mach_vm_offset_t address,
		vm_purgable_t control, int* state)
{
	kern_return_t kr;
	int st;

	// another task's memory isn't this process's to look at, as for the other VM traps here; and the MIG call
	// libsyscall would fall back on is a stub in darlingserver
	if (target != 0 && target != mach_task_self())
		return KERN_FAILURE;

	if (control == VM_PURGABLE_SET_STATE_FROM_KERNEL)
		return KERN_INVALID_ARGUMENT;
	if (control != VM_PURGABLE_SET_STATE && control != VM_PURGABLE_GET_STATE && control != VM_PURGABLE_PURGE_ALL)
		return KERN_INVALID_ARGUMENT;
	if (state == NULL)
		return KERN_INVALID_ADDRESS;

	// copied in for every control and out on success, as the trap does: outside the lock, which blocks every signal,
	// so a bad pointer faults as the caller's own access would
	st = *state;

	if (control == VM_PURGABLE_SET_STATE && (st & ~VM_PURGABLE_ALL_MASKS) != 0)
		return KERN_INVALID_ARGUMENT;
#if UINTPTR_MAX < UINT64_MAX
	// beyond a 32-bit process's map
	if (control != VM_PURGABLE_PURGE_ALL && address > UINTPTR_MAX)
		return KERN_INVALID_ADDRESS;
#endif

	unsigned long long mask = sigsafe_lock(&purgeable_lock);

	if (control == VM_PURGABLE_PURGE_ALL) {
		// all volatile objects: this process's, the only ones it has
		for (size_t i = 0; i < count; i++)
			if (regions[i].state == VM_PURGABLE_VOLATILE)
				purge_locked(&regions[i]);
		kr = KERN_SUCCESS;
		goto out;
	}

	uintptr_t page = (uintptr_t) address & ~PAGE_MASK_4K;
	struct region* r = NULL;
	for (size_t i = 0; i < count && r == NULL; i++)
		if (page >= regions[i].start && page < regions[i].end)
			r = &regions[i];

	if (r == NULL) {
		// an address with no mapping, or memory that isn't purgeable
		kr = mapped(page) ? KERN_INVALID_ARGUMENT : KERN_INVALID_ADDRESS;
	} else if (control == VM_PURGABLE_GET_STATE) {
		st = r->state;
		kr = KERN_SUCCESS;
	} else {
		kr = set_state_locked(r, &st);
	}

out:
	sigsafe_unlock(&purgeable_lock, mask);
	if (kr == KERN_SUCCESS)
		*state = st;
	return kr;
}
