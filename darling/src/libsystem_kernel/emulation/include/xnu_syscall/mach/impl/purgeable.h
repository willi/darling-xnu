#ifndef _DARLING_EMULATION_PURGEABLE_H_
#define _DARLING_EMULATION_PURGEABLE_H_

#include <stddef.h>
#include <stdint.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/vm_types.h>
#include <mach/vm_purgable.h>

// Purgeable memory as XNU has it: memory allocated with VM_FLAGS_PURGABLE, whose state (non-volatile, volatile or
// empty) mach_vm_purgable_control() gets and sets. The memory itself is ordinary anonymous memory; only an explicit
// purge (VM_PURGABLE_EMPTY, VM_PURGABLE_PURGE_ALL) empties it. XNU may purge volatile memory under memory pressure, and
// may as well not: volatile memory found intact is what a caller must already handle.

extern volatile int purgeable_regions;

// A purgeable allocation of [start, start + size)
void purgeable_add(uintptr_t start, size_t size);
// The range [start, start + size) was unmapped or replaced
void purgeable_forget_slow(uintptr_t start, size_t size);

static inline void purgeable_forget(uintptr_t start, size_t size)
{
	if (__atomic_load_n(&purgeable_regions, __ATOMIC_RELAXED) != 0)
		purgeable_forget_slow(start, size);
}

// In a fork child: nobody holds the table's lock
void purgeable_atfork_child(void);

kern_return_t _kernelrpc_mach_vm_purgable_control_trap_impl(mach_port_name_t target, mach_vm_offset_t address,
		vm_purgable_t control, int* state);

#endif // _DARLING_EMULATION_PURGEABLE_H_
