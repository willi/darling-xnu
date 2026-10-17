#ifndef _DARLING_EMULATION_PURGEABLE_H_
#define _DARLING_EMULATION_PURGEABLE_H_

#include <stdbool.h>
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

// A purgeable allocation of [start, start + size), made by the vm_map trap
void purgeable_add(uintptr_t start, size_t size);

// Around a system call that unmaps [start, start + size), or maps over it (MAP_FIXED): what was purgeable there is
// forgotten. Between the two, the table is locked when it has anything there, so that no purgeable allocation can take
// the range's address before it's forgotten. done: whether the call did unmap the range.
bool purgeable_unmap_begin(uintptr_t start, size_t size, unsigned long long* mask);
void purgeable_unmap_end(bool locked, unsigned long long mask, bool done, uintptr_t start, size_t size);

// In a fork child, before anything can unmap memory: the child's copy of purgeable memory isn't purgeable (XNU's
// vm_map_fork() copies it into ordinary objects), so the child starts with no purgeable memory.
void purgeable_atfork_child(void);

kern_return_t _kernelrpc_mach_vm_purgable_control_trap_impl(mach_port_name_t target, mach_vm_offset_t address,
		vm_purgable_t control, int* state);

#endif // _DARLING_EMULATION_PURGEABLE_H_
