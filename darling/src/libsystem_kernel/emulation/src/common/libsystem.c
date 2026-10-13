#include <darling/emulation/common/libsystem.h>

#include <stddef.h>
#include <_libkernel_init.h>

#include <darling/emulation/common/base.h>

// stays NULL in dyld and in processes running Apple's libSystem
_libkernel_darling_functions_t _libkernel_darling_functions;

VISIBLE
void __libkernel_darling_init(_libkernel_darling_functions_t fns)
{
	_libkernel_darling_functions = fns;
}

#ifndef VARIANT_DYLD
extern _libkernel_functions_t _libkernel_functions;

bool __libkernel_has_apple_libsystem(void)
{
	// __libkernel_init() ran, but Darling's libSystem did not register itself first
	return _libkernel_functions != NULL && _libkernel_darling_functions == NULL;
}
#endif
