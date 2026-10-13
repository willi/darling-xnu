#ifndef _DARLING_EMULATION_COMMON_LIBSYSTEM_H
#define _DARLING_EMULATION_COMMON_LIBSYSTEM_H

#include <stdbool.h>

// Whether this process runs Apple's own libSystem (an iOS Simulator runtime loaded through dyld_sim) rather than
// Darling's. Darling's libSystem registers itself with __libkernel_darling_init() before __libkernel_init().
#ifdef VARIANT_DYLD
static inline bool __libkernel_has_apple_libsystem(void) { return false; } // dyld runs neither
#else
bool __libkernel_has_apple_libsystem(void);
#endif

#endif // _DARLING_EMULATION_COMMON_LIBSYSTEM_H
