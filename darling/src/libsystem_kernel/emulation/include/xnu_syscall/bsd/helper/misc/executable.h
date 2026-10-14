#ifndef _DARLING_EMULATION_EXECUTABLE_H_
#define _DARLING_EMULATION_EXECUTABLE_H_

#include <stddef.h>
#include <stdint.h>

// What XNU knows about a process's executable from exec'ing it, read from the file darlingserver recorded at the exec.
// These return a negative Linux errno on failure.

// Opens the process's executable (read-only and close-on-exec).
int executable_open(int pid);

// Reads exactly `len` bytes at `offset`: 0 on success.
long executable_read(int fd, void* buf, size_t len, uint64_t offset);

// Reads up to `size` bytes of the first load command `cmd` of the executable's x86_64 Mach-O (its x86_64 slice, in a
// universal file) into `out`, and the Mach-O's offset in the file into `out_base`. 1 if found, 0 if not.
long executable_find_load_command(int fd, uint32_t cmd, void* out, size_t size, uint64_t* out_base);

#endif // _DARLING_EMULATION_EXECUTABLE_H_
