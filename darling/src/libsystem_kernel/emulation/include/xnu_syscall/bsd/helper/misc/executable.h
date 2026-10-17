#ifndef _DARLING_EMULATION_EXECUTABLE_H_
#define _DARLING_EMULATION_EXECUTABLE_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/param.h>

// A process's executable, read from the file at the path darlingserver recorded at exec: a file replaced since then is
// read instead (XNU keeps the vnode). These return a negative Linux errno on failure.

// Opens the process's executable (read-only and close-on-exec).
int executable_open(int pid);

// Reads exactly `len` bytes at `offset`: 0 on success.
long executable_read(int fd, void* buf, size_t len, uint64_t offset);

// Reads the first `size` bytes of the first load command `cmd` of the executable's x86_64 Mach-O (its x86_64 slice, in a
// universal file) into `out`, and the Mach-O's offset in the file into `out_base`. 1 if found, 0 if not; a command
// shorter than `size` is an error.
long executable_find_load_command(int fd, uint32_t cmd, void* out, size_t size, uint64_t* out_base);

// The names XNU's exec gives a process (set_proc_name(), xnu-12377.121.6 bsd/kern/kern_exec.c): its executable's last
// component, up to 2 * MAXCOMLEN characters in p_name and MAXCOMLEN in p_comm. The executable is the file darlingserver
// recorded at exec (vchroot's resolution of the path, so a symbolic link's target; a #! script's interpreter), which a
// fork keeps until it execs.
struct proc_names
{
	char p_name[2 * MAXCOMLEN + 1];
	char p_comm[MAXCOMLEN + 1];
};

// Fills `names` for pid: from its executable, or from `linux_comm` (Linux's comm, from /proc/<pid>/stat) for a process
// darlingserver has no executable for (ESRCH: one that exec'd a Linux program, or one that has exited). 0, or a negative
// Linux errno when darlingserver can't answer (EIO, ENAMETOOLONG), with Linux's comm in `names` all the same.
long executable_proc_names(int pid, const char* linux_comm, struct proc_names* names);

#endif // _DARLING_EMULATION_EXECUTABLE_H_
