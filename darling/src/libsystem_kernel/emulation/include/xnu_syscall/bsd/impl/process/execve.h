#ifndef LINUX_EXECVE_H
#define LINUX_EXECVE_H

#include <darling/emulation/conversion/signal/duct_signals.h>

long sys_execve(const char* fname, const char** argvp, const char** envp);

// sys_execve() for posix_spawn()'s child. spawn_fd is the write end of the pipe its parent reads, which then returns
// once the new image is activated, or with the error that failed it, as XNU's posix_spawn() does
// (exec_activate_image(), xnu-12377.121.6 bsd/kern/kern_exec.c). The contract with mldr (darling's
// src/startup/mldr/mldr.c), which the other two point to:
// - for a Darling executable (a Mach-O, or a #! script: mldr runs either), the descriptor stays open across the Linux
//   exec and mldr gets its number in __mldr_spawn_pipe (-1: none; it's always set, so an inherited one never counts);
// - mldr closes it once the image is activated, before any of the image's code runs, or writes the error that failed
//   the activation, an int: a negative XNU errno; EOF without one is success (a signal that kills mldr is too);
// - anything else (a Linux program) closes it at the exec: it stays close-on-exec.
// The parent and mldr ship together: an mldr that doesn't know __mldr_spawn_pipe keeps the descriptor open, and the
// parent waits until the child exits.
// `sigdefault`: the signals the new image starts with at their default, ignored or not (POSIX_SPAWN_SETSIGDEF), a
// Linux set; Linux's dispositions are as before if the exec fails (exec_signals_prepare()).
long sys_execve_spawn(const char* fname, const char** argvp, const char** envp, int spawn_fd, linux_sigset_t sigdefault);

#endif // LINUX_EXECVE_H
