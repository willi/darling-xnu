#ifndef _DARLING_EMULATION_EXEC_SIGNALS_H_
#define _DARLING_EMULATION_EXEC_SIGNALS_H_

#include <stdbool.h>

#include <darling/emulation/conversion/signal/sigaction.h>

// What a new image's signals start with, as XNU gives them, in one place. XNU's exec resets a caught signal to its
// default and keeps an ignored one ignored (execsigs(), bsd/kern/kern_sig.c); posix_spawn()'s POSIX_SPAWN_SETSIGDEF
// gives its signals their default, ignored or not, once the new image is active (kern_exec.c). Darling's
// sigexc_handler is the Linux handler of nearly every signal, so Linux's exec would reset an ignored one too; Linux's
// own SIG_IGN is what carries "ignored" across the exec, into mldr, dyld and libsystem_kernel, or a Linux program.
//
// Signal numbers are Linux's throughout; sig_handlers[] is indexed by them. A set is a linux_sigset_t: signal n is
// bit n - 1.

// A signal whose disposition is Linux's own: KILL and STOP can't be caught; sys_sigaction() hands CHLD, TTIN and
// TTOU to Linux, as the kernel itself acts on their disposition (auto-reaping; a background tty call proceeds only
// if TTIN or TTOU is ignored). sigexc_handler is never installed over an ignored one.
bool sig_linux_owned(int sig);

// A signal whose default action is to be ignored, on XNU as on Linux: WINCH and URG. sig_handlers[] starts them at
// SIG_IGN, so "ignored" and "default" can't be told apart there; either way Linux's default does the same.
bool sig_default_ignore_conflated(int sig);

// For a forked posix_spawn() child, before any of its setup runs: each caught signal, and each in `sigdefault`, gets
// its default action. An ignored one stays ignored. The child's handler table is its own: sys_fork() never shares
// memory with its parent (no CLONE_VM, vfork included), so this can't reach the caller's.
void exec_signals_reset_caught(linux_sigset_t sigdefault);

// The Linux dispositions exec_signals_prepare() changed, to be put back if the exec fails.
struct exec_signals_saved {
	unsigned int changed;	// bit n: signal n
	struct linux_sigaction old[32];
};

// Right before Linux's execve: each signal the app ignores gets Linux's SIG_IGN, so the exec keeps it, unless it's
// in `sigdefault`, which Linux then resets (posix_spawn()'s SETSIGDEF with POSIX_SPAWN_SETEXEC: applied here, not
// before, as XNU applies it only to the activated image). The app's own handler table is left alone, so a failed exec
// changes nothing once exec_signals_failed() has run.
void exec_signals_prepare(struct exec_signals_saved* saved, linux_sigset_t sigdefault);

// The exec failed: Linux's dispositions are back as exec_signals_prepare() found them.
void exec_signals_failed(const struct exec_signals_saved* saved);

// In a new image, before its handlers are installed (darling_sigexc_self()): a signal Linux has ignored was ignored
// by the app before the exec, and is recorded so. Answers whether its handler must not be installed: dyld leaves an
// ignored signal ignored for libsystem_kernel, which has its own sig_handlers, to find; a signal sig_linux_owned()
// keeps Linux's SIG_IGN in any image.
bool exec_signals_import(int sig);

#endif // _DARLING_EMULATION_EXEC_SIGNALS_H_
