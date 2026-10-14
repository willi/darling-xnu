#ifndef _DARLING_EMULATION_SIGNAL_KNOTES_H_
#define _DARLING_EMULATION_SIGNAL_KNOTES_H_

// EVFILT_SIGNAL knotes. XNU records every attempt to deliver a signal to a process in its EVFILT_SIGNAL knotes, even
// when the signal is ignored (except an ignored SIGCHLD). A Linux signalfd only sees a signal that every thread blocks,
// which Darling's processes don't, so each of libkqueue's knotes is an eventfd from signal_knote_open() instead (see
// _signal_knote_open_4libkqueue), and Darling's signal handlers add 1 to the eventfds of each signal they deliver.
//
// Where that differs from XNU:
// - It counts deliveries, not attempts to send: Linux merges a signal sent again while it is pending.
// - SIGCHLD and SIGTTOU at their default disposition (or ignored) aren't seen: Darling installs no handler for them.
// - A signal that a debugger drops through darlingserver isn't seen, and one it changes is seen as the new signal.

// Returns an eventfd that counts deliveries of the BSD signal signum, or a negative Linux errno. Only
// signal_knote_close() closes it: Darling's close() and dup2() refuse to, and a fork's child doesn't inherit it.
int signal_knote_open(int signum);

// Closes a descriptor from signal_knote_open(), once no signal handler can write to it any more.
void signal_knote_close(int fd);

// Called by Darling's signal handlers for a BSD signal being delivered to the process. Async-signal-safe.
void signal_knotes_post(int signum);

// In a fork's child, first: forgets the parent's knotes, whose eventfds the child closes. Allocation-free.
void signal_knotes_atfork_child(void);

#endif // _DARLING_EMULATION_SIGNAL_KNOTES_H_
