#ifndef _DARLING_EMULATION_SIGNAL_KNOTES_H_
#define _DARLING_EMULATION_SIGNAL_KNOTES_H_

#include <darling/emulation/common/base.h>

// EVFILT_SIGNAL knotes. XNU records every attempt to deliver a signal to a process in its EVFILT_SIGNAL knotes, even
// when the signal is ignored (except an ignored SIGCHLD). A Linux signalfd only sees a signal that every thread blocks,
// which Darling's processes don't, so libkqueue registers an eventfd for each knote here instead, and Darling's signal
// handler adds 1 to the eventfds of the signal it is delivering. Unlike XNU, which counts attempts to send a signal,
// that counts deliveries: Linux merges a signal sent again while it is pending.

// Registers an eventfd for the BSD signal signum. Returns 0, or a negative Linux errno.
VISIBLE
int __darling_signal_knote_register(int signum, int eventfd);

// Unregisters an eventfd; once this returns, no signal handler writes to it any more.
VISIBLE
void __darling_signal_knote_unregister(int eventfd);

// Called by Darling's signal handlers for a BSD signal being delivered to the process. Async-signal-safe.
void signal_knotes_post(int signum);

// In a fork's child: forgets the parent's knotes (their eventfds are the parent's). Allocation-free.
void signal_knotes_atfork_child(void);

#endif // _DARLING_EMULATION_SIGNAL_KNOTES_H_
