#ifndef DARLING_EMULATION_QOS_SCHED_H
#define DARLING_EMULATION_QOS_SCHED_H

// A thread's QoS, made visible to Linux's scheduler.
//
// XNU runs each QoS at its own base priority (osfmk/kern/sched.h: user-interactive 46, user-initiated 37,
// default 31, utility 20, background and maintenance 4), so on a busy CPU low-QoS work waits. A Darling thread is
// a Linux thread, and the nearest equivalent is its nice, relative to the process's base:
// - user-interactive, user-initiated, default, legacy and unspecified: the base;
// - utility: the base + 10;
// - background and maintenance: 19, Linux's lowest (CFS weight 15 against 1024 at nice 0).
// Never above the base, so no thread runs at a higher priority than it would without this. Not SCHED_IDLE: Darling
// can't boost a lock's owner, and a background thread holding one that main waits for mustn't be starved outright.
//
// Moving back up toward the base needs CAP_SYS_NICE, which every process in taffy's --privileged device container
// has. Without it the thread keeps the nice it has, and the process says so once on stderr.

// The calling thread now runs at `qos`, a thread_qos_t; anything else counts as unspecified.
void qos_sched_apply_self(unsigned int qos);

// The calling thread is about to enter _start_wqthread with these WQ_FLAG_THREAD_* flags.
void qos_sched_apply_wq_flags(int flags);

// Reads the process's base nice from the calling thread, the main thread, at bsdthread_register().
void qos_sched_init_base(void);

#endif // DARLING_EMULATION_QOS_SCHED_H
