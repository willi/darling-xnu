#ifndef LINUX_FORK_H
#define LINUX_FORK_H

#include <libsimple/lock.h>

long sys_fork(void);

// Held while a spawn has lent its own task the special ports its child is to inherit (see posix_spawn.c), so that no
// other fork inherits them. Each fork takes it; a spawn holding it forks with sys_fork_special_ports_locked().
extern libsimple_lock_t fork_special_ports_lock;
long sys_fork_special_ports_locked(void);

#endif // LINUX_FORK_H
