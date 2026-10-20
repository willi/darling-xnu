#ifndef _SYSCTL_PROC_H
#define _SYSCTL_PROC_H

#include <stdbool.h>
#include <stdint.h>

// Utility functions for parsing Linux procfs /proc/XX/stat
bool read_string(const char* path, char* dst, int maxlen);
const char* next_stat_elem(char** buf);
void skip_stat_elems(char** buf, int count);
// The parent pid in /proc/<pid>/stat, a zombie's too: Linux's real parent, not a tracer. -ESRCH once the pid is gone.
long proc_stat_ppid(int32_t pid);

#endif // _SYSCTL_PROC_H
