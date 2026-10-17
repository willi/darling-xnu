#ifndef LINUX_ACCESS_EXTENDED_H
#define LINUX_ACCESS_EXTENDED_H

#include <stddef.h>

long sys_access_extended(const void* entries, size_t size, int* results, unsigned int uid);

#endif // LINUX_ACCESS_EXTENDED_H
