#ifndef LINUX_MEMORYSTATUS_CONTROL_H
#define LINUX_MEMORYSTATUS_CONTROL_H

#include <stddef.h>
#include <stdint.h>

long sys_memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void* buffer, size_t buffersize);

#endif // LINUX_MEMORYSTATUS_CONTROL_H
