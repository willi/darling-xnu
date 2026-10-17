#ifndef LINUX_GETATTRLISTBULK_H
#define LINUX_GETATTRLISTBULK_H

#include <stdint.h>

#include <darling/emulation/conversion/xattr/getattrlist.h>

long sys_getattrlistbulk(int dirfd, struct xnu_attrlist* alist, void* attributeBuffer, __SIZE_TYPE__ bufferSize,
	uint64_t options);

#endif // LINUX_GETATTRLISTBULK_H
