#include <darling/emulation/xnu_syscall/bsd/impl/misc/csops.h>

#include <stdint.h>
#include <mach-o/loader.h>
#include <sys/codesign.h>
#include <sys/errno.h>
#include <strings.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/executable.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getpid.h>

#ifndef CS_OPS_DER_ENTITLEMENTS_BLOB
#define CS_OPS_DER_ENTITLEMENTS_BLOB 16
#endif
#ifndef CSSLOT_DER_ENTITLEMENTS
#define CSSLOT_DER_ENTITLEMENTS 7
#endif

// Finds the blob in the given slot of an executable's embedded code signature: its offset in the file and its length,
// or a length of 0 when the executable has no such blob. Returns a negative Linux errno on failure.
static long find_signature_blob(int fd, uint32_t slot, uint64_t* out_offset, uint32_t* out_length)
{
	struct linkedit_data_command lc;
	uint32_t superblob[3], index[2], blob[2];
	uint64_t base, signature;
	uint32_t i, count;
	long ret;

	*out_length = 0;

	ret = executable_find_load_command(fd, LC_CODE_SIGNATURE, &lc, sizeof(lc), &base);
	if (ret <= 0)
		return ret;
	signature = base + lc.dataoff;

	// CS_SuperBlob (big-endian): magic, length, count, then count CS_BlobIndex { type, offset }
	if ((ret = executable_read(fd, superblob, sizeof(superblob), signature)) < 0)
		return ret;
	if (__builtin_bswap32(superblob[0]) != CSMAGIC_EMBEDDED_SIGNATURE)
		return 0;
	count = __builtin_bswap32(superblob[2]);
	for (i = 0; i < count; i++)
	{
		if ((ret = executable_read(fd, index, sizeof(index), signature + sizeof(superblob) + (uint64_t) i * sizeof(index))) < 0)
			return ret;
		if (__builtin_bswap32(index[0]) != slot)
			continue;

		// CS_GenericBlob: magic, length (including this header)
		*out_offset = signature + __builtin_bswap32(index[1]);
		if ((ret = executable_read(fd, blob, sizeof(blob), *out_offset)) < 0)
			return ret;
		*out_length = __builtin_bswap32(blob[1]);
		return *out_length < sizeof(blob) ? -LINUX_ENOEXEC : 0;
	}
	return 0;
}

// The process's entitlements as its executable's code signature has them, copied out as XNU's csops_copy_token() does:
// a zeroed header when there are none, and only a header with the length (and ERANGE) when the buffer is too small.
static long copy_entitlements(int pid, uint32_t slot, void* useraddr, size_t usersize)
{
	uint64_t offset;
	uint32_t length;
	long ret;
	int fd;

	if (usersize < 8)
		return -ERANGE;

	fd = executable_open(pid);
	if (fd < 0)
		return errno_linux_to_bsd(fd);
	ret = find_signature_blob(fd, slot, &offset, &length);
	if (ret == 0 && length == 0)
		memset(useraddr, 0, 8);
	else if (ret == 0 && usersize < length)
	{
		memset(useraddr, 0, 8);
		((uint32_t*) useraddr)[1] = __builtin_bswap32(length);
		ret = -LINUX_ERANGE;
	}
	else if (ret == 0)
		ret = executable_read(fd, useraddr, length, offset);
	LINUX_SYSCALL1(__NR_close, fd);

	return ret < 0 ? errno_linux_to_bsd(ret) : 0;
}

// TODO: actually implement the rest
// Only the entitlements are real: the other operations return no actual data.
long sys_csops(int pid, unsigned int ops, void* useraddr, size_t usersize) {
	int ret = 0;

	if (pid == 0)
		pid = sys_getpid();

	switch (ops) {
		case CS_OPS_STATUS: {
			*(uint32_t*)useraddr = CS_VALID;
		} break;

		case CS_OPS_ENTITLEMENTS_BLOB: {
			ret = copy_entitlements(pid, CSSLOT_ENTITLEMENTS, useraddr, usersize);
		} break;

		case CS_OPS_DER_ENTITLEMENTS_BLOB: {
			ret = copy_entitlements(pid, CSSLOT_DER_ENTITLEMENTS, useraddr, usersize);
		} break;

		case CS_OPS_BLOB:
		case CS_OPS_IDENTITY: {
			memset(useraddr, 0, usersize);
		} break;

		// all other operations are completely unsupported
		default: {
			ret = -ENOSYS;
		} break;
	}

	return ret;
}

// also more or less a stub
long sys_csops_audittoken(int pid, unsigned int ops, void* useraddr, size_t usersize, audit_token_t* audit_token) {
	// just defer to the regular csops
	return sys_csops(pid, ops, useraddr, usersize);
}
