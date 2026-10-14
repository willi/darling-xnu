#include <darling/emulation/xnu_syscall/bsd/helper/misc/executable.h>

#include <mach/machine.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darlingserver/rpc.h>

int executable_open(int pid)
{
	char path[4096];
	uint64_t full_length;
	int ret;

	ret = dserver_rpc_get_executable_path(pid, path, sizeof(path), &full_length);
	if (ret < 0)
		return -LINUX_EIO;
	if (ret > 0)
		return -ret;
	if (full_length >= sizeof(path))
		return -LINUX_ENAMETOOLONG;

	return LINUX_SYSCALL(__NR_open, path, LINUX_O_RDONLY | LINUX_O_CLOEXEC, 0);
}

long executable_read(int fd, void* buf, size_t len, uint64_t offset)
{
	long ret = LINUX_SYSCALL(__NR_pread64, fd, buf, len, LL_ARG(offset));
	if (ret < 0)
		return ret;
	return ret == len ? 0 : -LINUX_ENOEXEC;
}

long executable_find_load_command(int fd, uint32_t cmd, void* out, size_t size, uint64_t* out_base)
{
	struct mach_header_64 header;
	struct load_command lc;
	uint64_t base = 0, offset;
	uint32_t magic, i;
	long ret;

	if ((ret = executable_read(fd, &magic, sizeof(magic), 0)) < 0)
		return ret;
	if (magic == FAT_CIGAM || magic == FAT_CIGAM_64)
	{
		// the fat header and architectures are big-endian
		struct fat_header fat;
		struct fat_arch_64 arch;
		size_t arch_size = (magic == FAT_CIGAM_64) ? sizeof(struct fat_arch_64) : sizeof(struct fat_arch);

		if ((ret = executable_read(fd, &fat, sizeof(fat), 0)) < 0)
			return ret;
		for (i = 0; i < __builtin_bswap32(fat.nfat_arch); i++)
		{
			if ((ret = executable_read(fd, &arch, arch_size, sizeof(fat) + (uint64_t) i * arch_size)) < 0)
				return ret;
			if (__builtin_bswap32(arch.cputype) == CPU_TYPE_X86_64)
				break;
		}
		if (i == __builtin_bswap32(fat.nfat_arch))
			return 0;
		if (magic == FAT_CIGAM_64)
			base = __builtin_bswap64(arch.offset);
		else
			base = __builtin_bswap32(((struct fat_arch*) &arch)->offset);
	}

	if ((ret = executable_read(fd, &header, sizeof(header), base)) < 0)
		return ret;
	if (header.magic != MH_MAGIC_64)
		return 0;

	// the load commands must stay within sizeofcmds, as the kernel requires at exec
	offset = base + sizeof(header);
	for (i = 0; i < header.ncmds; i++, offset += lc.cmdsize)
	{
		if ((ret = executable_read(fd, &lc, sizeof(lc), offset)) < 0)
			return ret;
		if (lc.cmdsize < sizeof(lc) || offset + lc.cmdsize > base + sizeof(header) + header.sizeofcmds)
			return -LINUX_ENOEXEC;
		if (lc.cmd != cmd)
			continue;

		// a command too short for its structure is malformed
		if (lc.cmdsize < size)
			return -LINUX_ENOEXEC;
		if ((ret = executable_read(fd, out, size, offset)) < 0)
			return ret;
		*out_base = base;
		return 1;
	}
	return 0;
}
