#include <darling/emulation/xnu_syscall/bsd/helper/misc/executable.h>

#include <mach/machine.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darlingserver/rpc.h>

extern void* memcpy(void* dst, const void* src, size_t n);

// The path darlingserver recorded at pid's exec, into path (size bytes): 0, or a negative Linux errno (ESRCH: no such
// process, or none it knows).
static long executable_path(int pid, char* path, size_t size)
{
	uint64_t full_length;
	int ret;

	ret = dserver_rpc_get_executable_path(pid, path, size, &full_length);
	if (ret < 0)
		return -LINUX_EIO;
	if (ret > 0)
		return -ret;
	if (full_length >= size)
		return -LINUX_ENAMETOOLONG;
	return 0;
}

// set_proc_name(): the last component, truncated to each field, which ends with a NUL
static void set_names(struct proc_names* names, const char* name, size_t len)
{
	size_t n;

	n = len < sizeof(names->p_name) - 1 ? len : sizeof(names->p_name) - 1;
	memcpy(names->p_name, name, n);
	names->p_name[n] = '\0';
	n = len < sizeof(names->p_comm) - 1 ? len : sizeof(names->p_comm) - 1;
	memcpy(names->p_comm, name, n);
	names->p_comm[n] = '\0';
}

// The calling process's own names, which change only at exec, and an exec starts a fresh copy of this library. The
// pid they're for is checked against the caller's: a fork's child has another. self_state: 0 empty, 1 being filled
// (by the one thread that claimed it), 2 filled.
static struct proc_names self_names;
static int self_pid;
static int self_state;

long executable_proc_names(int pid, const char* linux_comm, struct proc_names* names)
{
	char path[4096];
	size_t len, start;
	long ret;
	int is_self = pid == LINUX_SYSCALL0(__NR_getpid);

	if (is_self && __atomic_load_n(&self_state, __ATOMIC_ACQUIRE) == 2 && self_pid == pid)
	{
		*names = self_names;
		return 0;
	}

	ret = executable_path(pid, path, sizeof(path));
	len = 0;
	if (ret == 0)
	{
		len = __simple_strlen(path);
		while (len > 1 && path[len - 1] == '/')
			len--;
	}
	start = len;
	while (start > 0 && path[start - 1] != '/')
		start--;

	if (ret == 0 && len > start)
	{
		set_names(names, path + start, len - start);
		int empty = 0;
		if (is_self && __atomic_compare_exchange_n(&self_state, &empty, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		{
			self_names = *names;
			self_pid = pid;
			__atomic_store_n(&self_state, 2, __ATOMIC_RELEASE);
		}
		return 0;
	}

	// nothing recorded (ESRCH, or an empty path: a process that hasn't told darlingserver yet)
	if (ret == 0 || ret == -LINUX_ESRCH)
	{
		set_names(names, linux_comm, __simple_strlen(linux_comm));
		return 0;
	}
	return ret;
}

int executable_open(int pid)
{
	char path[4096];
	long ret;

	if ((ret = executable_path(pid, path, sizeof(path))) < 0)
		return ret;
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
