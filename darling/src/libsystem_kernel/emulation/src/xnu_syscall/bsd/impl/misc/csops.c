#include <darling/emulation/xnu_syscall/bsd/impl/misc/csops.h>

#include <stdint.h>
#include <mach-o/loader.h>
#include <sys/codesign.h>
#include <sys/errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/executable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/sha256.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/proc_info.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getpid.h>

#ifndef CS_OPS_DER_ENTITLEMENTS_BLOB
#define CS_OPS_DER_ENTITLEMENTS_BLOB 16
#endif
#ifndef CSSLOT_DER_ENTITLEMENTS
#define CSSLOT_DER_ENTITLEMENTS 7
#endif
#ifndef CSMAGIC_EMBEDDED_DER_ENTITLEMENTS
#define CSMAGIC_EMBEDDED_DER_ENTITLEMENTS 0xfade7172
#endif

// Finds the blob in the given slot of an executable's embedded code signature: its offset in the file and its length,
// or a length of 0 when the executable has no such blob. A blob without the given magic is an error. Returns a negative
// Linux errno on failure.
static long find_signature_blob(int fd, uint32_t slot, uint32_t magic, uint64_t* out_offset, uint32_t* out_length)
{
	struct linkedit_data_command lc;
	uint32_t superblob[3], index[2], blob[2];
	uint64_t base, signature;
	uint32_t i, count, length;
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
	// the superblob, with all its index entries, must lie within the signature
	length = __builtin_bswap32(superblob[1]);
	count = __builtin_bswap32(superblob[2]);
	if (length < sizeof(superblob) || length > lc.datasize || count > (length - sizeof(superblob)) / sizeof(index))
		return -LINUX_ENOEXEC;
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
		if (*out_length < sizeof(blob) || (uint64_t) __builtin_bswap32(index[1]) + *out_length > lc.datasize)
			return -LINUX_ENOEXEC;
		if (__builtin_bswap32(blob[0]) != magic)
			return -LINUX_ENOEXEC;
		return 0;
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
	ret = find_signature_blob(fd, slot, slot == CSSLOT_ENTITLEMENTS ? CSMAGIC_EMBEDDED_ENTITLEMENTS : CSMAGIC_EMBEDDED_DER_ENTITLEMENTS,
		&offset, &length);
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

// What a process's code signature says about it, as XNU records it at exec. Darling verifies no signature: a signed
// executable counts as valid, and an Apple-signed one (a CMS signature and a com.apple. identifier) as a platform binary,
// which is what AMFI makes of the simulator runtime's binaries on a Mac.
struct code_signature
{
	uint32_t flags; // CS_* status flags
	char identity[256];
	char team_id[64];
};

// Copies the NUL-terminated string at `offset` within the CodeDirectory at `cd` (of `cd_length` bytes) into `out`, or an
// empty string when it does not fit.
static long read_cd_string(int fd, uint64_t cd, uint32_t cd_length, uint32_t offset, char* out, size_t size)
{
	size_t len;
	long ret;

	out[0] = '\0';
	if (offset == 0 || offset >= cd_length)
		return 0;
	len = cd_length - offset < size ? cd_length - offset : size;
	// a string shorter than the buffer may end less than `size` bytes before the CodeDirectory does
	if ((ret = executable_read(fd, out, len, cd + offset)) < 0)
		return ret;
	if (strnlen(out, len) == len)
		out[0] = '\0';
	return 0;
}

static long read_code_signature(int pid, struct code_signature* sig)
{
	struct {
		uint32_t magic, length, version, flags, hashOffset, identOffset, nSpecialSlots, nCodeSlots, codeLimit;
		uint8_t hashSize, hashType, platform, pageSize;
		uint32_t spare2, scatterOffset, teamOffset;
	} cd;
	uint64_t cd_offset, cms_offset;
	uint32_t cd_length, cms_length, version;
	long ret;
	int fd;

	memset(sig, 0, sizeof(*sig));
	fd = executable_open(pid);
	if (fd < 0)
		return fd;

	ret = find_signature_blob(fd, CSSLOT_CODEDIRECTORY, CSMAGIC_CODEDIRECTORY, &cd_offset, &cd_length);
	if (ret < 0 || cd_length == 0)
		goto out;
	if (cd_length < offsetof(typeof(cd), scatterOffset))
	{
		ret = -LINUX_ENOEXEC;
		goto out;
	}
	memset(&cd, 0, sizeof(cd));
	if ((ret = executable_read(fd, &cd, cd_length < sizeof(cd) ? cd_length : sizeof(cd), cd_offset)) < 0)
		goto out;
	version = __builtin_bswap32(cd.version);

	// as XNU at exec: the CodeDirectory's flags (CS_RUNTIME, CS_RESTRICT, ...) become the process's, even though
	// nothing here enforces them
	sig->flags = CS_SIGNED | CS_VALID | (__builtin_bswap32(cd.flags) & CS_ALLOWED_MACHO);
	if ((ret = read_cd_string(fd, cd_offset, cd_length, __builtin_bswap32(cd.identOffset), sig->identity, sizeof(sig->identity))) < 0)
		goto out;
	if (version >= CS_SUPPORTSTEAMID && cd_length >= sizeof(cd))
	{
		ret = read_cd_string(fd, cd_offset, cd_length, __builtin_bswap32(cd.teamOffset), sig->team_id, sizeof(sig->team_id));
		if (ret < 0)
			goto out;
	}

	ret = find_signature_blob(fd, CSSLOT_SIGNATURESLOT, CSMAGIC_BLOBWRAPPER, &cms_offset, &cms_length);
	if (ret < 0)
		goto out;
	// an ad-hoc signature has an empty CMS blob: just its header
	if (cms_length > 8 && strncmp(sig->identity, "com.apple.", 10) == 0)
		sig->flags |= CS_PLATFORM_BINARY;

out:
	LINUX_SYSCALL1(__NR_close, fd);
	return ret;
}

// The calling process's own signature and CDHash are worked out once (CS_OPS_STATUS is frequent): its executable
// can't change without an exec, which starts over with fresh memory, and a forked child runs the same one. The first
// thread to get here fills the cache; any other meanwhile works its answer out itself.
enum { CACHE_EMPTY, CACHE_FILLING, CACHE_FULL };
static int self_sig_state;
static struct code_signature self_sig;
static long self_sig_ret;

static long code_signature_of(int pid, struct code_signature* sig)
{
	int expected = CACHE_EMPTY;
	long ret;

	if (pid != sys_getpid())
		return read_code_signature(pid, sig);
	if (__atomic_load_n(&self_sig_state, __ATOMIC_ACQUIRE) == CACHE_FULL)
	{
		*sig = self_sig;
		return self_sig_ret;
	}
	ret = read_code_signature(pid, sig);
	if (__atomic_compare_exchange_n(&self_sig_state, &expected, CACHE_FILLING, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
	{
		self_sig = *sig;
		self_sig_ret = ret;
		__atomic_store_n(&self_sig_state, CACHE_FULL, __ATOMIC_RELEASE);
	}
	return ret;
}

// Copies out the process's signing identifier or team identifier as XNU does: behind an 8-byte blob header that holds
// the total length, with only the header (and ERANGE) when the buffer is too small, and ENOENT when there is none.
static long copy_identity(int pid, unsigned int ops, void* useraddr, size_t usersize)
{
	struct code_signature sig;
	const char* identity;
	size_t length;
	long ret;

	if (usersize < 8)
		return -ERANGE;
	if ((ret = code_signature_of(pid, &sig)) < 0)
		return errno_linux_to_bsd(ret);
	if ((sig.flags & CS_VALID) == 0)
		return -EINVAL;
	identity = ops == CS_OPS_TEAMID ? sig.team_id : sig.identity;
	if (identity[0] == '\0')
		return -ENOENT;

	length = strlen(identity) + 1;
	memset(useraddr, 0, 8);
	((uint32_t*) useraddr)[1] = __builtin_bswap32(length + 8);
	if (usersize < length + 8)
		return -ERANGE;
	memcpy((char*) useraddr + 8, identity, length);
	return 0;
}

// Copies out the process's CDHash as XNU does: the first 20 bytes of the hash of its CodeDirectory, the one with the
// strongest hash type when it has alternates. Only SHA-256 CodeDirectories are supported.
static int self_cdhash_state;
static uint8_t self_cdhash[CS_CDHASH_LEN];

static long copy_cdhash(int pid, void* useraddr, size_t usersize)
{
	int expected = CACHE_EMPTY;
	uint8_t buf[4096], digest[SHA256_BLOCK_SIZE], hash_type;
	uint64_t offset = 0, candidate;
	uint32_t length = 0, candidate_length, slot, done, chunk;
	SHA256_CTX ctx;
	long ret = 0;
	int fd;

	if (usersize < CS_CDHASH_LEN)
		return -ERANGE;
	// the calling process's is worked out once (see code_signature_of())
	if (pid == sys_getpid() && __atomic_load_n(&self_cdhash_state, __ATOMIC_ACQUIRE) == CACHE_FULL)
	{
		memcpy(useraddr, self_cdhash, CS_CDHASH_LEN);
		return 0;
	}

	fd = executable_open(pid);
	if (fd < 0)
		return errno_linux_to_bsd(fd);

	// the primary CodeDirectory, then the alternates: XNU picks the strongest, and SHA-256 is the strongest codesign emits
	for (slot = CSSLOT_CODEDIRECTORY; slot < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT && length == 0;
		slot = slot == CSSLOT_CODEDIRECTORY ? CSSLOT_ALTERNATE_CODEDIRECTORIES : slot + 1)
	{
		ret = find_signature_blob(fd, slot, CSMAGIC_CODEDIRECTORY, &candidate, &candidate_length);
		if (ret < 0)
			goto out;
		if (candidate_length < offsetof(CS_CodeDirectory, pageSize) + 1)
			continue;
		if ((ret = executable_read(fd, &hash_type, 1, candidate + offsetof(CS_CodeDirectory, hashType))) < 0)
			goto out;
		if (hash_type == CS_HASHTYPE_SHA256)
		{
			offset = candidate;
			length = candidate_length;
		}
	}
	if (length == 0)
	{
		ret = -LINUX_EINVAL;
		goto out;
	}

	sha256_init(&ctx);
	for (done = 0; done < length; done += chunk)
	{
		chunk = length - done < sizeof(buf) ? length - done : sizeof(buf);
		if ((ret = executable_read(fd, buf, chunk, offset + done)) < 0)
			goto out;
		sha256_update(&ctx, buf, chunk);
	}
	sha256_final(&ctx, digest);
	memcpy(useraddr, digest, CS_CDHASH_LEN);
	if (pid == sys_getpid() &&
		__atomic_compare_exchange_n(&self_cdhash_state, &expected, CACHE_FILLING, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
	{
		memcpy(self_cdhash, digest, CS_CDHASH_LEN);
		__atomic_store_n(&self_cdhash_state, CACHE_FULL, __ATOMIC_RELEASE);
	}

out:
	LINUX_SYSCALL1(__NR_close, fd);
	return ret < 0 ? errno_linux_to_bsd(ret) : 0;
}

// TODO: actually implement the rest
// Only the status, CDHash, identities and entitlements are real: the other operations return no actual data.
long sys_csops(int pid, unsigned int ops, void* useraddr, size_t usersize) {
	int ret = 0;

	if (pid == 0)
		pid = sys_getpid();

	switch (ops) {
		case CS_OPS_STATUS: {
			struct code_signature sig;
			if (usersize < sizeof(uint32_t)) {
				ret = -EINVAL;
				break;
			}
			// an unsigned or unreadable executable stays CS_VALID as Darling always had it: nothing here enforces signatures
			if (code_signature_of(pid, &sig) < 0 || sig.flags == 0)
				sig.flags = CS_VALID;
			*(uint32_t*)useraddr = sig.flags;
			ret = 0;
		} break;

		case CS_OPS_CDHASH: {
			ret = copy_cdhash(pid, useraddr, usersize);
		} break;

		case CS_OPS_IDENTITY:
		case CS_OPS_TEAMID: {
			ret = copy_identity(pid, ops, useraddr, usersize);
		} break;

		case CS_OPS_ENTITLEMENTS_BLOB: {
			ret = copy_entitlements(pid, CSSLOT_ENTITLEMENTS, useraddr, usersize);
		} break;

		case CS_OPS_DER_ENTITLEMENTS_BLOB: {
			ret = copy_entitlements(pid, CSSLOT_DER_ENTITLEMENTS, useraddr, usersize);
		} break;

		case CS_OPS_BLOB: {
			memset(useraddr, 0, usersize);
		} break;

		// all other operations are completely unsupported
		default: {
			ret = -ENOSYS;
		} break;
	}

	return ret;
}

long sys_csops_audittoken(int pid, unsigned int ops, void* useraddr, size_t usersize, audit_token_t* audit_token) {
	long err;

	if (audit_token == NULL)
		return -EINVAL;

	// as XNU checks: the token must be for the process the pid names now, not one that died and left its pid to another
	if (audit_token->val[5] != (unsigned int) pid)
		return -ESRCH;
	if ((err = proc_identity_check(pid, PIF_COMPARE_IDVERSION, audit_token->val[7])) < 0)
		return err;

	return sys_csops(pid, ops, useraddr, usersize);
}
