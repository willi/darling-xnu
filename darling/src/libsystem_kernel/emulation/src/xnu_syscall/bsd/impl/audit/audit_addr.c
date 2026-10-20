#include <darling/emulation/xnu_syscall/bsd/impl/audit/audit_addr.h>

#include <stdbool.h>
#include <sys/errno.h>

#include <darling/emulation/conversion/errno.h>

#include <darlingserver/rpc.h>

#define min(a, b) ((a < b) ? a : b)

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);
extern void* memset(void* s, int c, __SIZE_TYPE__ n);

// The audit session is the process's in darlingserver, as XNU keeps it in the process's credential: it is inherited
// at fork and exec, and its audit ID and session ID are the process's audit token's (val[0], val[6]). darlingserver
// applies XNU's rules (dtape_task_audit_session_set()): only root sets one, an existing session's audit ID and
// terminal ID are immutable once set, and AU_ASSIGN_ASID gets a new session ID.

// with `in`, sets the session to it (root only); either way `out` gets the current one. Returns 0 or a negative errno.
static long audit_session(const auditinfo_addr_t* in, auditinfo_addr_t* out)
{
	uint32_t addr[4];
	int code = dserver_rpc_audit_session(in != NULL,
		in ? in->ai_auid : 0,
		in ? in->ai_mask.am_success : 0,
		in ? in->ai_mask.am_failure : 0,
		in ? (uint32_t) in->ai_termid.at_port : 0,
		in ? in->ai_termid.at_type : 0,
		in ? in->ai_termid.at_addr[0] : 0,
		in ? in->ai_termid.at_addr[1] : 0,
		in ? in->ai_termid.at_addr[2] : 0,
		in ? in->ai_termid.at_addr[3] : 0,
		in ? in->ai_asid : 0,
		in ? in->ai_flags : 0,
		&out->ai_auid,
		&out->ai_mask.am_success,
		&out->ai_mask.am_failure,
		(uint32_t*) &out->ai_termid.at_port,
		&out->ai_termid.at_type,
		&addr[0], &addr[1], &addr[2], &addr[3],
		&out->ai_asid,
		&out->ai_flags);
	memcpy(out->ai_termid.at_addr, addr, sizeof(addr));
	return code < 0 ? errno_linux_to_bsd(code) : 0;
}

long sys_getaudit_addr(struct auditinfo_addr* auditinfo_addr, int length)
{
	auditinfo_addr_t aia;
	long ret;

	memset(&aia, 0, sizeof(aia));
	ret = audit_session(NULL, &aia);
	if (ret < 0)
		return ret;
	memcpy(auditinfo_addr, &aia, min((unsigned) length, sizeof(aia)));
	return 0;
}

long sys_setaudit_addr(struct auditinfo_addr* auditinfo_addr, int length)
{
	auditinfo_addr_t aia, now;
	bool assign;
	long ret;

	memset(&aia, 0, sizeof(aia));
	memcpy(&aia, auditinfo_addr, min((unsigned) length, sizeof(aia)));
	// XNU's setaudit_addr() hands back the session when it assigned the ID
	assign = aia.ai_asid == AU_ASSIGN_ASID || aia.ai_asid == AU_DEFAUDITSID;

	memset(&now, 0, sizeof(now));
	ret = audit_session(&aia, &now);
	if (ret < 0)
		return ret;
	if (assign)
		memcpy(auditinfo_addr, &now, min((unsigned) length, sizeof(now)));
	return 0;
}

long sys_getauid(au_id_t* auid)
{
	auditinfo_addr_t aia;
	long ret;

	memset(&aia, 0, sizeof(aia));
	ret = audit_session(NULL, &aia);
	if (ret < 0)
		return ret;
	*auid = aia.ai_auid;
	return 0;
}

// XNU's setauid(): the current session with a new audit ID (and a new session ID if it had none)
long sys_setauid(au_id_t* auid)
{
	auditinfo_addr_t aia, now;
	long ret;

	memset(&aia, 0, sizeof(aia));
	ret = audit_session(NULL, &aia);
	if (ret < 0)
		return ret;
	if (aia.ai_asid == AU_DEFAUDITSID)
		aia.ai_asid = AU_ASSIGN_ASID;
	aia.ai_auid = *auid;
	memset(&now, 0, sizeof(now));
	return audit_session(&aia, &now);
}
