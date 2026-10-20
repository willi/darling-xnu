#include <darling/emulation/xnu_syscall/bsd/helper/misc/host_basic_info.h>

#include <mach/mach_init.h>

extern kern_return_t mach_port_deallocate(ipc_space_t task, mach_port_name_t name);
extern kern_return_t host_info(mach_port_name_t host, int itype, void* hinfo, mach_msg_type_number_t* count);

#define QOS_PARALLELISM_COUNT_LOGICAL 0x1

enum { HINFO_NONE, HINFO_FILLING, HINFO_READY };

// Written once, by the thread that wins HINFO_NONE -> HINFO_FILLING, and read only after HINFO_READY is seen with
// acquire: no reader can see a half-written copy (a reader of a half-filled static read 0 CPUs).
static struct host_basic_info cached;
static int cached_state = HINFO_NONE;

bool host_basic_info_get(struct host_basic_info* out)
{
	if (__atomic_load_n(&cached_state, __ATOMIC_ACQUIRE) == HINFO_READY) {
		*out = cached;
		return true;
	}

	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
	mach_port_t host = mach_host_self();
	kern_return_t kr = host_info(host, HOST_BASIC_INFO, out, &count);

	mach_port_deallocate(mach_task_self(), host);
	if (kr != KERN_SUCCESS || out->logical_cpu <= 0 || out->physical_cpu <= 0) {
		*out = (struct host_basic_info) {0};
		return false;
	}

	int expected = HINFO_NONE;
	if (__atomic_compare_exchange_n(&cached_state, &expected, HINFO_FILLING, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		cached = *out;
		__atomic_store_n(&cached_state, HINFO_READY, __ATOMIC_RELEASE);
	}
	return true;
}

int qos_max_parallelism(int qos, unsigned long flags)
{
	struct host_basic_info info;

	(void) qos;
	if (!host_basic_info_get(&info))
		return 0;
	return (flags & QOS_PARALLELISM_COUNT_LOGICAL) ? info.logical_cpu : info.physical_cpu;
}
