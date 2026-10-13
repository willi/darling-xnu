/*
 * Darling has no Skywalk nexus, so no channel can be opened: os_channel_create_extended() fails with ENOTSUP, which
 * callers (CoreUtils, CoreBluetooth, Sharing in newer runtimes) handle as on a system without the nexus they want.
 * Channel attributes are a plain value store, so callers that prepare attributes before opening keep working.
 * The ring and slot calls only apply to an open channel; they report that nothing is available.
 */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct darling_channel *channel_t;
typedef struct darling_channel_ring *channel_ring_t;
typedef struct darling_channel_slot *channel_slot_t;
typedef uint32_t ring_id_t;
typedef uint32_t nexus_port_t;
typedef int channel_attr_type_t;     /* enum in XNU */
typedef int ring_dir_t;              /* enum in XNU */
typedef int ring_id_type_t;          /* enum in XNU */
typedef int sync_mode_t;             /* enum in XNU */
typedef unsigned char uuid_t[16];
typedef struct slot_prop slot_prop_t;

#define DARLING_CHANNEL_ATTR_COUNT 64

typedef struct darling_channel_attr {
	uint64_t values[DARLING_CHANNEL_ATTR_COUNT];
} *channel_attr_t;

channel_attr_t
os_channel_attr_create(void)
{
	channel_attr_t attr = malloc(sizeof(*attr));
	if (attr != NULL) {
		for (int i = 0; i < DARLING_CHANNEL_ATTR_COUNT; i++) {
			attr->values[i] = 0;
		}
	}
	return attr;
}

void
os_channel_attr_destroy(const channel_attr_t attr)
{
	free(attr);
}

int
os_channel_attr_set(const channel_attr_t attr, const channel_attr_type_t type, const uint64_t value)
{
	if (attr == NULL || type < 0 || type >= DARLING_CHANNEL_ATTR_COUNT) {
		return EINVAL;
	}
	attr->values[type] = value;
	return 0;
}

int
os_channel_attr_get(const channel_attr_t attr, const channel_attr_type_t type, uint64_t *value)
{
	if (attr == NULL || value == NULL || type < 0 || type >= DARLING_CHANNEL_ATTR_COUNT) {
		return EINVAL;
	}
	*value = attr->values[type];
	return 0;
}

channel_t
os_channel_create_extended(const uuid_t uuid, const nexus_port_t port, const ring_dir_t dir, const ring_id_t rid,
    const channel_attr_t attr)
{
	errno = ENOTSUP;
	return NULL;
}

int
os_channel_get_fd(const channel_t channel)
{
	return -1;
}

int
os_channel_read_attr(const channel_t channel, channel_attr_t attr)
{
	return ENOTSUP;
}

ring_id_t
os_channel_ring_id(const channel_t channel, const ring_id_type_t type)
{
	return (ring_id_t)-1;
}

channel_ring_t
os_channel_tx_ring(const channel_t channel, const ring_id_t rid)
{
	return NULL;
}

channel_ring_t
os_channel_rx_ring(const channel_t channel, const ring_id_t rid)
{
	return NULL;
}

channel_slot_t
os_channel_get_next_slot(const channel_ring_t ring, const channel_slot_t slot, slot_prop_t *prop)
{
	return NULL;
}

int
os_channel_advance_slot(channel_ring_t ring, const channel_slot_t slot)
{
	return ENOTSUP;
}

void
os_channel_set_slot_properties(const channel_ring_t ring, const channel_slot_t slot, const slot_prop_t *prop)
{
}

int
os_channel_sync(const channel_t channel, const sync_mode_t mode)
{
	// a syscall wrapper in XNU: -1 with errno
	errno = ENOTSUP;
	return -1;
}
