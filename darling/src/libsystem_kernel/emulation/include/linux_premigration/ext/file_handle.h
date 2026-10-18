#ifndef EXT_FILE_HANDLE_H
#define EXT_FILE_HANDLE_H

#include <stdint.h>

#include <darling/emulation/common/base.h>

CPP_EXTERN_BEGIN

// Linux's, as fanotify reports one (fseventsd.m)
struct file_handle
{
	uint32_t handle_bytes;
	int handle_type;
	uint8_t f_handle[1];
};

// mount_id of a reference sys_name_to_handle() makes: id is valid
#define MOUNT_ID_FILEID (-101)

// CarbonCore's FSRef (80 bytes)
typedef struct {
	union
	{
		uint8_t opaque[80];

		struct
		{
			int mount_id;

			union
			{
				struct file_handle fh;

				// the object's volume and object ID (fileid_find()), the Linux mount it was on as a hint, and where
				// the process that made it keeps its path
				struct
				{
					uint32_t volume, mount;
					uint64_t objid;
					int index, gen;
				} __attribute__((packed)) id;
			};
		};
	};

} RefData;

int sys_name_to_handle(const char* name, RefData* ref, int follow);
int sys_open_by_handle(RefData* ref, int flags);
int sys_handle_to_name(RefData* ref, char name[4096]);

CPP_EXTERN_END

#endif // EXT_FILE_HANDLE_H
