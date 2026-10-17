#ifndef _VCHROOT_EXPAND_H
#define _VCHROOT_EXPAND_H

#define VCHROOT_FOLLOW	1
// the size of a path vchroot_expand() and vchroot_unexpand() work on
#define VCHROOT_PATH_MAX 4096
struct vchroot_expand_args
{
	char path[VCHROOT_PATH_MAX]; // contains evaluated path on return
	unsigned int flags;
	int dfd; // base directory when path is relative
};

struct vchroot_fdpath_args
{
	int fd;
	char* path;
	unsigned int maxlen;
};

struct vchroot_unexpand_args
{
	char path[VCHROOT_PATH_MAX];
};

int vchroot_expand(struct vchroot_expand_args* args);
int vchroot_unexpand(struct vchroot_unexpand_args* args);
int vchroot_fdpath(struct vchroot_fdpath_args* args);
// whether an expanded (Linux) path is the vchroot's root, the "/" the process sees
int vchroot_is_root(const char* linux_path);

#endif // _VCHROOT_EXPAND_H
