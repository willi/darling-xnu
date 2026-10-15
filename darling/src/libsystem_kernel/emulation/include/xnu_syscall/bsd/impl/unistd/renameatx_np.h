#ifndef LINUX_RENAMEATX_NP_H
#define LINUX_RENAMEATX_NP_H

long sys_renameatx_np(int oldfd, const char* oldpath, int newfd, const char* newpath, unsigned int flags);

#endif // LINUX_RENAMEATX_NP_H
