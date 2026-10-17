#ifndef LINUX_EXECVE_H
#define LINUX_EXECVE_H

long sys_execve(const char* fname, const char** argvp, const char** envp);

// sys_execve() for posix_spawn()'s child: spawn_fd is the pipe its parent waits on. A Darling executable (mldr runs it)
// inherits it as __mldr_spawn_pipe and closes it once the image is activated, or writes its error there; anything else
// closes it at the exec (it stays close-on-exec).
long sys_execve_spawn(const char* fname, const char** argvp, const char** envp, int spawn_fd);

#endif // LINUX_EXECVE_H
