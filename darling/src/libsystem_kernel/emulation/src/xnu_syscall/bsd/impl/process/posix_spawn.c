#include <darling/emulation/xnu_syscall/bsd/impl/process/posix_spawn.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/spawn.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <_libkernel_init.h>
#include <mach/mach_port.h>
#include <mach/task.h>
#include <libsimple/lock.h>

#include <darling/emulation/xnu_syscall/bsd/impl/process/execve.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/write.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/exit.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/pipe.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/dup2.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getuid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getgid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/setuid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/setgid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/setpgid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigprocmask.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/common/sigsafe_lock.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigaction.h>
#include <darling/emulation/linux_premigration/signal/exec_signals.h>
#include <darling/emulation/xnu_syscall/bsd/impl/process/fork.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/chdir.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchdir.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/fcntl.h>
#include <darling/emulation/xnu_syscall/bsd/impl/dirent/getdirentries.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makefd.h>

#include <darlingserver/rpc.h>

#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

#define LINUX_ADDR_NO_RANDOMIZE 0x40000

extern int _mach_fork_child(void);

// XNU sets the special ports a spawn's port actions ask for on the new task, naming the ports in the caller's space.
// Darling can't reach into the new task like that, but a task created by fork or exec takes its inheritable special
// ports (the bootstrap port among them) from the task it comes from. So the caller sets them on itself around the
// fork or exec, and puts its own back once the child has them. fork_special_ports_lock keeps every other fork from
// inheriting them meanwhile; spawns take it after libSystem's fork handlers have run, as forks do.
// Only the bootstrap port can be lent this way: the host port can't be set from user space, a child doesn't inherit
// the others, or (the seatbelt and task access ports) a task's can't be changed once set. launchd gives its jobs
// bootstrap ports whose receive rights are immovable, which darlingserver accepts here as XNU's exec does.
// Other port action types are ignored, as before (the simulator doesn't support exception ports, for one).

struct spawn_special_port
{
	int which;
	mach_port_t saved;
};

static int spawn_count_special_ports(const struct _posix_spawn_args_desc* desc)
{
	const struct xnu__posix_spawn_port_actions* pact = desc ? desc->pactp : NULL;
	int i, n = 0;

	if (pact == NULL || desc->port_actions_size < sizeof(*pact)
			|| pact->pspa_count < 0
			|| desc->port_actions_size < sizeof(*pact) + pact->pspa_count * sizeof(pact->pspa_actions[0]))
		return 0;

	for (i = 0; i < pact->pspa_count; i++)
	{
		if (pact->pspa_actions[i].port_type == XNU_PSPA_SPECIAL)
			n++;
	}
	return n;
}

static void spawn_restore_special_ports(struct spawn_special_port* ports, int n);

static kern_return_t spawn_set_special_port(int which, mach_port_t port)
{
	int code = dserver_rpc_spawn_set_special_port(which, port);

	return (code < 0) ? KERN_FAILURE : code;
}

// Takes fork_special_ports_lock, which spawn_restore_special_ports() releases (also when this fails).
static int spawn_set_special_ports(const struct _posix_spawn_args_desc* desc, struct spawn_special_port* ports, int n)
{
	const struct xnu__posix_spawn_port_actions* pact = desc->pactp;
	int i, set = 0;
	kern_return_t kr = KERN_SUCCESS;

	libsimple_lock_lock(&fork_special_ports_lock);

	for (i = 0; i < pact->pspa_count && set < n; i++)
	{
		const struct xnu__ps_port_action* act = &pact->pspa_actions[i];
		mach_port_t saved;

		if (act->port_type != XNU_PSPA_SPECIAL)
			continue;
		if (act->which == TASK_KERNEL_PORT || act->which == TASK_HOST_PORT)
		{
			kr = KERN_NO_ACCESS;
			break;
		}
		if (act->which != TASK_BOOTSTRAP_PORT)
		{
			__simple_kprintf("posix_spawn: can't give the child special port %d\n", act->which);
			continue;
		}

		kr = task_get_special_port(mach_task_self(), act->which, &saved);
		if (kr != KERN_SUCCESS)
			break;
		kr = spawn_set_special_port(act->which, act->new_port);
		if (kr != KERN_SUCCESS)
		{
			if (saved != MACH_PORT_NULL)
				mach_port_deallocate(mach_task_self(), saved);
			break;
		}
		ports[set++] = (struct spawn_special_port) { .which = act->which, .saved = saved };
	}

	if (kr == KERN_SUCCESS)
		return 0;

	spawn_restore_special_ports(ports, set);
	return -EINVAL; // as XNU fails any special port action it can't apply
}

static void spawn_restore_special_ports(struct spawn_special_port* ports, int n)
{
	while (n-- > 0)
	{
		kern_return_t kr = spawn_set_special_port(ports[n].which, ports[n].saved);

		if (kr != KERN_SUCCESS)
			__simple_kprintf("posix_spawn: failed to restore special port %d: %d\n", ports[n].which, kr);
		if (ports[n].saved != MACH_PORT_NULL)
			mach_port_deallocate(mach_task_self(), ports[n].saved);
	}
	libsimple_lock_unlock(&fork_special_ports_lock);
}

// A PSFA_FILEPORT_DUP2 names a fileport in the caller's space, which XNU turns into a descriptor while it runs the file
// actions. A forked child here doesn't have the caller's ports, so the caller turns them into (close-on-exec) descriptors
// before forking (fileport_fds, in file action order), and the child dups each one where the action asks.

static int spawn_count_fileports(const struct _posix_spawn_args_desc* desc)
{
	int i, n = 0;

	if (desc == NULL || desc->factp == NULL)
		return 0;

	for (i = 0; i < desc->factp->psfa_act_count; i++)
	{
		if (desc->factp->psfa_act_acts[i].psfaa_type == XNU_PSFA_FILEPORT_DUP2)
			n++;
	}
	return n;
}

static void spawn_close_fileports(int* fds, int n)
{
	while (n-- > 0)
		close_internal(fds[n]);
}

static int spawn_open_fileports(const struct _posix_spawn_args_desc* desc, int* fds, int n)
{
	int i, opened = 0;

	for (i = 0; i < desc->factp->psfa_act_count && opened < n; i++)
	{
		const struct xnu__psfa_action* act = &desc->factp->psfa_act_acts[i];
		int fd;

		if (act->psfaa_type != XNU_PSFA_FILEPORT_DUP2)
			continue;

		fd = (act->psfaa_fileport == MACH_PORT_NULL) ? -EINVAL : sys_fileport_makefd(act->psfaa_fileport);
		if (fd < 0)
		{
			spawn_close_fileports(fds, opened);
			return -EINVAL; // as XNU fails a fileport that isn't one
		}
		fds[opened++] = fd;
	}
	return 0;
}

// the descriptor a file action replaces or closes
static int spawn_action_target_fd(const struct xnu__psfa_action* act)
{
	switch (act->psfaa_type)
	{
		case XNU_PSFA_CLOSE:
		case XNU_PSFA_OPEN:
			return act->psfaa_filedes;
		case XNU_PSFA_DUP2:
		case XNU_PSFA_FILEPORT_DUP2:
			return act->psfaa_dup2args.psfad_newfiledes;
		default:
			return -1;
	}
}

long sys_posix_spawn(int* pid, const char* path, const struct _posix_spawn_args_desc* desc,
		char** argvp, char** envp)
{
	int ret, my_pid;
	int pipe[2] = { -1, -1 };
	int nports = spawn_count_special_ports(desc);
	struct spawn_special_port* ports = __builtin_alloca(nports * sizeof(*ports));
	int nfileports = spawn_count_fileports(desc);
	int* fileport_fds = __builtin_alloca(nfileports * sizeof(*fileport_fds));
	int next_fileport = 0;
	// the caller's signal mask, while signals are blocked across the fork
	unsigned long long caller_mask = 0;
	// POSIX_SPAWN_SETEXEC: no fork, this process execs; else the code below the fork runs in the forked child
	const bool setexec = desc && desc->attrp && (desc->attrp->psa_flags & POSIX_SPAWN_SETEXEC);
	// POSIX_SPAWN_SETSIGDEF's signals, in Linux's numbers
	linux_sigset_t sigdefault = 0;
	// SETEXEC with SETSIGMASK: the mask to put back if the exec fails
	sigset_t setexec_old_mask;
	bool setexec_mask_set = false;

	if (desc && desc->attrp && (desc->attrp->psa_flags & POSIX_SPAWN_SETSIGDEF))
		sigset_bsd_to_linux(&desc->attrp->psa_sigdefault, &sigdefault);

	if (nfileports > 0)
	{
		ret = spawn_open_fileports(desc, fileport_fds, nfileports);
		if (ret < 0)
			return ret;
	}

	if (setexec)
	{
		if (nports > 0)
		{
			ret = spawn_set_special_ports(desc, ports, nports);
			if (ret < 0)
			{
				nports = 0;
				goto out;
			}
		}
		goto no_fork;
	}

	ret = LINUX_SYSCALL(__NR_pipe2, pipe, LINUX_O_CLOEXEC);
	if (ret < 0)
		goto out;

	// mldr gets the write end: keep it above stdin, stdout and stderr, so nothing it prints lands in the pipe
	if (pipe[1] < 3)
	{
		ret = sys_fcntl(pipe[1], F_DUPFD_CLOEXEC, 3);
		if (ret < 0)
		{
			close_internal(pipe[0]);
			close_internal(pipe[1]);
			goto out;
		}
		close_internal(pipe[1]);
		pipe[1] = ret;
	}

	// we don't want to call user atfork callbacks, but we *do* want to call most
	// libsystem atfork callbacks to set up the environment for some of the calls we need
	// to make for the setup

	if (_libkernel_darling_functions)
		_libkernel_darling_functions->posix_spawn_prepare();

	if (nports > 0)
	{
		ret = spawn_set_special_ports(desc, ports, nports);
		if (ret < 0)
		{
			nports = 0;
			if (_libkernel_darling_functions)
				_libkernel_darling_functions->posix_spawn_parent();
			close_internal(pipe[0]);
			close_internal(pipe[1]);
			goto out;
		}
	}

	// XNU's posix_spawn() runs none of the caller's code in the new process. The child here runs its setup
	// before the exec: with signals blocked from the fork until its handlers are reset, none of the caller's
	// handlers can run in it.
	caller_mask = signals_block_all();
	if ((my_pid = (nports > 0) ? sys_fork_special_ports_locked() : sys_fork()) == 0)
	{
		// child
		// close the reading side
		close_internal(pipe[0]);

		if (_libkernel_darling_functions)
			_libkernel_darling_functions->posix_spawn_child();
		else
			_mach_fork_child(); // what Apple's libSystem runs after fork(); sys_fork did the rest of the handshake

		// the child has its special ports; the lock came along locked
		if (nports > 0)
			libsimple_lock_unlock(&fork_special_ports_lock);

		// Before any of its setup, as the new image will have them: the caught signals and SETSIGDEF's at their
		// default, the ignored ones ignored (exec_signals.h); then the mask the new image starts with, the caller's
		// or SETSIGMASK's. A signal that comes while a file action blocks (an open on a FIFO) then does what it would
		// in the new image: SIGINT ends the child, as XNU's interruptible sleep would end the spawn, and
		// darlingserver's own two signals reach it. No caller's handler can run in it, and none did before this:
		// signals were blocked from before the fork.
		exec_signals_reset_caught(sigdefault);
		linux_sigset_t start_mask = caller_mask;
		if (desc && desc->attrp && (desc->attrp->psa_flags & POSIX_SPAWN_SETSIGMASK))
			sigset_bsd_to_linux(&desc->attrp->psa_sigmask, &start_mask);
		signals_restore(start_mask);

no_fork:
		if (desc && desc->attrp)
		{
			if (desc->attrp->psa_flags & POSIX_SPAWN_RESETIDS)
			{
				sys_setgid(sys_getgid());
				sys_setuid(sys_getuid());
			}
			if (desc->attrp->psa_flags & POSIX_SPAWN_SETPGROUP)
			{
				ret = sys_setpgid(0, desc->attrp->psa_pgroup);
				if (ret != 0)
					goto fail;
			}
			// the forked child took it above; this process gets it back if its exec fails (SETPGROUP and
			// RESETIDS aren't undone: a divergence from XNU, which applies them to the activated image only)
			if (setexec && (desc->attrp->psa_flags & POSIX_SPAWN_SETSIGMASK))
			{
				ret = sys_sigprocmask(3 /* SIG_SETMASK */, &desc->attrp->psa_sigmask, &setexec_old_mask);
				if (ret != 0)
					goto fail;
				setexec_mask_set = true;
			}
			if (desc->attrp->psa_flags & _POSIX_SPAWN_DISABLE_ASLR)
			{
				unsigned int pers = LINUX_SYSCALL(__NR_personality, 0xffffffff);
				if (!(pers & LINUX_ADDR_NO_RANDOMIZE))
				{
					pers |= LINUX_ADDR_NO_RANDOMIZE;
					LINUX_SYSCALL(__NR_personality, pers);
				}
			}
			if (desc->attrp->psa_flags & POSIX_SPAWN_START_SUSPENDED)
			{
				int status = dserver_rpc_stop_after_exec();
				if (status < 0) {
					__simple_printf("Failed to tell darlingserver to stop us after exec: %d", status);
					__simple_abort();
				}
			}

			if (desc->attrp->psa_flags & POSIX_SPAWN_CLOEXEC_DEFAULT) {
				// set O_CLOEXEC on everything
				int dir = sys_open("/proc/self/fd", BSD_O_RDONLY, 0);
				char buf[4096];
				int len = 0;

				//__simple_kprintf("asked for cloexec default\n");

				if (dir < 0) {
					ret = dir;
					goto fail;
				}

				while ((len = LINUX_SYSCALL(__NR_getdents64, dir, buf, sizeof(buf))) > 0) {
					struct linux_dirent64* dirent = (struct linux_dirent64*)&buf[0];
					for (int i = 0; i < len; i += dirent->d_reclen, dirent = (struct linux_dirent64*)&buf[i]) {
						int fd = -1;

						//__simple_kprintf("dentry name: %s\n", dirent->d_name);
						if (dirent->d_name[0] == '.') {
							continue;
						}

						fd = __simple_atoi(dirent->d_name, NULL);

						// FIXME: pretty sure this should not be hardcoded
						if (fd == 1023) {
							// special commpage fd
							continue;
						}

						if (desc && desc->factp) {
							// if this FD is one that we're creating, don't set O_CLOEXEC on it
							for (size_t j = 0; j < desc->factp->psfa_act_count; j++) {
								const struct xnu__psfa_action* act = &desc->factp->psfa_act_acts[j];
								int maybe_fd = act->psfaa_filedes;

								switch (act->psfaa_type) {
									case XNU_PSFA_DUP2:
									case XNU_PSFA_FILEPORT_DUP2:
										maybe_fd = act->psfaa_dup2args.psfad_newfiledes;
										// fall through

									case XNU_PSFA_OPEN:
									case XNU_PSFA_INHERIT:
										if (fd == maybe_fd) {
											maybe_fd = -1;
										}
										break;

									default:
										break;
								}

								// maybe_fd was set to -1, indicating the descriptors matched
								if (maybe_fd == -1) {
									fd = -1;
									break;
								}
							}
						}

						// fd was set to -1, indicating we should skip it
						if (fd == -1) {
							continue;
						}

						//__simple_kprintf("setting cloexec on %d\n", fd);

						ret = sys_fcntl(fd, F_GETFD, 0);
						if (ret < 0) {
							close_internal(dir);
							goto fail;
						}

						ret = sys_fcntl(fd, F_SETFD, ret | FD_CLOEXEC);
						if (ret < 0) {
							close_internal(dir);
							goto fail;
						}
					}
				}

				close_internal(dir);

				if (len < 0) {
					ret = len;
					goto fail;
				}
			}

			// TODO: other attributes
		}
		if (desc && desc->factp)
		{
			int i;

			//__simple_kprintf("act count: %d\n", desc->factp->psfa_act_count);

			//sys_kill(sys_getpid(), SIGSTOP, 0);

			for (i = 0; i < desc->factp->psfa_act_count; i++)
			{
				const struct xnu__psfa_action* act;

				act = &desc->factp->psfa_act_acts[i];

				//__simple_kprintf("act count (on iter %d): %d\n", i, desc->factp->psfa_act_count);

				if (act->psfaa_filedes == pipe[1] || spawn_action_target_fd(act) == pipe[1])
				{
					ret = sys_fcntl(pipe[1], F_DUPFD_CLOEXEC, 3);
					if (ret < 0)
						goto fail;

					close_internal(pipe[1]);
					pipe[1] = ret;
				}

				// keep the descriptors of fileports that later actions still need out of this action's way
				for (int j = next_fileport; j < nfileports; j++)
				{
					if (fileport_fds[j] != spawn_action_target_fd(act))
						continue;

					ret = sys_fcntl(fileport_fds[j], F_DUPFD_CLOEXEC, 0);
					if (ret < 0)
						goto fail;

					close_internal(fileport_fds[j]);
					fileport_fds[j] = ret;
				}

				switch (act->psfaa_type)
				{
					case XNU_PSFA_CLOSE:
						//__simple_kprintf("closing %d\n", act->psfaa_filedes);
						ret = close_internal(act->psfaa_filedes);
						if (ret != 0)
							goto fail;
						break;

					case XNU_PSFA_DUP2:
						//__simple_kprintf("duping %d to %d\n", act->psfaa_filedes, act->psfaa_dup2args.psfad_newfiledes);
						ret = sys_dup2(act->psfaa_filedes, act->psfaa_dup2args.psfad_newfiledes);
						if (ret < 0)
							goto fail;
						break;

					case XNU_PSFA_FILEPORT_DUP2:
						ret = sys_dup2(fileport_fds[next_fileport++], act->psfaa_dup2args.psfad_newfiledes);
						if (ret < 0)
							goto fail;
						break;

					case XNU_PSFA_OPEN:
					{
						//__simple_kprintf("opening %s to %d\n", act->psfaa_openargs.psfao_path, act->psfaa_filedes);
						ret = sys_open(act->psfaa_openargs.psfao_path,
								act->psfaa_openargs.psfao_oflag, act->psfaa_openargs.psfao_mode);
						if (ret < 0)
							goto fail;

						if (ret != act->psfaa_filedes)
						{
							int fd = ret;
							ret = sys_dup2(ret, act->psfaa_filedes);

							if (ret < 0)
							{
								close_internal(fd);
								goto fail;
							}
						}
						break;
					}

					case XNU_PSFA_CHDIR: {
						//__simple_kprintf("chdiring to %s\n", act->psfaa_chdirargs.psfac_path);
						ret = sys_chdir(act->psfaa_chdirargs.psfac_path);
						if (ret < 0) {
							goto fail;
						}
					} break;

					case XNU_PSFA_FCHDIR: {
						//__simple_kprintf("fchdiring to %d\n", act->psfaa_filedes);
						ret = sys_fchdir(act->psfaa_filedes);
						if (ret < 0) {
							goto fail;
						}
					} break;

					// unset CLOEXEC on this fd
					case XNU_PSFA_INHERIT: {
						//__simple_kprintf("inheriting %d\n", act->psfaa_filedes);
						ret = sys_fcntl(act->psfaa_filedes, F_GETFD, 0);
						if (ret < 0) {
							goto fail;
						}
						ret = sys_fcntl(act->psfaa_filedes, F_SETFD, ret & ~FD_CLOEXEC);
						if (ret < 0) {
							goto fail;
						}
					} break;

					default:
						//__simple_kprintf("unknown PSFA type %d\n", act->psfaa_type);
						;
				}
			}

			//__simple_kprintf("act count (on finish): %d\n", desc->factp->psfa_act_count);
		}

		char binprefs[64];
		if (desc && desc->attrp && desc->attrp->psa_binprefs[0])
		{
			char** new_envp;
			int i, env_len = 0;

			while (envp[env_len])
				env_len++;
			env_len++; // terminating NULL

			// +1 for our new entry
			new_envp = (char**) __builtin_alloca((env_len + 1) * sizeof(char*));

			__simple_sprintf(binprefs, "__mldr_bprefs=%x,%x,%x,%x",
				desc->attrp->psa_binprefs[0],
				desc->attrp->psa_binprefs[1],
				desc->attrp->psa_binprefs[2],
				desc->attrp->psa_binprefs[3]);

			new_envp[0] = binprefs;
			for (i = 0; i < env_len; i++)
				new_envp[i+1] = envp[i];
			envp = new_envp;
		}

		// The no-fork case has no pipe (-1): its caller is the process that execs. It gets SETSIGDEF at the
		// exec, undone if that fails, as XNU applies it once the image is active (kern_exec.c); the forked child
		// has it already.
		ret = sys_execve_spawn((char*) path, (const char**) argvp, (const char**) envp, pipe[1],
			setexec ? sigdefault : 0);
fail:
		//__simple_kprintf("posix_spawn is failing with %d\n", ret);
		if (setexec)
		{
			// no_fork case
			if (setexec_mask_set)
				sys_sigprocmask(3 /* SIG_SETMASK */, &setexec_old_mask, NULL);
			spawn_close_fileports(fileport_fds, nfileports);
			if (nports > 0)
				spawn_restore_special_ports(ports, nports);
			ret = errno_linux_to_bsd(ret);
			return ret;
		}
		else
		{
			sys_write(pipe[1], &ret, sizeof(ret));
			sys_exit(127);
			__builtin_unreachable();
		}
	}
	else
	{
		// parent
		int err;

		// close the writing side
		close_internal(pipe[1]);

		// before libSystem's fork handlers, in the reverse order of a fork
		if (nports > 0)
		{
			spawn_restore_special_ports(ports, nports);
			nports = 0;
		}

		if (_libkernel_darling_functions)
			_libkernel_darling_functions->posix_spawn_parent();
		// Only now, with the fork's locks released (special ports, libSystem's atfork ones): the signals that came
		// meanwhile are delivered here, and a handler may fork, or malloc, itself.
		signals_restore(caller_mask);
		spawn_close_fileports(fileport_fds, nfileports);
		nfileports = 0;

		if (my_pid < 0)
		{
			close_internal(pipe[0]);
			ret = my_pid;
			goto out;
		}

		// XNU's posix_spawn() returns once the new image is activated, or with the error that failed it
		// (sys_execve_spawn(), execve.h)
		long got;
		while ((got = sys_read_nocancel(pipe[0], &ret, sizeof(ret))) == -EINTR)
			;
		// only a negative errno is an error; EOF is success
		if (got != sizeof(ret) || ret >= 0 || ret < -ELAST)
			ret = 0;
		close_internal(pipe[0]);

		// a failed spawn leaves no process on XNU, and gives no pid: reap the child that reported it
		if (ret < 0)
		{
			while (LINUX_SYSCALL(__NR_wait4, my_pid, NULL, 0, NULL) == -LINUX_EINTR)
				;
		}
		else if (pid != NULL)
			*pid = my_pid;
	}

out:
	if (nports > 0)
		spawn_restore_special_ports(ports, nports);
	spawn_close_fileports(fileport_fds, nfileports);
	return ret;
}
