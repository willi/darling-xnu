#ifndef LINUX_KEVENT_QOS_H
#define LINUX_KEVENT_QOS_H

#define PRIVATE 1
#include <sys/event.h>

long sys_kevent_qos(int	kq, const struct kevent_qos_s *changelist, int nchanges,
			struct	kevent_qos_s *eventlist, int nevents,
			void* data_out, unsigned long* data_available, unsigned int flags);

struct kevent64_s;
void kevent_qos_to_64(const struct kevent_qos_s* ev, struct kevent64_s* ev64);
void kevent_64_to_qos(const struct kevent64_s* ev64, struct kevent_qos_s* ev);

#endif // LINUX_KEVENT_QOS_H
