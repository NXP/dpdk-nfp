#include "netwrap_epoll.h"
#include "netwrap_common.h"
#include <errno.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <stdio.h>
#include "netwrap_log.h"

static int setup_epoll_wrappers_called;

static int (*libc_epoll_create)(int size);

static int (*libc_epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event);

static int (*libc_epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);


void setup_epoll_wrappers(void)
{
	LIBC_FUNCTION(epoll_create);
	LIBC_FUNCTION(epoll_ctl);
	LIBC_FUNCTION(epoll_wait);
	setup_epoll_wrappers_called = 1;
}

int epoll_create(int size)
{
	int epfd = -1;

	if (setup_epoll_wrappers_called) {
		ECAT_DBG("DPDK epoll create\n");
	} else {
		LIBC_FUNCTION(epoll_create);

		if (libc_epoll_create)
			epfd = libc_epoll_create(size);
		else {
			errno = EACCES;
			epfd = -1;
		}
	}

	return epfd;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	if (IS_USECT_SOCKET(epfd)) {
		ECAT_DBG("DPDK epoll ctl\n");
	}

	if (libc_epoll_ctl)
		return libc_epoll_ctl(epfd, op, fd, event);

	LIBC_FUNCTION(epoll_ctl);
	if (libc_epoll_ctl)
		return libc_epoll_ctl(epfd, op, fd, event);

	errno = EACCES;
	return -1;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	if (IS_USECT_SOCKET(epfd)) {
		ECAT_DBG("DPDK epoll wait\n");
	}

	if (libc_epoll_wait)
		return libc_epoll_wait(epfd, events, maxevents, timeout);

	LIBC_FUNCTION(epoll_wait);
	if (libc_epoll_wait)
		return libc_epoll_wait(epfd, events, maxevents, timeout);

	errno = EACCES;
	return -1;
}
