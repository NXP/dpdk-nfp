#include <stdio.h>
#include <stdlib.h>
#include "netwrap_socket.h"
#include "netwrap_sockopt.h"
#include "netwrap_ioctl.h"
#if 0
#include "netwrap_fork.h"
#include "netwrap_select.h"
#include "netwrap_uio.h"
#include "netwrap_sendfile.h"
#include "netwrap_epoll.h"
#endif

__attribute__((constructor(65535))) static void setup_wrappers(void)
{
	setup_socket_wrappers();
	setup_sockopt_wrappers();
	setup_ioctl_wrappers();
#if 0
	setup_fork_wrappers();
	setup_select_wrappers();
	setup_uio_wrappers();
	setup_sendfile_wrappers();
	setup_epoll_wrappers();
#endif
}
