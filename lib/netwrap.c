#include <stdio.h>
#include <stdlib.h>
#include "netwrap_socket.h"
#include "netwrap_sockopt.h"
#include "netwrap_ioctl.h"

__attribute__((constructor(65535))) static void setup_wrappers(void)
{
	setup_socket_wrappers();
	setup_sockopt_wrappers();
	setup_ioctl_wrappers();
}
