#include "netwrap_common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include "netwrap_ioctl.h"
#include "netwrap_errno.h"
#include "netwrap_log.h"

static int (*libc_ioctl)(int, unsigned long int, ...);

void setup_ioctl_wrappers(void)
{
	LIBC_FUNCTION(ioctl);
}

int ioctl(int fd, unsigned long int request, ...)
{
	int ioctl_value;
	va_list ap;
	void *data;

	va_start(ap, request);
	data = va_arg(ap, void *);
	va_end(ap);

	if (IS_USECT_SOCKET(fd)) {
		printf("DPDK IOCTL fd = %d, request = 0x%x\n",
				fd, request);
		ioctl_value = (*libc_ioctl)(fd, request, data);
	} else if (libc_ioctl) {
		ECAT_DBG("libc_ioctl fd = %d, request = 0x%x\n",
				fd, request);
		ioctl_value = (*libc_ioctl)(fd, request, data);
	} else {
		LIBC_FUNCTION(ioctl);
		ECAT_DBG("libc_ioctl fd = %d, request = 0x%x\n",
				fd, request);
		if (libc_ioctl)
			ioctl_value = (*libc_ioctl)(fd, request, data);
		else {
			ioctl_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Ioctl called on socket '%d' returned %d\n", fd,
		ioctl_value);*/
	return ioctl_value;
}
