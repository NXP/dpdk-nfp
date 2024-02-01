#include "netwrap_common.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>
#include "netwrap_uio.h"
#include "netwrap_errno.h"
#include "netwrap_log.h"


static ssize_t (*libc_writev)(int, const struct iovec *, int);

void setup_uio_wrappers(void)
{
	LIBC_FUNCTION(writev);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t writev_value = -1;

	if (IS_USECT_SOCKET(fd)) {
		ECAT_DBG("DPDK writev\n");
		writev_value = (*libc_writev)(fd, iov, iovcnt);
	} else if (libc_writev)
		writev_value = (*libc_writev)(fd, iov, iovcnt);
	else {
		LIBC_FUNCTION(writev);

		if (libc_writev)
			writev_value = (*libc_writev)(fd, iov, iovcnt);
		else {
			writev_value = -1;
			errno = EACCES;
		}
	}

	return writev_value;
}
