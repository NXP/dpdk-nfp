#include "netwrap_common.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <stdio.h>
#include "netwrap_sendfile.h"
#include "netwrap_errno.h"
#include "netwrap_log.h"

static ssize_t (*libc_sendfile64)(int, int, off_t *, size_t);
static ssize_t (*libc_read)(int, void*, size_t);

void setup_sendfile_wrappers(void)
{
	LIBC_FUNCTION(sendfile64);
	LIBC_FUNCTION(read);
}

#define BUF_SIZE 1024

ssize_t sendfile64(int out_fd, int in_fd, off64_t *offset, size_t count)
{
	ssize_t sendfile_value = -1;

	if (IS_USECT_SOCKET(out_fd)) {
		ECAT_DBG("DPDK sendfile\n");
	} else if (libc_sendfile64)
		sendfile_value = (*libc_sendfile64)(out_fd, in_fd,
				offset, count);
	else {
		LIBC_FUNCTION(sendfile64);

		if (libc_sendfile64)
			sendfile_value = (*libc_sendfile64)(out_fd, in_fd,
				offset, count);
		else {
			sendfile_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Sendfile64 called on socket '%d' returned:'%d'\n",
		out_fd, (int)sendfile_value);*/
	return sendfile_value;
}
