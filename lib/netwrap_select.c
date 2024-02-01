#include "netwrap_common.h"
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "netwrap_select.h"
#include "netwrap_errno.h"
#include "netwrap_log.h"

static int (*libc_select)(int, fd_set *, fd_set *, fd_set *,
	struct timeval *);


void setup_select_wrappers(void)
{
	LIBC_FUNCTION(select);
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout)
{
	int select_value;

	if (IS_USECT_SOCKET((nfds - 1))) {
		ECAT_DBG("DPDK select\n");
		select_value = (*libc_select)(nfds, readfds, writefds,
			exceptfds, timeout);
	} else if (libc_select)
		select_value = (*libc_select)(nfds, readfds, writefds,
			exceptfds, timeout);
	else {
		LIBC_FUNCTION(select);

		if (libc_select)
			select_value = (*libc_select)(nfds, readfds, writefds,
				exceptfds, timeout);
		else {
			select_value = -1;
			errno = EACCES;
		}
	}

	/*printf("Select called with max fd = %d returned %d\n",
		nfds, select_value);*/
	return select_value;
}
