#include "netwrap_common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "netwrap_sockopt.h"
#include "netwrap_errno.h"
#include "netwrap_log.h"

static int (*libc_setsockopt)(int, int, int, const void*, socklen_t);
static int (*libc_getsockopt)(int, int, int, void*, socklen_t*);

void setup_sockopt_wrappers(void)
{
	LIBC_FUNCTION(setsockopt);
	LIBC_FUNCTION(getsockopt);
}

int setsockopt(int sockfd, int level, int opt_name, const void *opt_val,
	socklen_t opt_len)
{
	int setsockopt_value = -1;

	if (IS_USECT_SOCKET(sockfd)) {
		printf("DPDK setsockopt fd = %d, level = %d, optname = %d\n",
				sockfd, level, opt_name);
		setsockopt_value = 0;
	} else if (libc_setsockopt)
		setsockopt_value = (*libc_setsockopt)(sockfd, level, opt_name,
			opt_val, opt_len);
	else {
		LIBC_FUNCTION(setsockopt);

		if (libc_setsockopt)
			setsockopt_value = (*libc_setsockopt)(sockfd, level,
				opt_name, opt_val, opt_len);
		else {
			setsockopt_value = -1;
			errno = EACCES;
		}
	}

	return setsockopt_value;
}

int getsockopt(int sockfd, int level, int opt_name, void *opt_val,
	socklen_t *opt_len)
{
	int getsockopt_value = -1;

	if (IS_USECT_SOCKET(sockfd)) {
		printf("DPDK getsockopt fd = %d, level = %d, optname = %d\n",
				sockfd, level, opt_name);
	} else if (libc_getsockopt) {
		ECAT_DBG("libc_getsockopt fd = %d, level = %d, optname = %d\n",
				sockfd, level, opt_name);
		getsockopt_value = (*libc_getsockopt)(sockfd, level, opt_name,
			opt_val, opt_len);
	} else {
		LIBC_FUNCTION(getsockopt);
		ECAT_DBG("libc_getsockopt fd = %d, level = %d, optname = %d\n",
				sockfd, level, opt_name);

		if (libc_getsockopt)
			getsockopt_value = (*libc_getsockopt)(sockfd, level,
					opt_name, opt_val, opt_len);
		else {
			getsockopt_value = -1;
			errno = EACCES;
		}
	}
	return getsockopt_value;
}
