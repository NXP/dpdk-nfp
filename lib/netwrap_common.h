#ifndef __NETWRAP_COMMON_H__
#define __NETWRAP_COMMON_H__

#ifndef RTLD_NEXT
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
#include <dlfcn.h>

#define LIBC_FUNCTION(func) do {			\
		libc_##func = dlsym(RTLD_NEXT, #func);	\
		if (dlerror()) {			\
			errno = EACCES;			\
			exit(1);			\
		}					\
	} while (0)

#define OFP_SOCK_NUM_OFFSET 8192
#define IS_OFP_SOCKET(_fd) (_fd >= OFP_SOCK_NUM_OFFSET)

extern int usect_sockfd;
#define IS_USECT_SOCKET(_fd) (_fd == usect_sockfd)

#endif /* __NETWRAP_COMMON_H__ */


