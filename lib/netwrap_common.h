#ifndef __NETWRAP_COMMON_H__
#define __NETWRAP_COMMON_H__

#ifndef RTLD_NEXT
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>

/* record packet related info */
struct packet_info {
	bool flag;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint8_t src_mac[6];
	uint8_t dst_mac[6];
};

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


