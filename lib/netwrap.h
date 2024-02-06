/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

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
#include <rte_log.h>
#include <errno.h>

#define RTE_LOGTYPE_pre_ld RTE_LOGTYPE_USER1

/* record packet related info */
struct packet_info {
	bool flag;
	rte_be16_t src_port;
	rte_be16_t dst_port;
	rte_be32_t src_ip;
	rte_be32_t dst_ip;
	uint8_t src_mac[RTE_ETHER_ADDR_LEN];
	uint8_t dst_mac[RTE_ETHER_ADDR_LEN];
};

#ifndef RTLD_NEXT
#define RTLD_NEXT	((void *) -1l)
#endif

#define LIBC_FUNCTION(func) do {			\
		libc_##func = dlsym(RTLD_NEXT, #func);	\
		if (dlerror()) {			\
			fprintf(stderr, \
				"Failed to load sym(%s)\n", #func);\
			errno = EACCES;			\
			exit(1);			\
		}					\
	} while (0)

#define OFP_SOCK_NUM_OFFSET 8192
#define IS_OFP_SOCKET(_fd) (_fd >= OFP_SOCK_NUM_OFFSET)

#define IS_USECT_SOCKET(_fd) (_fd == s_usect_sockfd)

#endif /* __NETWRAP_COMMON_H__ */
