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

#define IS_USECT_SOCKET(_fd) \
({ \
	int usr_fd_found = 0, i; \
	\
	for (i = 0; i < (s_usr_fd_num); i++) { \
		if (_fd == s_fd_usr[i]) { \
			usr_fd_found = 1; \
			break; \
		} \
	} \
	usr_fd_found; \
})

void
pre_ld_configure_dl_sec_path(uint16_t port_id, uint16_t rxq_id);

#endif /* __NETWRAP_COMMON_H__ */
