#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include "netwrap_log.h"


static volatile bool force_quit;

static void
signal_handler(int signum)
{
        if (signum == SIGINT || signum == SIGTERM) {
                printf("\n\nSignal %d received, preparing to exit...\n",
                                signum);
                force_quit = true;
        }
}

__attribute__((destructor)) static void netwrap_main_dtor(void);

__attribute__((constructor(65535))) static void netwrap_main_ctor(void)
{
	int dpdk_argc;
	char *dpdk_env;
	int i;
	int ret;
	uint16_t nb_ports;

	dpdk_env = getenv("DPDK_ENV");
	if (!dpdk_env) {
		ECAT_DBG("DPDK_ENV not set\n");
		exit(1);
	}

	for (i = 0, dpdk_argc = 1; i < strlen(dpdk_env); ++i) {
		if (isspace(dpdk_env[i]))
			++dpdk_argc;
	}

	char *dpdk_argv[dpdk_argc];

	dpdk_argc = rte_strsplit(dpdk_env, strlen(dpdk_env), dpdk_argv,
			dpdk_argc, ' ');

	for (i = 0; i < dpdk_argc; ++i)
		ECAT_DBG("arg[%d]: %s\n", i, dpdk_argv[i]);
	fflush(stdout);

	ret = rte_eal_init(dpdk_argc, dpdk_argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	force_quit = false;
	signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
}

__attribute__((destructor)) static void netwrap_main_dtor(void)
{

}
