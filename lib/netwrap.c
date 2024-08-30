/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <dlfcn.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if_arp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <dirent.h>

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
#include <rte_string_fns.h>
#include <rte_tm.h>
#include <rte_ipsec.h>
#include <rte_tailq.h>

#include <rte_pmd_dpaa2.h>
#include <nxp/rte_remote_direct_flow.h>

#include "netwrap.h"

#define PRE_LD_CONSTRUCTOR_PRIO 65535

#define PRE_LOAD_USR_APP_NAME_ENV "PRE_LOAD_USR_APP_NAME"

#define IPSEC_STROKE_PROCESS_NAME \
	"/usr/lib/ipsec/stroke"

static char *s_usr_app_nm;

#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif
#define INVALID_SOCKFD (-1)

static int s_socket_pre_set;
static int s_in_pre_loading;

static int s_eal_inited;
static pthread_mutex_t s_eal_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_dp_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint16_t s_cpu_start = 1;
#define SYS_CORE_ID 0

static const char *s_dpdmux_ep_name;
static int s_dpdmux_id = -1;
static int s_dpdmux_ep_id;

enum {
	CRYPTO_DEV_INGRESS_QP,
	CRYPTO_DEV_EGRESS_QP,
	CRYPTO_DEV_QP_NUM
};

#define SESS_MP_NB_OBJS 1024
#define SESS_MP_CACHE_SZ 64

#define CRYPT_DEV_QUEUE_DESC 2048
#define CRYPT_DEV_DEFAULT_ID 0
#define CRYPT_DEV_MAX_NUM 4

static struct pre_ld_crypt_param s_crypt_param;

static const char *s_eal_file_prefix;
static char *s_uplink;
static const char *s_slow_if;
static char *s_downlink;

static int s_manual_restart_ipsec;
static int s_flow_control;
static int s_force_eal_thread;

static int s_fd_rte_ring;

static uint16_t s_l3_traffic_dump;
static uint8_t s_l4_traffic_dump;

static pthread_t s_main_td;

#define MAX_USR_FD_NUM 1024

#define STATISTICS_DELAY_SEC 5

struct eth_ipv4_udp_hdr {
	struct rte_ether_hdr eth_hdr;
	struct rte_ipv4_hdr ip_hdr;
	struct rte_udp_hdr udp_hdr;
} __rte_packed;

struct pre_ld_rx_pool {
	struct rte_mbuf **rx_bufs;
	uint16_t max_num;
	uint16_t head;
	uint16_t tail;
};

enum hdr_init_enum {
	HDR_INIT_NONE = 0,
	LOCAL_ETH_INIT = (1 << 0),
	LOCAL_IP_INIT = (1 << 1),
	LOCAL_UDP_INIT = (1 << 2),
	REMOTE_ETH_INIT = (1 << 3),
	REMOTE_IP_INIT = (1 << 4),
	REMOTE_UDP_INIT = (1 << 5),
	HDR_INIT_ALL = LOCAL_ETH_INIT | LOCAL_IP_INIT |
		LOCAL_UDP_INIT | REMOTE_ETH_INIT |
		REMOTE_IP_INIT | REMOTE_UDP_INIT
};

enum pre_ld_statistic_dir {
	PRE_LD_STAT_RX,
	PRE_LD_STAT_TX
};

struct fd_statistic {
	uint64_t count;
	uint64_t pkts;
	uint64_t oh_bytes;
	uint64_t usr_bytes;
};

struct fd_thread_desc {
	uint32_t cpu;
	uint32_t *lcore;
	pthread_t thread;
};

enum fd_data_path_type {
	FD_DP_DIRECT_TYPE,
	FD_DP_IN_DIRECT_TYPE
};

struct fd_hw_desc {
	uint16_t rx_port;
	uint16_t *rxq_id;
	uint16_t tx_port;
};

struct fd_entry_desc {
	struct pre_ld_direct_entry *rx_entry;
	struct pre_ld_direct_entry *tx_entry;
};

union fd_data_path_desc {
	struct fd_hw_desc hw_desc;
	struct fd_entry_desc entry_desc;
};

struct fd_desc {
	TAILQ_ENTRY(fd_desc) next;
	int fd;
	int eal_thread;
	int eal_thread_nb;
	struct fd_thread_desc th_desc[RTE_MAX_LCORE];
	struct eth_ipv4_udp_hdr hdr;
	enum hdr_init_enum hdr_init;
	enum fd_data_path_type dp_type;
	union fd_data_path_desc dp_desc;
	void *flow;
	struct rte_mempool *tx_pool;
	struct pre_ld_rx_pool rx_buffer;

	uint16_t rx_port_mtu;
	uint16_t tx_port_mtu;

	struct fd_statistic tx_stat;
	struct fd_statistic rx_stat;

	/** Update by statistic function only.*/
	struct fd_statistic tx_old_stat;
	struct fd_statistic rx_old_stat;
};

enum pre_ld_crypto_dir {
	INGRESS_CRYPTO_EQ,
	INGRESS_CRYPTO_DQ,
	EGRESS_CRYPTO_EQ,
	EGRESS_CRYPTO_DQ
};

pthread_mutex_t s_fd_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct fd_desc *s_fd_desc;

TAILQ_HEAD(fd_desc_list, fd_desc);
static struct fd_desc_list s_fd_desc_list =
	TAILQ_HEAD_INITIALIZER(s_fd_desc_list);

pthread_mutex_t s_fd_list_mutex = PTHREAD_MUTEX_INITIALIZER;

#define UDP_HDR_LEN sizeof(struct rte_udp_hdr)

#define IPv4_HDR_LEN \
	(sizeof(struct rte_ipv4_hdr) + UDP_HDR_LEN)

#define IPv4_ESP_HDR_LEN \
	(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_esp_hdr))

#define ESP_TAIL_MAX_LEN 16

static int (*libc_socket)(int, int, int);
static int (*libc_shutdown)(int, int);
static int (*libc_close)(int);
static int (*libc_bind)(int, const struct sockaddr *, socklen_t);
static int (*libc_accept)(int, struct sockaddr *, socklen_t *);
static int (*libc_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t (*libc_read)(int, void *, size_t);
static ssize_t (*libc_write)(int, const void *, size_t);
static ssize_t (*libc_recv)(int, void *, size_t, int);
static ssize_t (*libc_send)(int, const void *, size_t, int);
static int (*libc_select)(int, fd_set *, fd_set *, fd_set *,
	struct timeval *);

#define PRE_LD_ETH_FCS_SIZE \
	(RTE_TM_ETH_FRAMING_OVERHEAD_FCS - RTE_TM_ETH_FRAMING_OVERHEAD)

static int s_socket_dbg;
static int s_statistic_print;

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define MEMPOOL_ELEM_SIZE 8192
#define MEMPOOL_USR_SIZE (MEMPOOL_ELEM_SIZE / 8)

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_DPAA2_RX_DESC_MAX 8192

#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t s_dpaa2_nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t s_nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t s_nb_txd = RTE_TEST_TX_DESC_DEFAULT;

#define MAX_QUEUES_PER_PORT 16
static struct rte_ring *s_port_rxq_rings[RTE_MAX_ETHPORTS];
static struct rte_ring *s_port_txq_rings[RTE_MAX_ETHPORTS];
static uint16_t s_def_rxq[RTE_MAX_ETHPORTS];

static uint16_t s_rxq_ids[RTE_MAX_ETHPORTS][MAX_QUEUES_PER_PORT];
static uint16_t s_txq_ids[RTE_MAX_ETHPORTS][MAX_QUEUES_PER_PORT];

static struct rte_ring *s_crypt_queue_ring[CRYPT_DEV_MAX_NUM];
static uint16_t *s_crypt_queue_ids[CRYPT_DEV_MAX_NUM];

static struct rte_eth_conf s_port_conf = {
	.rxmode = {0},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

static struct rte_mempool *s_pre_ld_rx_pool;
static int s_tx_from_rx_pool;

struct pre_ld_dir_port_cfg {
	int valid;
	uint16_t ext_id;
	uint16_t ul_id;
	uint16_t dl_id;
	uint16_t tap_id;
};

static struct pre_ld_dir_port_cfg s_dir_ports;

enum pre_ld_port_type {
	NULL_TYPE = 0,
	EXTERNAL_TYPE = (1 << 0),
	UP_LINK_TYPE = (1 << 1),
	DOWN_LINK_TYPE = (1 << 2),
	KERNEL_TAP_TYPE = (1 << 3),
	ALL_TYPE = EXTERNAL_TYPE | UP_LINK_TYPE |
		DOWN_LINK_TYPE | KERNEL_TAP_TYPE
};

#define IP_DEFTTL       64
#define IP_VERSION      0x40
#define IP_HDRLEN       0x05
#define IP_VHL_DEF      (IP_VERSION | IP_HDRLEN)

TAILQ_HEAD(pre_ld_lcore_direct_list, pre_ld_direct_entry);
static struct pre_ld_lcore_direct_list s_pre_ld_lists[RTE_MAX_LCORE];

static pthread_mutex_t s_lcore_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Single core support only now.*/
static int s_pre_ld_quit;

/** Single rx/tx ports pair support only now, default 0.*/
static uint16_t s_rx_port;
static uint16_t s_tx_port;

static int s_dpdmux_entry_index = -1;

static int s_data_path_core = -1;

static int s_ipsec_buf_swap;

#define MAX_HUGE_FRAME_SIZE 9600
static uint16_t s_mtu_set;
static int s_dump_traffic_flow;

struct pre_ld_default_direction {
	struct rte_remote_dir_req *def_dir;
	uint16_t from_ids[MAX_DEF_DIR_NUM];
	uint16_t to_ids[MAX_DEF_DIR_NUM];
	uint16_t prios[MAX_DEF_DIR_NUM];
	struct rte_flow *flows[MAX_DEF_DIR_NUM];
};

struct pre_ld_default_direction s_pre_ld_def_dir;

struct pre_ld_udp_desc {
	uint16_t offset;
	uint16_t length;
} __rte_packed;

#define PRE_LD_MP_PRIV_SIZE \
	sizeof(struct pre_ld_ipsec_priv)

#define PRE_LD_MBUF_OFFSET 512

#define PRE_LD_MBUF_MAX_SIZE \
	(PRE_LD_MP_PRIV_SIZE + PRE_LD_MBUF_OFFSET + \
	RTE_MBUF_DEFAULT_DATAROOM)

static struct pre_ld_ring *
pre_ld_ring_create(const char *name, uint16_t size)
{
	struct pre_ld_ring *_r;
	int ret;

	_r = rte_zmalloc(NULL, sizeof(struct pre_ld_ring), 0);
	if (!_r)
		return NULL;
	ret = strlcpy(_r->name, name, RTE_MEMZONE_NAMESIZE);
	if (ret < 0 || ret >= RTE_MEMZONE_NAMESIZE) {
		rte_free(_r);

		return NULL;
	}

	size = rte_align32pow2(size + 1);

	_r->pre_ld_elems = rte_zmalloc(NULL,
		size * sizeof(void *), RTE_CACHE_LINE_SIZE);
	if (!_r->pre_ld_elems) {
		rte_free(_r);

		return NULL;
	}
	_r->pre_ld_head = 0;
	_r->pre_ld_tail = 0;
	_r->pre_ld_size = size;

	return _r;
}

static void
pre_ld_ring_free(struct pre_ld_ring *plr)
{
	rte_free(plr->pre_ld_elems);
	rte_free(plr);
}

static inline uint16_t
pre_ld_ring_eq(struct pre_ld_ring *plr, void **elem, uint16_t num)
{
	uint16_t idx = 0, pos;

	pos = plr->pre_ld_tail;
	while (((pos + 1) & (plr->pre_ld_size - 1)) !=
		plr->pre_ld_head) {
		plr->pre_ld_elems[pos] = elem[idx];
		idx++;
		pos = (pos + 1) & (plr->pre_ld_size - 1);
		if (idx == num)
			break;
	}
	rte_io_wmb();
	plr->pre_ld_tail = pos;

	return idx;
}

static inline uint16_t
pre_ld_ring_dq(struct pre_ld_ring *plr, void **elem, uint16_t num)
{
	uint16_t idx = 0, pos;

	pos = plr->pre_ld_head;
	while (plr->pre_ld_tail != pos) {
		elem[idx] = plr->pre_ld_elems[pos];
		idx++;
		pos = (pos + 1) & (plr->pre_ld_size - 1);
		if (idx == num)
			break;
	}
	rte_io_wmb();
	rte_io_rmb();
	plr->pre_ld_head = pos;

	return idx;
}

static inline void
pre_ld_insert_dir_list_safe(struct pre_ld_lcore_direct_list *list,
	struct pre_ld_direct_entry *dir)
{
	pthread_mutex_lock(&s_lcore_mutex);
	dir->state = PRE_LD_DIR_ENTRY_RUNNING;
	dcbf(&dir->state);
	TAILQ_INSERT_TAIL(list, dir, next);
	pthread_mutex_unlock(&s_lcore_mutex);
}

static inline void
pre_ld_remove_dir_list_safe(struct pre_ld_lcore_direct_list *list,
	struct pre_ld_direct_entry *dir)
{
	pthread_mutex_lock(&s_lcore_mutex);
	dir->state = PRE_LD_DIR_ENTRY_STOPPING;
	dcbf(&dir->state);
	while (dir->state != PRE_LD_DIR_ENTRY_STOPPED) {
		dccivac(&dir->state);
		if (s_pre_ld_quit)
			break;
	}
	TAILQ_REMOVE(list, dir, next);
	pthread_mutex_unlock(&s_lcore_mutex);
}

static void
pre_ld_free_crypt_queue_ring(void)
{
	int i;

	for (i = 0; i < CRYPT_DEV_MAX_NUM; i++) {
		if (s_crypt_queue_ring[i]) {
			rte_ring_free(s_crypt_queue_ring[i]);
			s_crypt_queue_ring[i] = NULL;
		}
	}

	for (i = 0; i < CRYPT_DEV_MAX_NUM; i++) {
		if (s_crypt_queue_ids[i]) {
			rte_free(s_crypt_queue_ids[i]);
			s_crypt_queue_ids[i] = NULL;
		}
	}
}

static int
pre_ld_cryptodev_init(void)
{
	struct rte_cryptodev_config dev_conf;
	struct rte_cryptodev_qp_conf qp_conf;
	uint16_t qp;
	struct rte_cryptodev_info cdev_info;
	char nm[RTE_MEMZONE_NAMESIZE];
	int ret;
	uint8_t crypt_dev = s_crypt_param.crypt_dev;

	rte_cryptodev_info_get(crypt_dev, &cdev_info);
	if (cdev_info.max_nb_queue_pairs < 2) {
		RTE_LOG(ERR, pre_ld,
			"Crypto(%d) can't support encap/decap with %d queue(s)\n",
			crypt_dev, cdev_info.max_nb_queue_pairs);
		return -ENOTSUP;
	}

	dev_conf.socket_id = 0;
	dev_conf.nb_queue_pairs = cdev_info.max_nb_queue_pairs;
	dev_conf.ff_disable = RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO;

	ret = rte_cryptodev_configure(crypt_dev, &dev_conf);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Crypto(%d) configure failed(%d)\n", crypt_dev, ret);

		return ret;
	}

	qp_conf.nb_descriptors = CRYPT_DEV_QUEUE_DESC;
	qp_conf.mp_session = s_crypt_param.sess_pool;
	for (qp = 0; qp < dev_conf.nb_queue_pairs; qp++) {
		ret = rte_cryptodev_queue_pair_setup(crypt_dev, qp,
				&qp_conf, dev_conf.socket_id);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"Crypto(%d) setup qp%d failed(%d)\n",
				crypt_dev, qp, ret);

			return ret;
		}
	}

	ret = rte_cryptodev_start(crypt_dev);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Crypto(%d) start failed(%d)\n", crypt_dev, ret);

		return ret;
	}

	if (!s_crypt_queue_ring[crypt_dev]) {
		sprintf(nm, "pre_ld_crypt%d_queues", crypt_dev);
		s_crypt_queue_ring[crypt_dev] = rte_ring_create(nm,
			cdev_info.max_nb_queue_pairs * 2, 0, RING_F_EXACT_SZ);
		if (!s_crypt_queue_ring[crypt_dev]) {
			rte_cryptodev_stop(crypt_dev);
			return -ENOMEM;
		}
		s_crypt_queue_ids[crypt_dev] = rte_zmalloc(NULL,
			cdev_info.max_nb_queue_pairs * sizeof(uint16_t), 0);
		if (!s_crypt_queue_ids[crypt_dev]) {
			rte_ring_free(s_crypt_queue_ring[crypt_dev]);
			s_crypt_queue_ring[crypt_dev] = NULL;
			rte_cryptodev_stop(crypt_dev);
			return -ENOMEM;
		}
		for (qp = 0; qp < cdev_info.max_nb_queue_pairs; qp++) {
			s_crypt_queue_ids[crypt_dev][qp] = qp;
			rte_ring_enqueue(s_crypt_queue_ring[crypt_dev],
				&s_crypt_queue_ids[crypt_dev][qp]);
		}
	}

	return 0;
}

static int
pre_ld_crypt_sess_priv_pool_create(void)
{
	size_t max_sz, sz;
	void *sec_ctx;
	char mp_name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *sess_mp;
	uint8_t dev_id = s_crypt_param.crypt_dev;

	max_sz = 0;
	sz = rte_cryptodev_sym_get_private_session_size(dev_id);
	if (sz > max_sz)
		max_sz = sz;

	/* Get security context of the crypto device */
	sec_ctx = rte_cryptodev_get_sec_ctx(dev_id);
	if (sec_ctx) {
		/* Get size of security session */
		sz = rte_security_session_get_size(sec_ctx);
		if (sz > max_sz)
			max_sz = sz;
	}

	snprintf(mp_name, RTE_MEMPOOL_NAMESIZE, "sess_mp_priv");
	sess_mp = rte_mempool_create(mp_name, SESS_MP_NB_OBJS,
			max_sz, SESS_MP_CACHE_SZ, 0, NULL, NULL, NULL,
			NULL, 0, 0);
	s_crypt_param.sess_priv_pool = sess_mp;

	return 0;
}

static int
pre_ld_crypto_init(struct rte_mempool *mbuf_pool)
{
	int ret;

	s_crypt_param.crypt_dev = CRYPT_DEV_DEFAULT_ID;
	s_crypt_param.sess_pool = mbuf_pool;
	ret = pre_ld_crypt_sess_priv_pool_create();
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Crypto session pool create failed(%d)\n",
			ret);

		return ret;
	}
	ret = pre_ld_cryptodev_init();
	if (ret) {
		RTE_LOG(ERR, pre_ld, "Crypto init failed(%d)\n", ret);

		return ret;
	}
	ret = xfrm_setup_msgloop(&s_crypt_param);
	if (ret) {
		RTE_LOG(ERR, pre_ld, "IPSec msg setup failed(%d)\n", ret);

		return ret;
	}

	RTE_LOG(INFO, pre_ld, "Crypto init successfully\n");

	return 0;
}

static inline int
convert_ip_addr_to_str(char *str,
	const void *_addr, uint8_t len)
{
	uint8_t i, idx = 0;
	int ret_len;
	const uint8_t *addr = _addr;

	if (len == 4) {
		for (i = 0; i < len; i++) {
			ret_len = sprintf(&str[idx], "%d", addr[i]);
			str[idx + ret_len] = '.';
			idx += (ret_len + 1);
		}
		str[idx] = 0;
	} else if (len == 16) {
		for (i = 0; i < len; i++) {
			ret_len = sprintf(&str[idx], "%d", addr[i]);
			str[idx + ret_len] = ':';
			idx += (ret_len + 1);
		}
		str[idx] = 0;
	} else {
		RTE_LOG(ERR, pre_ld,
			"Invalid IP address length(%d)", len);
		return -EINVAL;
	}

	return 0;
}

static int
netwrap_get_current_process_name(char *nm)
{
	FILE *f;
	size_t size;
	char file_nm[1024];
	char ps_nm[1024];
	int pid = getpid();

	memset(file_nm, 0, 1024);
	memset(ps_nm, 0, 1024);
	sprintf(file_nm, "/proc/%d/cmdline", pid);
	f = fopen(file_nm, "r");
	if (f) {
		size = fread(ps_nm, sizeof(char), 1024, f);
		if (size > 0) {
			RTE_LOG(INFO, pre_ld,
				"This process: PID = %d, name: %s\n",
				pid, ps_nm);
			strcpy(nm, ps_nm);

			return 0;
		}
	}

	return -EACCES;
}

static int
netwrap_is_usr_process(void)
{
	int ret;
	char current_nm[1024];

	ret = netwrap_get_current_process_name(current_nm);
	if (!ret) {
		s_usr_app_nm = getenv(PRE_LOAD_USR_APP_NAME_ENV);
		if (!s_usr_app_nm) {
			setenv(PRE_LOAD_USR_APP_NAME_ENV, current_nm, 1);
			s_usr_app_nm = getenv(PRE_LOAD_USR_APP_NAME_ENV);
		}
		if (!strcmp(s_usr_app_nm, current_nm))
			return true;

		RTE_LOG(INFO, pre_ld,
			"This process(%s) is not user app(%s)\n",
			current_nm, s_usr_app_nm);
	}

	return false;
}

static int
pre_ld_sp_out_ready(void)
{
	struct pre_ld_ipsec_cntx *cntx = xfm_get_cntx();

	if (LIST_FIRST(&cntx->sp_ipv4_out_list) ||
		LIST_FIRST(&cntx->sp_ipv6_out_list))
		return true;

	return false;
}

static int
eal_destroy_dpaa2_mux_flow(void)
{
	int ret;

	if (s_dpdmux_entry_index < 0 || s_dpdmux_id < 0)
		return 0;

	ret = rte_pmd_dpaa2_mux_flow_destroy(s_dpdmux_id,
		s_dpdmux_entry_index);
	if (!ret)
		s_dpdmux_entry_index = -1;

	return ret;
}

static inline int
is_usr_socket(int sockfd)
{
	struct fd_desc *usr, *tusr;

	RTE_TAILQ_FOREACH_SAFE(usr, &s_fd_desc_list, next, tusr) {
		if (usr->fd == sockfd)
			return true;
	}

	return false;
}

static void
usr_socket_fd_remove(int sockfd)
{
	pthread_mutex_lock(&s_fd_list_mutex);
	TAILQ_REMOVE(&s_fd_desc_list, &s_fd_desc[sockfd], next);
	pthread_mutex_unlock(&s_fd_list_mutex);
	RTE_LOG(INFO, pre_ld, "FD(%d) was removed from user sockets.\n",
		sockfd);
}

static int
usr_socket_fd_release(int sockfd)
{
	int ret = 0, i, times = PRE_LD_FLOW_DESTROY_TRY_TIMES;
	uint16_t rx_port, nb, *rxq_id;
	struct pre_ld_rx_pool *rx_pool;
	struct rte_mbuf *free_burst[MAX_PKT_BURST];
	struct pre_ld_lcore_direct_list *list = NULL;
	struct rte_ring *tx_ring = NULL, *rx_ring = NULL;
	struct pre_ld_ring *pre_ld_rx_ring = NULL;
	struct fd_thread_desc *th_desc;
	struct fd_desc *desc = &s_fd_desc[sockfd];
	struct pre_ld_direct_entry *rx_entry;
	struct pre_ld_direct_entry *tx_entry;

	pthread_mutex_lock(&s_fd_mutex);

	if (desc->dp_type == FD_DP_DIRECT_TYPE) {
		rx_port = desc->dp_desc.hw_desc.rx_port;
		rxq_id = desc->dp_desc.hw_desc.rxq_id;
	} else {
		rx_entry = desc->dp_desc.entry_desc.rx_entry;
		tx_entry = desc->dp_desc.entry_desc.tx_entry;
		rx_port = rx_entry->poll.poll_port.port_id;
		rxq_id = rx_entry->poll.poll_port.queue_id;
		if (rx_entry->dest_type == RX_RING)
			rx_ring = rx_entry->dest.rx_ring;
		else
			pre_ld_rx_ring = rx_entry->dest.pre_ld_rx_ring;
		tx_ring = tx_entry->poll.tx_ring;
		list = &s_pre_ld_lists[s_data_path_core];
		pre_ld_remove_dir_list_safe(list, rx_entry);
		desc->dp_desc.entry_desc.rx_entry = NULL;
		pre_ld_remove_dir_list_safe(list, tx_entry);
		desc->dp_desc.entry_desc.tx_entry = NULL;
	}

	ret = rte_ring_enqueue(s_port_rxq_rings[rx_port], rxq_id);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s release *s_fd_desc[%d].rxq_id(%d) failed(%d)\n",
			__func__, sockfd, *rxq_id, ret);
	}

	if (desc->flow) {
again:
		ret = rte_flow_destroy(rx_port, desc->flow, NULL);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: Destroy FD[%d].flow failed(%d), times=%d\n",
				__func__, sockfd, ret, times);
		}
		if (ret == -EAGAIN && times > 0) {
			times--;
			goto again;
		}
		desc->flow = NULL;
	}

	if (pre_ld_rx_ring) {
dq_pre_ld_rxr_again:
		nb = pre_ld_ring_dq(pre_ld_rx_ring,
				(void **)free_burst, MAX_PKT_BURST);
		if (nb > 0) {
			rte_pktmbuf_free_bulk(free_burst, nb);
			goto dq_pre_ld_rxr_again;
		}
		pre_ld_ring_free(pre_ld_rx_ring);
	}

	if (rx_ring) {
dq_rxr_again:
		nb = rte_ring_dequeue_burst(rx_ring,
				(void **)free_burst, MAX_PKT_BURST, NULL);
		if (nb > 0) {
			rte_pktmbuf_free_bulk(free_burst, nb);
			goto dq_rxr_again;
		}
		rte_ring_free(rx_ring);
	}

	if (tx_ring) {
dq_txr_again:
		nb = rte_ring_dequeue_burst(tx_ring,
				(void **)free_burst, MAX_PKT_BURST, NULL);
		if (nb > 0) {
			rte_pktmbuf_free_bulk(free_burst, nb);
			goto dq_txr_again;
		}
		rte_ring_free(tx_ring);
	}

	rx_pool = &desc->rx_buffer;
	if (rx_pool->rx_bufs) {
		while (rx_pool->head != rx_pool->tail) {
			rte_pktmbuf_free(rx_pool->rx_bufs[rx_pool->head]);
			rx_pool->head = (rx_pool->head + 1) &
				(rx_pool->max_num - 1);
		}
		rte_free(desc->rx_buffer.rx_bufs);
	}

	if (desc->tx_pool) {
		rte_mempool_free(desc->tx_pool);
		desc->tx_pool = NULL;
	}

	for (i = 0; i < desc->eal_thread_nb; i++) {
		th_desc = &desc->th_desc[i];
		if (th_desc->cpu != LCORE_ID_ANY)
			eal_lcore_non_eal_release(th_desc->cpu);
		th_desc->cpu = LCORE_ID_ANY;
		if (th_desc->lcore)
			*th_desc->lcore = LCORE_ID_ANY;
	}

	memset(desc, 0, sizeof(struct fd_desc));
	desc->fd = INVALID_SOCKFD;

	pthread_mutex_unlock(&s_fd_mutex);

	return ret;
}

static void
usr_socket_force_release(void)
{
	int fd, ret;
	struct fd_desc *usr_fd;

	while (RTE_TAILQ_FIRST(&s_fd_desc_list)) {
		usr_fd = RTE_TAILQ_FIRST(&s_fd_desc_list);
		fd = usr_fd->fd;
		usr_socket_fd_remove(fd);
		if (libc_close) {
			ret = (*libc_close)(fd);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"%s Close sockfd(%d) failed(%d)\n",
					__func__, fd, ret);
			}
		}
		ret = usr_socket_fd_release(fd);
		RTE_LOG(INFO, pre_ld, "Release all: FD(%d), ret=%d\n",
			fd, ret);
	}
}

static void eal_quit(void)
{
	uint16_t portid, drain;
	int ret;
	struct pre_ld_lcore_direct_list *list;
	struct pre_ld_direct_entry *entry;

	sleep(1);
	s_pre_ld_quit = 1;

	usr_socket_force_release();

	if (s_data_path_core >= 0) {
		list = &s_pre_ld_lists[s_data_path_core];
		while (RTE_TAILQ_FIRST(list)) {
			entry = RTE_TAILQ_FIRST(list);
			pre_ld_remove_dir_list_safe(list, entry);
			rte_free(entry);
		}
	}

	ret = eal_destroy_dpaa2_mux_flow();
	if (ret) {
		RTE_LOG(INFO, pre_ld, "Destroy mux flow failed(%d)",
			ret);
	}
	RTE_ETH_FOREACH_DEV(portid) {
		if (portid == s_tx_port && rte_lcore_id() != LCORE_ID_ANY) {
drain_again:
			drain = rte_pmd_dpaa2_clean_tx_conf(portid, 0);
			if (drain)
				goto drain_again;
		}
		RTE_LOG(INFO, pre_ld, "Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"rte_eth_dev_stop: err=%d, port=%d\n",
				ret, portid);
		}
		rte_eth_dev_close(portid);
		rte_ring_free(s_port_rxq_rings[portid]);
		s_port_rxq_rings[portid] = NULL;
		rte_ring_free(s_port_txq_rings[portid]);
		s_port_txq_rings[portid] = NULL;
		rte_log(RTE_LOG_INFO, RTE_LOGTYPE_pre_ld, "done.\n");
	}

	pre_ld_free_crypt_queue_ring();

	/* clean up the EAL */
	rte_eal_cleanup();
	RTE_LOG(INFO, pre_ld, "Bye...\n");
}

static int
eal_data_path_thread_register(struct fd_desc *desc)
{
	int ret, new_cpu, lcore, i;
	uint32_t cpu;
	rte_cpuset_t cpuset;
	struct fd_thread_desc *th_desc;
	pthread_t thread;

	if (!desc->eal_thread)
		return 0;

	thread = pthread_self();
	cpu = sched_getcpu();
	for (i = 0; i < desc->eal_thread_nb; i++) {
		th_desc = &desc->th_desc[i];
		if (likely((th_desc->cpu == cpu &&
			thread == th_desc->thread) ||
			thread == s_main_td))
			return 0;
	}

register_again:
	ret = rte_thread_register();
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Register thread(%ld) of FD(%d) Failed(%d)\n",
			pthread_self(), desc->fd, ret);
		return ret;
	}

	lcore = rte_lcore_id();
	if (lcore == SYS_CORE_ID ||
		lcore == s_data_path_core) {
		RTE_LOG(WARNING, pre_ld,
			"Skip core%d = sys core(%d) or data core(%d)\n",
			lcore, SYS_CORE_ID, s_data_path_core);
		goto register_again;
	}
	CPU_ZERO(&cpuset);
	CPU_SET(rte_lcore_id(), &cpuset);
	ret = pthread_setaffinity_np(pthread_self(),
		sizeof(cpu_set_t), &cpuset);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Set affinity(TD(%ld) FD(%d)) Failed(%d)\n",
			pthread_self(), desc->fd, ret);
		return ret;
	}
	new_cpu = sched_getcpu();
	if (new_cpu != (int)rte_lcore_id()) {
		RTE_LOG(ERR, pre_ld,
			"Register thread(%ld) of FD(%d) cpu(%d) != RTE cpu(%d)\n",
			pthread_self(), desc->fd, new_cpu, rte_lcore_id());

		return -EINVAL;
	}

	pthread_mutex_lock(&s_fd_mutex);
	if (desc->eal_thread_nb >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, pre_ld,
			"Too many threads allocated for FD(%d)\n",
			desc->fd);
		pthread_mutex_unlock(&s_fd_mutex);

		return -EINVAL;
	}
	th_desc = &desc->th_desc[desc->eal_thread_nb];
	th_desc->cpu = new_cpu;
	th_desc->thread = pthread_self();
	th_desc->lcore = &RTE_PER_LCORE(_lcore_id);
	desc->eal_thread_nb++;
	RTE_LOG(INFO, pre_ld,
		"Register %d thread(s)(%ld) of FD(%d) from cpu(%d) to cpu(%d)\n",
		desc->eal_thread_nb, pthread_self(),
		desc->fd, cpu, new_cpu);
	pthread_mutex_unlock(&s_fd_mutex);

	return 0;
}

static int
pre_ld_adjust_rx_l4_info(int sockfd, struct rte_mbuf *mbuf)
{
	int ret;
	uint8_t l4_offset = 0;
	struct rte_udp_hdr *udp_hdr;
	uint16_t length;
	struct pre_ld_udp_desc *desc;
	struct rte_udp_hdr *flow_hdr = &s_fd_desc[sockfd].hdr.udp_hdr;

	ret = rte_pmd_dpaa2_rx_get_offset(mbuf,
			NULL, &l4_offset, NULL);
	if (unlikely(ret))
		return ret;

	if (unlikely(l4_offset != offsetof(struct eth_ipv4_udp_hdr,
		udp_hdr))) {
		RTE_LOG(WARNING, pre_ld,
			"FD(%d): UDP offset = %d, IPV6 or tunnel frame?\n",
			sockfd, l4_offset);
		rte_pktmbuf_dump(stdout, mbuf, 60);
		return -EINVAL;
	}

	udp_hdr = rte_pktmbuf_mtod_offset(mbuf, void *, l4_offset);
	if (unlikely(udp_hdr->src_port != flow_hdr->dst_port ||
		udp_hdr->dst_port != flow_hdr->src_port)) {
		RTE_LOG(WARNING, pre_ld,
			"FD(%d): UDP RX ERR(src %04x!=%04x, dst %04x!=%04x)\n",
			sockfd, udp_hdr->src_port, flow_hdr->dst_port,
			udp_hdr->dst_port, flow_hdr->src_port);
		rte_pktmbuf_dump(stdout, mbuf, 60);
		return -EINVAL;
	}
	length = rte_be_to_cpu_16(udp_hdr->dgram_len) -
		sizeof(struct rte_udp_hdr);
	desc = (struct pre_ld_udp_desc *)udp_hdr - 1;
	desc->offset = sizeof(struct pre_ld_udp_desc) +
		sizeof(struct rte_udp_hdr);
	desc->length = length;
	mbuf->data_off = (uint16_t)((uint8_t *)desc -
		(uint8_t *)mbuf->buf_addr);

	return 0;
}

static int
recv_frame_available(int sockfd)
{
	RTE_SET_USED(sockfd);

	return true;
}

static int
eal_recv(int sockfd, void *buf, size_t len, int flags)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *free_burst[MAX_PKT_BURST];
	struct rte_mbuf *mbuf;
	uint32_t nb_rx = 0, i, total_bytes = 0, j;
	size_t length, remain = len;
	struct pre_ld_udp_desc *udp_desc;
	int ret;
	uint8_t *buf_u8 = buf, *pkt;
	struct fd_desc *desc = &s_fd_desc[sockfd];
	struct pre_ld_rx_pool *rx_pool = &desc->rx_buffer;
	struct pre_ld_direct_entry *rx_entry;
	struct fd_hw_desc *hw_desc;

	RTE_SET_USED(flags);

	ret = eal_data_path_thread_register(desc);
	if (ret)
		return ret;

	i = 0;
	while (rx_pool->head != rx_pool->tail &&
		total_bytes < len) {
		mbuf = rx_pool->rx_bufs[rx_pool->head];
		udp_desc = rte_pktmbuf_mtod(mbuf, void *);
		length = udp_desc->length;
		pkt = ((uint8_t *)udp_desc + udp_desc->offset);
		if (length <= remain) {
			rte_memcpy(&buf_u8[total_bytes], pkt, length);
			desc->rx_stat.usr_bytes += length;
			remain -= length;
			total_bytes += length;
			free_burst[i] = mbuf;
			i++;
			rx_pool->rx_bufs[rx_pool->head] = NULL;
			rx_pool->head = (rx_pool->head + 1) &
				(rx_pool->max_num - 1);
		} else {
			rte_memcpy(&buf_u8[total_bytes], pkt, remain);
			desc->rx_stat.usr_bytes += remain;
			total_bytes += remain;
			udp_desc->offset += remain;
			udp_desc->length -= remain;
			remain = 0;
		}
		if (i == MAX_PKT_BURST) {
			rte_pktmbuf_free_bulk(free_burst, i);
			i = 0;
		}
	}

	if (i > 0)
		rte_pktmbuf_free_bulk(free_burst, i);

	if (!remain)
		goto finsh_recv;

	if (desc->dp_type == FD_DP_IN_DIRECT_TYPE) {
		rx_entry = desc->dp_desc.entry_desc.rx_entry;
		if (unlikely(!rx_entry)) {
			/** FD close*/
			goto finsh_recv;
		}
		if (rx_entry->dest_type == RX_RING) {
			nb_rx = rte_ring_dequeue_burst(rx_entry->dest.rx_ring,
				(void **)pkts_burst, MAX_PKT_BURST, NULL);
		} else {
			nb_rx = pre_ld_ring_dq(rx_entry->dest.pre_ld_rx_ring,
				(void **)pkts_burst, MAX_PKT_BURST);
		}
	} else {
		hw_desc = &desc->dp_desc.hw_desc;
		nb_rx = rte_eth_rx_burst(hw_desc->rx_port,
				*hw_desc->rxq_id, pkts_burst, MAX_PKT_BURST);
	}
	for (i = 0; i < nb_rx; i++) {
		desc->rx_stat.oh_bytes +=
			pkts_burst[i]->pkt_len +
			RTE_TM_ETH_FRAMING_OVERHEAD_FCS;
	}
	desc->rx_stat.pkts += nb_rx;
	desc->rx_stat.count++;
	if (!nb_rx)
		goto finsh_recv;
	j = 0;
	for (i = 0; i < nb_rx; i++) {
		ret = pre_ld_adjust_rx_l4_info(sockfd, pkts_burst[i]);
		if (unlikely(ret))
			break;
		udp_desc = rte_pktmbuf_mtod(pkts_burst[i], void *);
		pkt = (uint8_t *)udp_desc + udp_desc->offset;
		length = udp_desc->length;
		if (remain >= length) {
			rte_memcpy(&buf_u8[total_bytes], pkt, length);
			desc->rx_stat.usr_bytes += length;
			remain -= length;
			total_bytes += length;
			free_burst[j] = pkts_burst[i];
			j++;
		} else {
			rte_memcpy(&buf_u8[total_bytes], pkt, remain);
			desc->rx_stat.usr_bytes += remain;
			remain = 0;
			total_bytes += remain;
			udp_desc->offset += remain;
			udp_desc->length -= remain;
			rx_pool->rx_bufs[rx_pool->tail] = pkts_burst[i];
			rx_pool->tail = (rx_pool->tail + 1) &
				(rx_pool->max_num - 1);
			i++;

			break;
		}
	}
	rte_pktmbuf_free_bulk(free_burst, j);
	while (i != nb_rx) {
		if (unlikely(((rx_pool->tail + 1) &
			(rx_pool->max_num - 1)) == rx_pool->head)) {
			RTE_LOG(ERR, pre_ld,
				"RX pool is too small?\n");
			rte_pktmbuf_free_bulk(&pkts_burst[i], nb_rx - i);
			break;
		}
		/** Remove Header.*/
		ret = pre_ld_adjust_rx_l4_info(sockfd, pkts_burst[i]);
		if (unlikely(ret))
			break;
		rx_pool->rx_bufs[rx_pool->tail] = pkts_burst[i];
		rx_pool->tail = (rx_pool->tail + 1) &
			(rx_pool->max_num - 1);
		i++;
	}

finsh_recv:

	return total_bytes;
}

static void
eal_send_fill_mbufs(int fd, const uint8_t *buf, uint16_t lens[],
	struct rte_mbuf *mbufs[], uint16_t count)
{
	void *udp_data;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_udp_hdr *udp_hdr;
	uint16_t i;
	struct rte_mbuf *m;

	for (i = 0; i < count; i++) {
		m = mbufs[i];
		m->data_off = PRE_LD_MBUF_OFFSET;

		/* Initialize the Ethernet header */
		eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

		rte_memcpy(eth_hdr, &s_fd_desc[fd].hdr,
			sizeof(struct eth_ipv4_udp_hdr));
		/* Set IP header length then calculate checksum.*/
		ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		ip_hdr->total_length = rte_cpu_to_be_16(lens[i] + IPv4_HDR_LEN);
		ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

		/* Set UDP header length only*/
		udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
		udp_hdr->dgram_len = rte_cpu_to_be_16(lens[i] + UDP_HDR_LEN);

		udp_data = (void *)(udp_hdr + 1);
		rte_memcpy(udp_data, buf, lens[i]);
		m->nb_segs = 1;
		m->next = NULL;
		m->data_len = lens[i] + RTE_ETHER_HDR_LEN + IPv4_HDR_LEN;
		if (m->data_len < (RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN))
			m->data_len = (RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN);
		m->pkt_len = m->data_len;
		m->packet_type = RTE_PTYPE_L2_ETHER |
			RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP;
		buf += lens[i];
	}
}

static int
eal_send(int sockfd, const void *buf, size_t len, int flags)
{
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	uint16_t lens[MAX_PKT_BURST];
	int sent = 0, i, ret;
	uint16_t mtu, max_len, hdr_len, count = 0;
	struct rte_mempool *pool;
	struct pre_ld_direct_entry *tx_entry;
	struct fd_hw_desc *hw_desc;
	struct fd_desc *desc = &s_fd_desc[sockfd];

	RTE_SET_USED(sockfd);
	RTE_SET_USED(flags);

	if (s_tx_from_rx_pool)
		pool = s_pre_ld_rx_pool;
	else
		pool = desc->tx_pool;

	ret = eal_data_path_thread_register(desc);
	if (ret)
		return 0;

	ret = 0;
	mtu = desc->tx_port_mtu;
	max_len = mtu + RTE_ETHER_HDR_LEN;
	hdr_len = RTE_ETHER_HDR_LEN + IPv4_HDR_LEN;
	if (pre_ld_sp_out_ready())
		hdr_len += IPv4_ESP_HDR_LEN + ESP_TAIL_MAX_LEN;
	while ((len + hdr_len) > max_len) {
		if (unlikely(count >= MAX_PKT_BURST))
			break;

		lens[count] = (max_len - hdr_len);
		len -= lens[count];
		count++;
	}
	if (len > 0 && count < MAX_PKT_BURST) {
		lens[count] = len;
		count++;
	}
	ret = rte_pktmbuf_alloc_bulk(pool, mbufs, count);
	if (ret)
		return 0;

	eal_send_fill_mbufs(sockfd, buf, lens, mbufs, count);

	if (desc->dp_type == FD_DP_IN_DIRECT_TYPE) {
		tx_entry = desc->dp_desc.entry_desc.tx_entry;
		if (unlikely(!tx_entry)) {
			/** FD close*/
			goto quit_send;
		}
		sent = rte_ring_enqueue_bulk(tx_entry->poll.tx_ring,
			(void * const *)mbufs, count, NULL);
	} else {
		hw_desc = &desc->dp_desc.hw_desc;
		sent = rte_eth_tx_burst(hw_desc->tx_port,
			0, mbufs, count);
	}
	ret = 0;
	for (i = 0; i < sent; i++) {
		desc->tx_stat.usr_bytes += lens[i];
		desc->tx_stat.oh_bytes +=
			lens[i] + RTE_TM_ETH_FRAMING_OVERHEAD_FCS;
		ret += lens[i];
	}
	desc->tx_stat.pkts += sent;
	desc->tx_stat.count += sent;

quit_send:
	if (sent < count)
		rte_pktmbuf_free_bulk(&mbufs[sent], count - sent);

	return ret;
}

void
pre_ld_deconfigure_sec_path(struct pre_ld_ipsec_sp_entry *sp)
{
	struct pre_ld_lcore_direct_list *list;
	uint16_t *queue_id, rx_port, sec_id;
	uint16_t *sec_qid;
	char src_info[128], sec_info[128], dst_info[128];
	int ret;
	struct pre_ld_direct_entry *entry_to_sec;
	struct pre_ld_direct_entry *entry_from_sec;

	list = &s_pre_ld_lists[s_data_path_core];
	entry_to_sec = sp->entry_to_sec;
	entry_from_sec = sp->entry_from_sec;
	sp->entry_to_sec = NULL;
	sp->entry_from_sec = NULL;
	rx_port = entry_to_sec->poll.poll_port.port_id;
	queue_id = entry_to_sec->poll.poll_port.queue_id;
	sec_id = entry_to_sec->dest.dest_sec.sec_id;
	sec_qid = entry_to_sec->dest.dest_sec.queue_id;
	sprintf(src_info, "Port%d/rxq%d", rx_port, *queue_id);
	sprintf(sec_info, "Sec%d/queue%d", sec_id, *sec_qid);
	pre_ld_remove_dir_list_safe(list, entry_to_sec);
	/** Drain outstanding  SEC queue.*/
	usleep(100000);
	ret = rte_ring_enqueue(s_port_rxq_rings[rx_port], queue_id);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s: Free queue(%d) to %s failed(%d)\n",
			__func__, *queue_id,
			s_port_rxq_rings[rx_port]->name, ret);
	}
	sprintf(dst_info, "Port%d", entry_from_sec->dest.dest_port);
	pre_ld_remove_dir_list_safe(list, entry_from_sec);

	RTE_ASSERT(sec_id ==
		entry_from_sec->poll.poll_sec.sec_id);
	RTE_ASSERT(sec_qid ==
		entry_from_sec->poll.poll_sec.queue_id);
	ret = rte_ring_enqueue(s_crypt_queue_ring[sec_id], sec_qid);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s: Free queue(%d) to %s failed(%d)\n",
			__func__, *sec_qid,
			s_crypt_queue_ring[sec_id]->name, ret);
	}

	rte_free(entry_to_sec);
	rte_free(entry_from_sec);

	RTE_LOG(INFO, pre_ld, "Remove %s -> %s -> %s\n",
		src_info, sec_info, dst_info);
}

int
pre_ld_configure_sec_path(struct pre_ld_ipsec_sp_entry *sp)
{
	struct pre_ld_lcore_direct_list *list;
	uint16_t lcore_id, rx_port, tx_port;
	struct pre_ld_direct_entry *dir_to_sec;
	struct pre_ld_direct_entry *dir_from_sec;
	struct pre_ld_sp_node *sp_node;
	enum pre_ld_dir_dest_type dest_type;
	enum pre_ld_dir_poll_type poll_type;
	uint16_t *rxq_id, *crypt_qid;
	int ret;

	if (s_data_path_core < 0) {
		rte_exit(EXIT_FAILURE,
			"Data path code not specified!\n");

		return -EINVAL;
	}

	if (sp->dir == XFRM_POLICY_IN) {
		rx_port = s_dir_ports.dl_id;
		tx_port = s_dir_ports.ul_id;
		dest_type = SEC_INGRESS;
		poll_type = SEC_IN_COMPLETE;
	} else if (sp->dir == XFRM_POLICY_OUT) {
		rx_port = s_dir_ports.ul_id;
		tx_port = s_dir_ports.ext_id;
		dest_type = SEC_EGRESS;
		poll_type = SEC_EG_COMPLETE;
	} else {
		return -EINVAL;
	}

	lcore_id = s_data_path_core;
	list = &s_pre_ld_lists[lcore_id];
	dir_to_sec = rte_zmalloc(NULL,
		sizeof(struct pre_ld_direct_entry), 0);
	if (!dir_to_sec) {
		rte_exit(EXIT_FAILURE,
			"%s/line%d: data path alloc failed\n",
			__func__, __LINE__);

		return -ENOMEM;
	}
	sp_node = rte_zmalloc(NULL, sizeof(struct pre_ld_sp_node), 0);
	if (!sp_node) {
		rte_free(dir_to_sec);
		rte_exit(EXIT_FAILURE,
			"%s/line%d: sp node alloc failed\n",
			__func__, __LINE__);

		return -ENOMEM;
	}
	sp_node->sp = sp;
	sp_node->next = NULL;

	ret = rte_ring_dequeue(s_port_rxq_rings[rx_port],
		(void **)&rxq_id);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"No RXQ available from ring(%s)\n",
			s_port_rxq_rings[rx_port]->name);
		rte_free(dir_to_sec);

		return ret;
	}

	ret = rte_ring_dequeue(s_crypt_queue_ring[sp->crypt_id],
		(void **)&crypt_qid);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"No crypt queue available from ring(%s)\n",
			s_crypt_queue_ring[sp->crypt_id]->name);
		rte_ring_enqueue(s_port_rxq_rings[rx_port],
			rxq_id);
		rte_free(dir_to_sec);

		return ret;
	}

	dir_to_sec->poll_type = RX_QUEUE;
	dir_to_sec->poll.poll_port.port_id = rx_port;
	dir_to_sec->poll.poll_port.queue_id = rxq_id;
	dir_to_sec->poll.poll_port.flow = sp->flow;
	dir_to_sec->dest_type = dest_type;

	dir_to_sec->dest.dest_sec.queue_id = crypt_qid;
	dir_to_sec->dest.dest_sec.sec_id = sp->crypt_id;
	dir_to_sec->dest.dest_sec.sp_list = sp_node;

	dir_from_sec = rte_zmalloc(NULL,
		sizeof(struct pre_ld_direct_entry), 0);
	if (!dir_from_sec) {
		rte_exit(EXIT_FAILURE,
			"%s/line%d: data path alloc failed\n",
			__func__, __LINE__);
		rte_ring_enqueue(s_port_rxq_rings[rx_port],
			rxq_id);
		rte_ring_enqueue(s_crypt_queue_ring[sp->crypt_id],
			crypt_qid);
		rte_free(dir_to_sec);

		return -ENOMEM;
	}

	dir_from_sec->poll.poll_sec.sp_list = NULL;
	dir_from_sec->poll_type = poll_type;
	dir_from_sec->poll.poll_sec.queue_id = crypt_qid;
	dir_from_sec->poll.poll_sec.sec_id = sp->crypt_id;

	dir_from_sec->dest_type = HW_PORT;
	dir_from_sec->dest.dest_port = tx_port;

	sp->attr.group = 0;
	sp->attr.priority = *rxq_id;
	sp->attr.ingress = 1;

	sp->entry_to_sec = dir_to_sec;
	sp->entry_from_sec = dir_from_sec;
	sp->ingress_queue.index = *rxq_id;

	pre_ld_insert_dir_list_safe(list, dir_to_sec);
	pre_ld_insert_dir_list_safe(list, dir_from_sec);

	return 0;
}

int
pre_ld_attach_sec_path(struct pre_ld_ipsec_sp_entry *sp)
{
	struct pre_ld_lcore_direct_list *list;
	struct pre_ld_direct_entry *entry, *tentry, *found = NULL;
	struct pre_ld_sp_node *curr, *prev, *sp_node;
	enum pre_ld_dir_poll_type poll_type;
	uint16_t lcore_id, sec_id, *queue_id;

	if (s_data_path_core < 0) {
		rte_exit(EXIT_FAILURE,
			"Data path code not specified!\n");

		return -EINVAL;
	}
	lcore_id = s_data_path_core;
	list = &s_pre_ld_lists[lcore_id];

	RTE_TAILQ_FOREACH_SAFE(entry, list, next, tentry) {
		if (entry->poll_type == RX_QUEUE &&
			entry->poll.poll_port.flow == sp->flow) {
			found = entry;
			break;
		}
	}

	if (!found)
		return -EACCES;

	curr = found->dest.dest_sec.sp_list;
	prev = NULL;
	while (curr) {
		prev = curr;
		curr = curr->next;
	}
	if (!prev) {
		RTE_LOG(ERR, pre_ld, "%s: No SP on SEC path\n",
			__func__);
		return -EINVAL;
	}
	sp_node = rte_malloc(NULL, sizeof(struct pre_ld_sp_node), 0);
	if (!sp_node)
		return -ENOMEM;
	sp_node->sp = sp;
	sp_node->next = NULL;

	prev->next = sp_node;

	sp->entry_to_sec = found;
	poll_type = sp->dir == XFRM_POLICY_IN ?
		SEC_IN_COMPLETE : SEC_EG_COMPLETE;
	sec_id = found->dest.dest_sec.sec_id;
	queue_id = found->dest.dest_sec.queue_id;
	found = NULL;
	RTE_TAILQ_FOREACH_SAFE(entry, list, next, tentry) {
		if (entry->poll_type == poll_type &&
			entry->poll.poll_sec.sec_id == sec_id &&
			entry->poll.poll_sec.queue_id == queue_id) {
			found = entry;
			break;
		}
	}
	sp->entry_from_sec = found;

	return 0;
}

int
pre_ld_detach_sec_path(struct pre_ld_ipsec_sp_entry *sp)
{
	struct pre_ld_sp_node *curr, *prev;

	if (!sp->entry_to_sec)
		return -EACCES;

	curr = sp->entry_to_sec->dest.dest_sec.sp_list;
	prev = NULL;
	while (curr) {
		if (curr->sp == sp)
			break;
		prev = curr;
		curr = curr->next;
	}
	if (!curr) {
		RTE_LOG(ERR, pre_ld, "%s: No SP found on SEC path\n",
			__func__);
		return -EINVAL;
	}
	if (prev)
		prev->next = curr->next;
	else
		sp->entry_to_sec->dest.dest_sec.sp_list = curr->next;

	/** Drain outstanding  SEC queue.*/
	usleep(100000);

	if (!sp->entry_to_sec->dest.dest_sec.sp_list) {
		RTE_LOG(WARNING, pre_ld,
			"%s: SEC path should be deconfigured\n",
			__func__);
	}
	rte_free(curr);

	return 0;
}

static struct rte_flow *
pre_ld_configure_default_flow(uint16_t portid,
	uint16_t group, uint16_t priority)
{
	struct rte_flow_attr flow_attr;
	struct rte_flow_item flow_item[2];
	struct rte_flow_action flow_action[2];
	struct rte_flow_action_queue rxq;
	struct rte_flow *flow = NULL;
	int ret;

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	flow_attr.group = group;
	flow_attr.priority = priority;
	flow_attr.ingress = 1;
	flow_attr.egress = 0;

	flow_item[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	flow_item[0].spec = NULL;
	flow_item[0].mask = NULL;
	flow_item[0].last = NULL;
	flow_item[1].type = RTE_FLOW_ITEM_TYPE_END;

	flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	rxq.index = priority;
	flow_action[0].conf = &rxq;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
	ret = rte_flow_validate(portid, &flow_attr, flow_item,
		flow_action, NULL);
	if (ret) {
		RTE_LOG(ERR, pre_ld, "%s: flow validate failed(%d)",
			__func__, ret);
		return NULL;
	}
	flow = rte_flow_create(portid, &flow_attr, flow_item,
		flow_action, NULL);
	if (!flow) {
		RTE_LOG(ERR, pre_ld, "%s: flow create failed", __func__);

		return NULL;
	}

	return flow;
}

static inline void
pre_ld_add_port_dir_entry(struct pre_ld_lcore_direct_list *list,
	uint16_t from_id, uint16_t to_id, uint16_t *rxq_id)
{
	struct pre_ld_direct_entry *entry;

	entry = rte_zmalloc(NULL, sizeof(struct pre_ld_direct_entry), 0);
	if (!entry)
		rte_panic("Data path alloc failed\n");

	entry->poll_type = RX_QUEUE;
	entry->poll.poll_port.port_id = from_id;
	entry->poll.poll_port.queue_id = rxq_id;
	entry->dest_type = HW_PORT;
	entry->dest.dest_port = to_id;
	pre_ld_insert_dir_list_safe(list, entry);
}

static inline struct rte_flow *
pre_ld_sw_default_direct(struct pre_ld_lcore_direct_list *lcore,
	uint16_t *prio, uint16_t from_id, uint16_t to_id)
{
	struct rte_flow *flow;

	pre_ld_add_port_dir_entry(lcore, from_id, to_id, prio);
	flow = pre_ld_configure_default_flow(from_id,
		DEFAULT_DIRECT_GROUP, *prio);

	return flow;
}

static inline void
pre_ld_def_dir_add(const char *from_nm,
	const char *to_nm, uint16_t from_id, uint16_t to_id,
	uint16_t prio, struct rte_flow *flow)
{
	if (!s_pre_ld_def_dir.def_dir)
		s_pre_ld_def_dir.def_dir = s_def_dir;

	strcpy(s_pre_ld_def_dir.def_dir[s_def_dir_num].from_name,
		from_nm);
	strcpy(s_pre_ld_def_dir.def_dir[s_def_dir_num].to_name,
		to_nm);
	s_pre_ld_def_dir.from_ids[s_def_dir_num] = from_id;
	s_pre_ld_def_dir.to_ids[s_def_dir_num] = to_id;
	s_pre_ld_def_dir.prios[s_def_dir_num] = prio;
	s_pre_ld_def_dir.flows[s_def_dir_num] = flow;
	s_def_dir_num++;
}

static void
pre_ld_build_def_direct_traffic(struct pre_ld_lcore_direct_list *lcore,
	const char *from_nm, const char *to_nm,
	uint16_t from_id, uint16_t to_id)
{
	struct rte_flow *flow;

	if (rte_pmd_dpaa2_dev_is_dpaa2(from_id)) {
		if (s_dump_traffic_flow) {
			flow = pre_ld_sw_default_direct(lcore,
					&s_def_rxq[from_id], from_id, to_id);
		} else {
			flow = rte_remote_default_direct(from_nm,
					to_nm, NULL, DEFAULT_DIRECT_GROUP,
					s_def_rxq[from_id]);
		}
	} else {
		flow = NULL;
		pre_ld_add_port_dir_entry(lcore, from_id, to_id,
			&s_def_rxq[from_id]);
	}
	pre_ld_def_dir_add(from_nm, to_nm, from_id, to_id,
		s_def_rxq[from_id], flow);
}

static void
pre_ld_configure_direct_traffic(uint16_t ext_id,
	uint16_t ul_id, uint16_t dl_id, uint16_t tap_id)
{
	uint16_t lcore_id;
	struct pre_ld_lcore_direct_list *lcore;
	char ext_nm[RTE_ETH_NAME_MAX_LEN];
	char ul_nm[RTE_ETH_NAME_MAX_LEN];
	char dl_nm[RTE_ETH_NAME_MAX_LEN];
	char tap_nm[RTE_ETH_NAME_MAX_LEN];

	rte_eth_dev_get_name_by_port(ext_id, ext_nm);
	rte_eth_dev_get_name_by_port(ul_id, ul_nm);
	rte_eth_dev_get_name_by_port(dl_id, dl_nm);
	rte_eth_dev_get_name_by_port(tap_id, tap_nm);

	if (s_data_path_core < 0)
		rte_exit(EXIT_FAILURE, "No data path core available\n");
	lcore_id = s_data_path_core;

	lcore = &s_pre_ld_lists[lcore_id];
	pre_ld_build_def_direct_traffic(lcore, dl_nm, tap_nm,
		dl_id, tap_id);
	pre_ld_build_def_direct_traffic(lcore, tap_nm, dl_nm,
		tap_id, dl_id);
	pre_ld_build_def_direct_traffic(lcore, ext_nm, ul_nm,
		ext_id, ul_id);
	pre_ld_build_def_direct_traffic(lcore, ul_nm, ext_nm,
		ul_id, ext_id);
}

static const char *
pre_ld_get_tap_kernel_if_nm(const char *peer_name)
{
	char dir_nm[512];
	DIR *dir;
	char *dup_nm;
	struct dirent *entry;

	sprintf(dir_nm,
		"/sys/bus/fsl-mc/drivers/fsl_mc_dprc/dprc.1/%s/net",
		peer_name);
	dir = opendir(dir_nm);
	if (!dir) {
		RTE_LOG(ERR, pre_ld, "Unable open directory(%s)\n",
			dir_nm);

		return NULL;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.' || entry->d_type != DT_DIR)
			continue;

		dup_nm = strdup(entry->d_name);
		closedir(dir);
		return dup_nm;
	}

	closedir(dir);
	return NULL;
}

static void
pre_ld_configure_split_traffic(uint32_t portid)
{
	const char *ep_name;
	const char *def_ep_name;
	int ret, id = -1, ep_id = -1;
	uint16_t mux_def_id;
	struct rte_remote_query_rsp rsp;

	ep_name = rte_pmd_dpaa2_ep_name(portid);
	if (!ep_name)
		return;

	ret = rte_remote_mux_parse_ep_name(ep_name,
			NULL, &id, NULL, &ep_id);
	if (!ret) {
		if (s_dpdmux_ep_name) {
			RTE_LOG(WARNING, pre_ld,
				"Multiple dpdmux ep names(%s)(%s) detected.\n",
				s_dpdmux_ep_name, ep_name);
		}
		s_dpdmux_ep_name = ep_name;
		s_dpdmux_id = id;
		s_dpdmux_ep_id = ep_id;
		if (!s_slow_if &&
			!rte_pmd_dpaa2_mux_default_id(id, &mux_def_id) &&
			!rte_pmd_dpaa2_mux_ep_name(id, mux_def_id, &def_ep_name)) {
			s_slow_if = pre_ld_get_tap_kernel_if_nm(def_ep_name);
			if (s_slow_if) {
				RTE_LOG(INFO, pre_ld,
					"Found tap port(%s)(%s) connected to dpdmux%d.%d\n",
					s_slow_if, def_ep_name, id, mux_def_id);
			}
		}

		return;
	}

	ret = remote_direct_query(&rsp);
	if (!ret) {
		if (!s_downlink) {
			s_downlink = rte_malloc(NULL,
				RTE_ETH_NAME_MAX_LEN, 0);
			strcpy(s_downlink, rsp.downlink_nm);
		}
		if (!s_uplink) {
			s_uplink = rte_malloc(NULL,
				RTE_ETH_NAME_MAX_LEN, 0);
			strcpy(s_uplink, rsp.uplink_nm);
		}
		if (!s_slow_if)
			s_slow_if = pre_ld_get_tap_kernel_if_nm(rsp.taplink_end_nm);

		if (s_slow_if) {
			RTE_LOG(INFO, pre_ld,
				"Found tap port(%s)(%s) connected to %s\n",
				s_slow_if, rsp.taplink_end_nm, rsp.taplink_nm);
		}
	}
}

static inline struct rte_ipsec_session *
pre_ld_ipsec_sa_2_session(struct pre_ld_ipsec_sa_entry *sa)
{
	return &sa->session;
}

static inline enum rte_security_session_action_type
pre_ld_ipsec_sa_2_action(struct pre_ld_ipsec_sa_entry *sa)
{
	struct rte_ipsec_session *ips;

	ips = pre_ld_ipsec_sa_2_session(sa);
	return ips->type;
}

static inline int
pre_ld_ipsec_dequeue(struct rte_mbuf *pkts[], uint16_t max_pkts,
	uint16_t dev_id, uint16_t c_qp)
{
	int32_t nb_pkts = 0, j, nb_cops;
	struct rte_crypto_op *cops[max_pkts];
	struct rte_mbuf *pkt;
	struct rte_mbuf *free_mbufs[max_pkts];
	struct pre_ld_ipsec_priv *src_priv, *dst_priv;

	nb_cops = rte_cryptodev_dequeue_burst(dev_id,
		c_qp, cops, max_pkts);

	for (j = 0; j < nb_cops; j++) {
		if (s_ipsec_buf_swap) {
			pkt = cops[j]->sym->m_dst;
			dst_priv = rte_mbuf_to_priv(pkt);
			src_priv = rte_mbuf_to_priv(cops[j]->sym->m_src);
			rte_memcpy(dst_priv->cntx, src_priv->cntx,
				sizeof(struct rte_ether_hdr));
			free_mbufs[j] = cops[j]->sym->m_src;
		} else {
			pkt = cops[j]->sym->m_src;
		}

		if (unlikely(cops[j]->status)) {
			rte_pktmbuf_free(pkt);
			continue;
		}

		pkts[nb_pkts++] = pkt;
	}

	if (s_ipsec_buf_swap)
		rte_pktmbuf_free_bulk(free_mbufs, nb_cops);

	/* return packets */
	return nb_pkts;
}

static inline int
pre_ld_ipaddr_sp_cmp(const xfrm_address_t *src,
	const xfrm_address_t *dst, uint16_t family,
	struct pre_ld_ipsec_sp_entry *sp)
{
	uint16_t size = 0;

	if (family == AF_INET)
		size = sizeof(rte_be32_t);
	else if (family == AF_INET6)
		size = sizeof(xfrm_address_t);
	else
		return false;

	if (!memcmp(&sp->src, src, size) &&
		!memcmp(&sp->dst, dst, size))
		return true;

	return false;
}

static inline void
pre_ld_adjust_ipv4_pktlen(struct rte_mbuf *m,
	const struct rte_ipv4_hdr *iph, uint32_t l2_len)
{
	uint32_t plen, trim;

	plen = rte_be_to_cpu_16(iph->total_length) + l2_len;
	if (plen < m->pkt_len) {
		trim = m->pkt_len - plen;
		rte_pktmbuf_trim(m, trim);
	}
}

static void
pre_ld_adjust_ipv4(struct rte_mbuf *pkt,
	enum pre_ld_crypto_dir dir)
{
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *iph4;
	struct pre_ld_ipsec_priv *priv;

	priv = rte_mbuf_to_priv(pkt);
	if (dir == INGRESS_CRYPTO_EQ || dir == EGRESS_CRYPTO_EQ) {
		eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		rte_memcpy(priv->cntx, eth, sizeof(struct rte_ether_hdr));

		iph4 = (void *)rte_pktmbuf_adj(pkt, RTE_ETHER_HDR_LEN);
		pre_ld_adjust_ipv4_pktlen(pkt, iph4, 0);

		pkt->l2_len = 0;
		pkt->l3_len = sizeof(*iph4);
	} else if (dir == INGRESS_CRYPTO_DQ || dir == EGRESS_CRYPTO_DQ) {
		iph4 = rte_pktmbuf_mtod(pkt, void *);
		rte_memcpy((char *)iph4 - sizeof(struct rte_ether_hdr),
				priv->cntx, sizeof(struct rte_ether_hdr));
		pkt->data_off -= sizeof(struct rte_ether_hdr);
		pkt->pkt_len += sizeof(struct rte_ether_hdr);
		pkt->data_len += sizeof(struct rte_ether_hdr);
	} else {
		RTE_LOG(ERR, pre_ld, "Invalid IPSec dir(%d)\n", dir);
	}
}

static inline uint16_t
pre_ld_ipsec_sa_enqueue(struct rte_mbuf *pkts[],
	void *sas, uint16_t nb_pkts,
	uint16_t crypto_id, uint16_t qp)
{
	int i, ret;
	struct pre_ld_ipsec_priv *priv;
	struct pre_ld_ipsec_sa_entry *sa = sas;
	struct rte_ipsec_session *ips = pre_ld_ipsec_sa_2_session(sa);
	struct rte_crypto_op *cops[nb_pkts];
	struct rte_mbuf *mbufs[nb_pkts];

	if (ips->type != RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL) {
		RTE_LOG(ERR, pre_ld,
			"Type(%d) not support, Lookaside support only!\n",
			ips->type);
		return 0;
	} else if (!ips->security.ses) {
		RTE_LOG(ERR, pre_ld,
			"Session has not been created!\n");
		return 0;
	}

	if (s_ipsec_buf_swap) {
		ret = rte_pktmbuf_alloc_bulk(s_pre_ld_rx_pool,
			mbufs, nb_pkts);
		if (ret)
			return 0;
	}

	for (i = 0; i < nb_pkts; i++) {
		priv = rte_mbuf_to_priv(pkts[i]);
		priv->sa = sa;

		priv->cop.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
		priv->cop.status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

		priv->sym_cop.m_src = pkts[i];
		if (s_ipsec_buf_swap)
			priv->sym_cop.m_dst = mbufs[i];
		else
			priv->sym_cop.m_dst = NULL;

		rte_security_attach_session(&priv->cop, ips->security.ses);

		cops[i] = &priv->cop;
	}

	return rte_cryptodev_enqueue_burst(crypto_id,
			qp, cops, nb_pkts);
}

static void
pre_ld_pktmbuf_init(struct rte_mempool *mp,
	__rte_unused void *opaque_arg,
	void *_m,
	__rte_unused uint32_t i)
{
	struct rte_mbuf *m = _m;
	uint32_t mbuf_size, buf_len, priv_size;

	RTE_ASSERT(mp->private_data_size >=
		   sizeof(struct rte_pktmbuf_pool_private));

	priv_size = rte_pktmbuf_priv_size(mp);
	mbuf_size = sizeof(struct rte_mbuf) + priv_size;
	buf_len = rte_pktmbuf_data_room_size(mp);

	RTE_ASSERT(RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) == priv_size);
	RTE_ASSERT(mp->elt_size >= mbuf_size);
	RTE_ASSERT(buf_len <= UINT16_MAX);

	memset(m, 0, mbuf_size);
	/* start of buffer is after mbuf structure and priv data */
	m->priv_size = priv_size;
	m->buf_addr = (char *)m + mbuf_size;
	rte_mbuf_iova_set(m, rte_mempool_virt2iova(m) + mbuf_size);
	m->buf_len = buf_len;

	/* keep some headroom between start of buffer and data */
	m->data_off = PRE_LD_MBUF_OFFSET;

	/* init some constant fields */
	m->pool = mp;
	m->nb_segs = 1;
	m->port = RTE_MBUF_PORT_INVALID;
	rte_mbuf_refcnt_set(m, 1);
	m->next = NULL;
}

static uint16_t
pre_ld_direct_to_crypto(struct pre_ld_direct_entry *entry,
	struct rte_mbuf *mbufs[], uint16_t nb_rx)
{
	uint16_t crypto_id = entry->dest.dest_sec.sec_id;
	uint16_t queueid = *entry->dest.dest_sec.queue_id;
	void *sa = NULL;
	enum pre_ld_crypto_dir dir = EGRESS_CRYPTO_EQ;
	uint16_t nb_tx = 0, i;
	struct pre_ld_ipsec_sp_entry *sp;

	if (entry->dest_type == SEC_EGRESS)
		dir = EGRESS_CRYPTO_EQ;
	else if (entry->dest_type == SEC_INGRESS)
		dir = INGRESS_CRYPTO_EQ;
	else
		return 0;

	if (likely(entry->dest.dest_sec.sp_list)) {
		sp = entry->dest.dest_sec.sp_list->sp;
		if (likely(sp && sp->sa))
			sa = sp->sa;
	}

	if (unlikely(!sa))
		return 0;

	for (i = 0; i < nb_rx; i++)
		pre_ld_adjust_ipv4(mbufs[i], dir);
	nb_tx = pre_ld_ipsec_sa_enqueue(mbufs, sa, nb_rx,
		crypto_id, queueid);

	return nb_tx;
}

static inline void
pre_ld_l3_l4_traffic_dump(struct rte_mbuf *mbuf,
	const char *prefix)
{
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *iph4;
	struct rte_ipv6_hdr *iph6;

	eth = rte_pktmbuf_mtod(mbuf, void *);

	if (s_l3_traffic_dump && !s_l4_traffic_dump) {
		if (eth->ether_type == rte_cpu_to_be_16(s_l3_traffic_dump))
			goto print_mbuf;
	} else if (!s_l3_traffic_dump && s_l4_traffic_dump) {
		if (eth->ether_type ==
			rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
			iph4 = (void *)(eth + 1);
			if (iph4->next_proto_id == s_l4_traffic_dump)
				goto print_mbuf;
		} else if (eth->ether_type ==
			rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
			iph6 = (void *)(eth + 1);
			if (iph6->proto == s_l4_traffic_dump)
				goto print_mbuf;
		}
	} else if (s_l3_traffic_dump && s_l4_traffic_dump) {
		if (s_l3_traffic_dump == RTE_ETHER_TYPE_IPV4 &&
			eth->ether_type ==
			rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
			iph4 = (void *)(eth + 1);
			if (iph4->next_proto_id == s_l4_traffic_dump)
				goto print_mbuf;
		} else if (s_l3_traffic_dump == RTE_ETHER_TYPE_IPV6 &&
			eth->ether_type ==
			rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
			iph6 = (void *)(eth + 1);
			if (iph6->proto == s_l4_traffic_dump)
				goto print_mbuf;
		}
	}

	return;

print_mbuf:
	if (s_l3_traffic_dump && !s_l4_traffic_dump) {
		RTE_LOG(INFO, pre_ld,
			"%s with l3 is 0x%04x\n",
			prefix, s_l3_traffic_dump);
	} else if (!s_l3_traffic_dump && s_l4_traffic_dump) {
		RTE_LOG(INFO, pre_ld,
			"%s with l4 is 0x%02x\n",
			prefix, s_l4_traffic_dump);
	} else if (s_l3_traffic_dump && s_l4_traffic_dump) {
		RTE_LOG(INFO, pre_ld,
			"%s with l3 is 0x%04x and l4 is 0x%02x\n",
			prefix, s_l3_traffic_dump, s_l4_traffic_dump);
	}
	rte_pktmbuf_dump(stdout, mbuf, 60);
}

static int
pre_ld_main_loop(void *dummy)
{
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	uint32_t lcore_id;
	int i, nb_rx, j, ret;
	uint16_t nb_tx, portid, queueid, crypto_id;
	struct pre_ld_lcore_direct_list *list;
	struct pre_ld_direct_entry *entry, *tentry;
	uint64_t bytes_overhead[MAX_PKT_BURST];
	char prefix[1024];

	RTE_SET_USED(dummy);

	pthread_mutex_lock(&s_dp_init_mutex);
	if (s_data_path_core >= 0) {
		RTE_LOG(ERR, pre_ld,
			"Single data path core(%d) support only\n",
			s_data_path_core);
		RTE_LOG(ERR, pre_ld,
			"Quit from core(%d)\n", rte_lcore_id());
		pthread_mutex_unlock(&s_dp_init_mutex);
		return -EINVAL;
	}
	lcore_id = rte_lcore_id();
	list = &s_pre_ld_lists[lcore_id];
	s_data_path_core = lcore_id;

	pre_ld_configure_direct_traffic(s_dir_ports.ext_id,
		s_dir_ports.ul_id, s_dir_ports.dl_id,
		s_dir_ports.tap_id);
	pthread_mutex_unlock(&s_dp_init_mutex);

	RTE_LOG(INFO, pre_ld,
		"entering main loop on lcore %u\n", lcore_id);

	ret = pre_ld_crypto_init(s_pre_ld_rx_pool);
	if (ret) {
		RTE_LOG(ERR, pre_ld, "Crypto init failed(%d)\n", ret);
		return ret;
	}

for_ever_loop:
	if (s_pre_ld_quit)
		return 0;

	RTE_TAILQ_FOREACH_SAFE(entry, list, next, tentry) {
		queueid = INVALID_QUEUEID;
		if (unlikely(entry->state != PRE_LD_DIR_ENTRY_RUNNING)) {
			if (entry->state == PRE_LD_DIR_ENTRY_STOPPING) {
				/** Delay some time to drain traffic.*/
				usleep(1000);
				entry->state = PRE_LD_DIR_ENTRY_STOPPED;
				dcbf(&entry->state);
			}
			continue;
		}

		if (entry->poll_type == RX_QUEUE) {
			portid = entry->poll.poll_port.port_id;
			queueid = *entry->poll.poll_port.queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid,
					mbufs, MAX_PKT_BURST);
			if (unlikely(s_l3_traffic_dump || s_l4_traffic_dump)) {
				sprintf(prefix, "Receive from port%d queue%d",
					portid, queueid);
				for (j = 0; j < nb_rx; j++)
					pre_ld_l3_l4_traffic_dump(mbufs[j], prefix);
			}
			if (unlikely(s_dump_traffic_flow && nb_rx > 0)) {
				RTE_LOG(INFO, pre_ld,
					"Receive from port%d queue%d\n",
					portid, queueid);
				for (j = 0; j < nb_rx; j++)
					rte_pktmbuf_dump(stdout, mbufs[j], 60);
				RTE_LOG(INFO, pre_ld,
					"Receive %d frames done\n\n", nb_rx);
			}
		} else if (entry->poll_type == TX_RING) {
			nb_rx = rte_ring_dequeue_burst(entry->poll.tx_ring,
				(void **)mbufs, MAX_PKT_BURST, NULL);
			if (unlikely(s_l3_traffic_dump || s_l4_traffic_dump)) {
				sprintf(prefix, "Receive from TX ring(%s)",
					entry->poll.tx_ring->name);
				for (j = 0; j < nb_rx; j++)
					pre_ld_l3_l4_traffic_dump(mbufs[j], prefix);
			}
			if (unlikely(s_dump_traffic_flow && nb_rx > 0)) {
				RTE_LOG(INFO, pre_ld,
					"Receive from TX ring(%s)\n",
					entry->poll.tx_ring->name);
				for (j = 0; j < nb_rx; j++)
					rte_pktmbuf_dump(stdout, mbufs[j], 60);
				RTE_LOG(INFO, pre_ld,
					"Receive %d frames done\n\n", nb_rx);
			}
		} else if (entry->poll_type == SEC_IN_COMPLETE ||
			entry->poll_type == SEC_EG_COMPLETE) {
			crypto_id = entry->poll.poll_sec.sec_id;
			queueid = *entry->poll.poll_sec.queue_id;
			nb_rx = pre_ld_ipsec_dequeue(mbufs, MAX_PKT_BURST,
				crypto_id, queueid);
			if (unlikely(!nb_rx))
				continue;
			if (entry->poll_type == SEC_IN_COMPLETE) {
				for (i = 0; i < nb_rx; i++)
					pre_ld_adjust_ipv4(mbufs[i], INGRESS_CRYPTO_DQ);
				if (unlikely(s_l3_traffic_dump || s_l4_traffic_dump)) {
					sprintf(prefix, "Ingress SEC DQ:");
					for (i = 0; i < nb_rx; i++)
						pre_ld_l3_l4_traffic_dump(mbufs[i], prefix);
				}
				if (unlikely(s_dump_traffic_flow)) {
					RTE_LOG(INFO, pre_ld, "Ingress SEC DQ:\n");
					for (i = 0; i < nb_rx; i++)
						rte_pktmbuf_dump(stdout, mbufs[i], 60);
					RTE_LOG(INFO, pre_ld,
						"Decap %d frames done\n\n",
						nb_rx);
				}
			} else if (entry->poll_type == SEC_EG_COMPLETE) {
				for (i = 0; i < nb_rx; i++)
					pre_ld_adjust_ipv4(mbufs[i], EGRESS_CRYPTO_DQ);
				if (unlikely(s_l3_traffic_dump || s_l4_traffic_dump)) {
					sprintf(prefix, "Egress SEC DQ:");
					for (i = 0; i < nb_rx; i++)
						pre_ld_l3_l4_traffic_dump(mbufs[i], prefix);
				}
				if (unlikely(s_dump_traffic_flow)) {
					RTE_LOG(INFO, pre_ld, "Egress SEC DQ:\n");
					for (i = 0; i < nb_rx; i++)
						rte_pktmbuf_dump(stdout, mbufs[i], 60);
					RTE_LOG(INFO, pre_ld,
						"Encap %d frames done\n\n",
						nb_rx);
				}
			}
		} else {
			nb_rx = 0;
		}

		if (!nb_rx)
			continue;

		if (entry->poll_type == SEC_IN_COMPLETE ||
			entry->poll_type == SEC_EG_COMPLETE) {
			for (j = 0; j < nb_rx; j++)
				entry->rx_stat.sec_bytes += mbufs[j]->pkt_len;
		} else {
			for (j = 0; j < nb_rx; j++) {
				bytes_overhead[j] = mbufs[j]->pkt_len +
					RTE_TM_ETH_FRAMING_OVERHEAD_FCS;
				entry->rx_stat.oh_bytes += bytes_overhead[j];
			}
		}
		entry->rx_stat.pkts += nb_rx;
		entry->rx_stat.count++;

		if (entry->dest_type == SEC_EGRESS ||
			entry->dest_type == SEC_INGRESS) {
			if (unlikely(s_l3_traffic_dump || s_l4_traffic_dump)) {
				sprintf(prefix, "%s SEC EQ:",
					entry->dest_type == SEC_EGRESS ?
					"Egress" : "Ingress");
				for (i = 0; i < nb_rx; i++)
					pre_ld_l3_l4_traffic_dump(mbufs[i], prefix);
			}
			if (unlikely(s_dump_traffic_flow)) {
				RTE_LOG(INFO, pre_ld, "%s SEC EQ:\n",
					entry->dest_type == SEC_EGRESS ?
					"Egress" : "Ingress");
				for (i = 0; i < nb_rx; i++)
					rte_pktmbuf_dump(stdout, mbufs[i], 60);
			}
			nb_tx = pre_ld_direct_to_crypto(entry, mbufs, nb_rx);
			if (unlikely(s_dump_traffic_flow)) {
				RTE_LOG(INFO, pre_ld,
					"%s SEC EQ %d frames done\n\n",
					entry->dest_type == SEC_EGRESS ?
					"Egress" : "Ingress", nb_tx);
			}
		} else if (entry->dest_type == HW_PORT) {
			portid = entry->dest.dest_port;
			if (unlikely(s_l3_traffic_dump || s_l4_traffic_dump)) {
				sprintf(prefix, "TX to port%d:", portid);
				for (i = 0; i < nb_rx; i++)
					pre_ld_l3_l4_traffic_dump(mbufs[i], prefix);
			}
			if (unlikely(s_dump_traffic_flow)) {
				RTE_LOG(INFO, pre_ld, "TX to port%d:\n", portid);
				for (i = 0; i < nb_rx; i++)
					rte_pktmbuf_dump(stdout, mbufs[i], 60);
			}
			nb_tx = rte_eth_tx_burst(portid, 0, mbufs, nb_rx);
			if (unlikely(s_dump_traffic_flow)) {
				RTE_LOG(INFO, pre_ld,
					"TX %d frames to port%d done\n\n",
					nb_tx, portid);
			}
		} else if (entry->dest_type == RX_RING) {
			if (unlikely(s_l3_traffic_dump || s_l4_traffic_dump)) {
				sprintf(prefix, "EQ to rx ring(%s):",
					entry->dest.rx_ring->name);
				for (i = 0; i < nb_rx; i++) {
					pre_ld_l3_l4_traffic_dump(mbufs[i],
						prefix);
				}
			}
			if (unlikely(s_dump_traffic_flow)) {
				RTE_LOG(INFO, pre_ld,
					"EQ to rx ring(%s):\n",
					entry->dest.rx_ring->name);
				for (i = 0; i < nb_rx; i++)
					rte_pktmbuf_dump(stdout, mbufs[i], 60);
			}
			nb_tx = rte_ring_enqueue_burst(entry->dest.rx_ring,
					(void * const *)mbufs, nb_rx, NULL);
			if (unlikely(s_dump_traffic_flow)) {
				RTE_LOG(INFO, pre_ld,
					"EQ %d frames to rx ring(%s) done\n",
					nb_tx, entry->dest.rx_ring->name);
			}
		} else if (entry->dest_type == PRE_LD_RX_RING) {
			if (unlikely(s_l3_traffic_dump || s_l4_traffic_dump)) {
				sprintf(prefix, "EQ to preload rx ring(%s):",
					entry->dest.pre_ld_rx_ring->name);
				for (i = 0; i < nb_rx; i++) {
					pre_ld_l3_l4_traffic_dump(mbufs[i],
						prefix);
				}
			}
			if (unlikely(s_dump_traffic_flow)) {
				RTE_LOG(INFO, pre_ld,
					"EQ to preload rx ring(%s):\n",
					entry->dest.pre_ld_rx_ring->name);
				for (i = 0; i < nb_rx; i++)
					rte_pktmbuf_dump(stdout, mbufs[i], 60);
			}
			nb_tx = pre_ld_ring_eq(entry->dest.pre_ld_rx_ring,
				(void **)mbufs, nb_rx);
			if (unlikely(s_dump_traffic_flow)) {
				RTE_LOG(INFO, pre_ld,
					"EQ %d frames to preload rx ring(%s) done\n",
					nb_tx,
					entry->dest.pre_ld_rx_ring->name);
			}
		} else {
			nb_tx = 0;
		}
		for (j = 0; j < nb_tx; j++) {
			entry->tx_stat.oh_bytes += bytes_overhead[j];
		}
		entry->tx_stat.pkts += nb_tx;
		entry->tx_stat.count++;
		if (nb_tx < nb_rx) {
			rte_pktmbuf_free_bulk(&mbufs[nb_tx],
				nb_rx - nb_tx);
		}
	}

	goto for_ever_loop;

	return 0;
}

static enum pre_ld_port_type
pre_ld_set_port_type(enum pre_ld_port_type port_type[],
	uint16_t size)
{
	uint16_t portid1, portid2, port_num;
	char port_name1[RTE_ETH_NAME_MAX_LEN];
	char port_name2[RTE_ETH_NAME_MAX_LEN];
	const char *peer_name;
	enum pre_ld_port_type type_val = NULL_TYPE;
	int kernel_port = -1;

	for (port_num = 0; port_num < size; port_num++)
		port_type[port_num] = NULL_TYPE;

	port_num = 0;

	RTE_ETH_FOREACH_DEV(portid1) {
		if (rte_pmd_dpaa2_dev_is_dpaa2(portid1))
			port_num++;
		if (port_type[portid1] != NULL_TYPE)
			continue;
		rte_eth_dev_get_name_by_port(portid1, port_name1);
		peer_name = rte_pmd_dpaa2_ep_name(portid1);
		if (!peer_name ||
			!strncmp(peer_name, "dpmac.", strlen("dpmac."))) {
			if (type_val & EXTERNAL_TYPE) {
				RTE_LOG(INFO, pre_ld,
					"Multiple external ports?\n");
				type_val = NULL_TYPE;
				goto quit;
			}
			port_type[portid1] = EXTERNAL_TYPE;
			type_val |= EXTERNAL_TYPE;
			continue;
		}
		RTE_ETH_FOREACH_DEV(portid2) {
			if (portid2 == portid1)
				continue;
			rte_eth_dev_get_name_by_port(portid2, port_name2);
			if (peer_name && !strcmp(peer_name, port_name2)) {
				if (type_val &
					(UP_LINK_TYPE | DOWN_LINK_TYPE)) {
					RTE_LOG(INFO, pre_ld,
						"Multiple pairs of ul/dl ports?\n");
					type_val = NULL_TYPE;
					goto quit;
				}
				port_type[portid1] = UP_LINK_TYPE;
				port_type[portid2] = DOWN_LINK_TYPE;
				type_val |= UP_LINK_TYPE | DOWN_LINK_TYPE;
				break;
			}
		}
		if (port_type[portid1] == NULL_TYPE &&
			rte_pmd_dpaa2_dev_is_dpaa2(portid1)) {
			if (type_val & KERNEL_TAP_TYPE) {
				RTE_LOG(INFO, pre_ld,
					"Multiple tap ports?\n");
				type_val = NULL_TYPE;
				goto quit;
			}
			port_type[portid1] = KERNEL_TAP_TYPE;
			type_val |= KERNEL_TAP_TYPE;
			kernel_port = portid1;
		}
	}

	if (port_num == 1) {
		RTE_ETH_FOREACH_DEV(portid1) {
			if (rte_pmd_dpaa2_dev_is_dpaa2(portid1)) {
				port_type[portid1] = DOWN_LINK_TYPE;
				type_val = DOWN_LINK_TYPE;
			}
		}
	} else if (kernel_port >= 0 && !s_slow_if) {
		peer_name = rte_pmd_dpaa2_ep_name(kernel_port);
		s_slow_if = pre_ld_get_tap_kernel_if_nm(peer_name);
		if (s_slow_if) {
			rte_eth_dev_get_name_by_port(kernel_port, port_name1);
			RTE_LOG(INFO, pre_ld,
				"Found tap port(%s)(%s) connected to %s\n",
				s_slow_if, peer_name, port_name1);
		}
	}
quit:
	if (type_val == NULL_TYPE) {
		for (port_num = 0; port_num < size; port_num++)
			port_type[port_num] = NULL_TYPE;
	}
	return type_val;
}

#define MAX_ARGV_NUM 32

static int
is_cpu_detected(uint32_t lcore_id)
{
	char path[PATH_MAX];
	uint32_t len = snprintf(path, sizeof(path),
		"/sys/devices/system/cpu/cpu%u/topology/core_id",
		lcore_id);

	if (len <= 0 || len >= sizeof(path))
		return 0;
	if (access(path, F_OK) != 0)
		return 0;

	return 1;
}

static inline double
pre_ld_st_gbps(uint64_t bytes_diff)
{
#define PRE_LD_G_SIZE ((double)(1000 * 1000 * 1000))
#define PRE_LD_ST_G_SIZE (STATISTICS_DELAY_SEC * PRE_LD_G_SIZE)
	return (double)bytes_diff * 8 / PRE_LD_ST_G_SIZE;
}

static inline double
pre_ld_st_mpps(uint64_t pkts_diff)
{
#define PRE_LD_M_SIZE ((double)(1000 * 1000))
#define PRE_LD_ST_M_SIZE (STATISTICS_DELAY_SEC * PRE_LD_M_SIZE)
	return (double)pkts_diff / PRE_LD_ST_M_SIZE;
}

static void
pre_ld_st_entry_info_and_update(char *info,
	enum pre_ld_statistic_dir dir,
	const struct pre_ld_dir_statistic *entry_stat,
	struct pre_ld_dir_statistic *entry_old_stat)
{
	uint64_t count_diff, pkt_diff, oh_diff;
	int offset;
	double gbps;

	count_diff = entry_stat->count - entry_old_stat->count;
	pkt_diff = entry_stat->pkts - entry_old_stat->pkts;
	oh_diff = entry_stat->oh_bytes - entry_old_stat->oh_bytes;
	rte_memcpy(entry_old_stat, entry_stat,
		sizeof(struct pre_ld_dir_statistic));

	if (count_diff > 0) {
		offset = sprintf(info,
			"Average %s burst(%.1f)(%ld/%ld) ",
			dir == PRE_LD_STAT_RX ? "rx" : "tx",
			pkt_diff / (double)count_diff,
			pkt_diff, count_diff);
	} else {
		offset = 0;
	}
	gbps = pre_ld_st_gbps(oh_diff);
	offset += sprintf(&info[offset], "%s line: ",
		dir == PRE_LD_STAT_RX ? "recv" : "send");
	if (gbps > 1) {
		sprintf(&info[offset], "%.2fGbps, %.2fMPPS",
			gbps, pre_ld_st_mpps(pkt_diff));
	} else {
		sprintf(&info[offset], "%.2fMbps, %.2fMPPS",
			gbps * 1000, pre_ld_st_mpps(pkt_diff));
	}
}

static void
pre_ld_st_fd_info_and_update(int fd,
	enum pre_ld_statistic_dir dir,
	const struct fd_statistic *fd_stat,
	struct fd_statistic *fd_old_stat)
{
	uint64_t pkt_diff, oh_diff, usr_diff;
	double oh_gbps, usr_gbps;
	char info[1024];
	int offset;

	oh_diff = fd_stat->oh_bytes - fd_old_stat->oh_bytes;
	usr_diff = fd_stat->usr_bytes - fd_old_stat->usr_bytes;
	pkt_diff = fd_stat->pkts - fd_old_stat->pkts;
	oh_gbps = pre_ld_st_gbps(oh_diff);
	usr_gbps = pre_ld_st_gbps(usr_diff);
	offset = sprintf(info, "FD(%d) %s ",
		fd, dir == PRE_LD_STAT_RX ? "recv" : "send");
	if (oh_gbps > 1) {
		offset += sprintf(&info[offset], "line: %.2fGbps, ",
			oh_gbps);
	} else {
		offset += sprintf(&info[offset], "line: %.2fMbps, ",
			oh_gbps * 1000);
	}
	if (usr_gbps > 1) {
		offset += sprintf(&info[offset],
			"usr: %.2fGbps,  %.2fMPPS\n",
			usr_gbps, pre_ld_st_mpps(pkt_diff));
	} else {
		offset += sprintf(&info[offset],
			"usr: %.2fMbps,  %.2fMPPS\n",
			usr_gbps * 1000, pre_ld_st_mpps(pkt_diff));
	}
	RTE_LOG(INFO, pre_ld, "%s", info);
	rte_memcpy(fd_old_stat, fd_stat, sizeof(struct fd_statistic));
}

static void *
pre_ld_data_path_statistics(void *arg)
{
	uint16_t i;
	struct pre_ld_lcore_direct_list *list;
	struct pre_ld_direct_entry *entry, *tentry;
	char poll_info[512], entry_info[512];
	char rx_stat_info[512], tx_stat_info[512];
	const char *space = "        ";
	struct fd_desc *usr, *tusr;

statistics_loop:
	if (s_data_path_core < 0)
		goto usr_fd_statistics;

	list = &s_pre_ld_lists[s_data_path_core];
	i = 0;
	RTE_TAILQ_FOREACH_SAFE(entry, list, next, tentry) {
		if (entry->poll_type == RX_QUEUE) {
			sprintf(poll_info, "Poll from port%d/queue%d",
				entry->poll.poll_port.port_id,
				*entry->poll.poll_port.queue_id);
		} else if (entry->poll_type == TX_RING) {
			sprintf(poll_info, "Poll from tx ring(%s)",
				entry->poll.tx_ring->name);
		} else if (entry->poll_type == SEC_IN_COMPLETE) {
			sprintf(poll_info, "Poll decap from SEC%d/queue%d",
				entry->poll.poll_sec.sec_id,
				*entry->poll.poll_sec.queue_id);
		} else if (entry->poll_type == SEC_EG_COMPLETE) {
			sprintf(poll_info, "Poll encap from SEC%d/queue%d",
				entry->poll.poll_sec.sec_id,
				*entry->poll.poll_sec.queue_id);
		} else {
			sprintf(poll_info, "Err poll type(%d)",
				entry->poll_type);
		}
		if (entry->dest_type == HW_PORT) {
			sprintf(entry_info, "then forward to port%d",
				entry->dest.dest_port);
		} else if (entry->dest_type == RX_RING) {
			sprintf(entry_info, "then forward to rx ring(%s)",
				entry->dest.rx_ring->name);
		} else if (entry->dest_type == PRE_LD_RX_RING) {
			sprintf(entry_info,
				"then forward to preload rx ring(%s)",
				entry->dest.pre_ld_rx_ring->name);
		} else if (entry->dest_type == SEC_EGRESS) {
			sprintf(entry_info, "then encap to SEC%d/queue%d",
				entry->dest.dest_sec.sec_id,
				*entry->dest.dest_sec.queue_id);
		} else if (entry->dest_type == SEC_INGRESS) {
			sprintf(entry_info, "then decap to SEC%d/queue%d",
				entry->dest.dest_sec.sec_id,
				*entry->dest.dest_sec.queue_id);
		} else {
			sprintf(entry_info, "then drop");
		}

		pre_ld_st_entry_info_and_update(tx_stat_info,
			PRE_LD_STAT_TX, &entry->tx_stat, &entry->tx_old_stat);

		pre_ld_st_entry_info_and_update(rx_stat_info,
			PRE_LD_STAT_RX, &entry->rx_stat, &entry->rx_old_stat);

		RTE_LOG(INFO, pre_ld,
			"DIRECT ENTRY[%d] on core%d:\n%s%s %s\n%s%s\n%s%s\n\n",
			i, s_data_path_core,
			space, poll_info, entry_info,
			space, rx_stat_info,
			space, tx_stat_info);
		i++;
	}

usr_fd_statistics:
	RTE_TAILQ_FOREACH_SAFE(usr, &s_fd_desc_list, next, tusr) {
		pre_ld_st_fd_info_and_update(usr->fd, PRE_LD_STAT_TX,
			&usr->tx_stat, &usr->tx_old_stat);

		pre_ld_st_fd_info_and_update(usr->fd, PRE_LD_STAT_RX,
			&usr->rx_stat, &usr->rx_old_stat);
	}

	sleep(STATISTICS_DELAY_SEC);
	if (s_pre_ld_quit)
		return arg;
	goto statistics_loop;

	return arg;
}

static int eal_main(void)
{
	int ret;
	uint16_t nb_ports, i;
	uint16_t nb_ports_available = 0;
	uint16_t portid, dpaa2_rxqs = 0;
	uint16_t rxq_num[RTE_MAX_ETHPORTS];
	uint16_t txq_num[RTE_MAX_ETHPORTS];
	struct rte_eth_conf *port_conf;
	struct rte_eth_dev_info *dev_info;
	enum pre_ld_port_type port_type[RTE_MAX_ETHPORTS], type_ret;
	size_t eal_argc = 0;
	char *eal_argv[MAX_ARGV_NUM];
	char func_nm[64], s_cpu[32], s_cpu_mask[32];
	char s_file_prefix[32], s_file_prefix_val[32];
	uint16_t ext_id = 0, ul_id = 0, dl_id = 0, tap_id = 0;
	uint32_t cpu_mask;
	pthread_t pid;
	struct rte_eth_fc_conf fc_conf;
	char ring_nm[RTE_MEMZONE_NAMESIZE];

	sprintf(func_nm, "%s", __func__);
	eal_argv[eal_argc] = func_nm;
	eal_argc++;
	/** One is main and another is data path thread probably.*/
	cpu_mask = (1 << s_cpu_start) | (1 << (s_cpu_start + 1));

	sprintf(s_cpu, "-c");
	eal_argv[eal_argc] = s_cpu;
	eal_argc++;

	sprintf(s_cpu_mask, "0x%x", cpu_mask);
	eal_argv[eal_argc] = s_cpu_mask;
	eal_argc++;

	if (s_eal_file_prefix) {
		sprintf(s_file_prefix, "--file-prefix");
		eal_argv[eal_argc] = s_file_prefix;
		eal_argc++;
		sprintf(s_file_prefix_val, "%s", s_eal_file_prefix);
		eal_argv[eal_argc] = s_file_prefix_val;
		eal_argc++;
	}

	/* init EAL */
	ret = rte_eal_init(eal_argc, eal_argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	s_main_td = pthread_self();

	RTE_LOG(INFO, pre_ld,
		"Main core%d, current core%d, CPU mask is 0x%08x\n",
		rte_get_main_lcore(), sched_getcpu(),
		cpu_mask);

	nb_ports = rte_eth_dev_count_avail();
	if (!nb_ports)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	RTE_LOG(INFO, pre_ld, "%d Ethernet ports found.\n", nb_ports);

	/* create the mbuf pool */
	s_pre_ld_rx_pool = rte_pktmbuf_pool_create("rx_pool",
		MEMPOOL_ELEM_SIZE, MEMPOOL_CACHE_SIZE,
		PRE_LD_MP_PRIV_SIZE,
		PRE_LD_MBUF_MAX_SIZE, rte_socket_id());
	if (!s_pre_ld_rx_pool)
		rte_exit(EXIT_FAILURE, "Cannot init rx pool\n");

	if (getenv("TX_FROM_RX_POOL")) {
		s_tx_from_rx_pool = 1;
		RTE_LOG(INFO, pre_ld,
			"Using single pool for TX/RX\n");
	}

	port_conf = rte_zmalloc(NULL,
		sizeof(struct rte_eth_conf) * RTE_MAX_ETHPORTS, 0);
	if (!port_conf) {
		rte_exit(EXIT_FAILURE,
			"Malloc ports configuration failed\n");
	}
	dev_info = rte_zmalloc(NULL,
		sizeof(struct rte_eth_dev_info) * RTE_MAX_ETHPORTS, 0);
	if (!dev_info) {
		rte_exit(EXIT_FAILURE,
			"Malloc ports information failed\n");
	}

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		rte_memcpy(&port_conf[i], &s_port_conf,
			sizeof(s_port_conf));
	}

	type_ret = pre_ld_set_port_type(port_type, RTE_MAX_ETHPORTS);

	RTE_ETH_FOREACH_DEV(portid) {
		nb_ports_available++;
		rxq_num[portid] = 0;

		/* init port */
		RTE_LOG(INFO, pre_ld,
			"Configuring port%u, type:%d... ",
			portid, port_type[portid]);

		ret = rte_eth_dev_info_get(portid, &dev_info[portid]);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));
		}

		if (dev_info[portid].tx_offload_capa &
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
			port_conf[portid].txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		}

		if (port_type[portid] == EXTERNAL_TYPE) {
			ext_id = portid;
			rxq_num[portid] = 1;
			txq_num[portid] = 1;
		} else if (port_type[portid] == UP_LINK_TYPE) {
			ul_id = portid;
			rxq_num[portid] = dev_info[portid].max_rx_queues;
			txq_num[portid] = dev_info[portid].max_tx_queues;
		} else if (port_type[portid] == DOWN_LINK_TYPE) {
			dl_id = portid;
			s_rx_port = dl_id;
			s_tx_port = dl_id;
			rxq_num[portid] = dev_info[portid].max_rx_queues;
			txq_num[portid] = dev_info[portid].max_tx_queues;
		} else if (port_type[portid] == KERNEL_TAP_TYPE) {
			tap_id = portid;
			rxq_num[portid] = 1;
			txq_num[portid] = 1;
		} else {
			rte_exit(EXIT_FAILURE,
				"Invalid port[%d] type(%d)\n",
				portid, port_type[portid]);
		}
		ret = rte_eth_dev_configure(portid, rxq_num[portid],
			txq_num[portid], &port_conf[portid]);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Cannot configure device: err=%d, port=%u\n",
				ret, portid);
		}
		if (rte_pmd_dpaa2_dev_is_dpaa2(portid))
			dpaa2_rxqs += rxq_num[portid];
		rte_log(RTE_LOG_INFO, RTE_LOGTYPE_pre_ld,
			"%d rxq(s) and %d txq(s) setup done.\n",
			rxq_num[portid], txq_num[portid]);
	}

	if (!nb_ports_available)
		rte_exit(EXIT_FAILURE, "no port available\n");

	if (dpaa2_rxqs &&
		s_dpaa2_nb_rxd >= RTE_DPAA2_RX_DESC_MAX / dpaa2_rxqs)
		s_dpaa2_nb_rxd = RTE_DPAA2_RX_DESC_MAX / dpaa2_rxqs;

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		uint16_t rxd;

		/* init port */
		RTE_LOG(INFO, pre_ld,
			"Initializing port %u... ", portid);
		if (rte_pmd_dpaa2_dev_is_dpaa2(portid))
			rxd = s_dpaa2_nb_rxd;
		else
			rxd = s_nb_rxd;

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &rxd,
				&s_nb_txd);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				 "Adjust descriptors: err=%d, port=%u\n",
				 ret, portid);
		}

		/* init one RX queue */
		rxq_conf = dev_info[portid].default_rxconf;
		rxq_conf.offloads = port_conf[portid].rxmode.offloads;
		for (i = 0; i < rxq_num[portid]; i++) {
			ret = rte_eth_rx_queue_setup(portid, i, rxd,
					rte_eth_dev_socket_id(portid),
					&rxq_conf,
					s_pre_ld_rx_pool);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE,
					"setup port%d:rxq[%d] failed(%d)\n",
					portid, (int)i, ret);
			}
		}

		/* init one TX queue on each port */
		txq_conf = dev_info[portid].default_txconf;
		txq_conf.offloads = port_conf[portid].txmode.offloads;
		for (i = 0; i < txq_num[portid]; i++) {
			ret = rte_eth_tx_queue_setup(portid, i, s_nb_txd,
					rte_eth_dev_socket_id(portid),
					&txq_conf);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE,
					"setup port%d:txq[%d] failed(%d)\n",
					portid, (int)i, ret);
			}
		}
		memset(&fc_conf, 0, sizeof(fc_conf));
		if (s_flow_control)
			fc_conf.mode = RTE_ETH_FC_FULL;
		else
			fc_conf.mode = RTE_ETH_FC_NONE;
		ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
		if (ret) {
			RTE_LOG(WARNING, pre_ld,
				"Flow control set not support on port%d\n",
				portid);
		}

		if (s_mtu_set) {
			ret = rte_eth_dev_set_mtu(portid, s_mtu_set);
			if (ret) {
				RTE_LOG(WARNING, pre_ld,
					"Set MTU(%d) on port%d failed(%d)\n",
					s_mtu_set, portid, ret);
			}
		}

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start:err=%d, port=%u\n",
				ret, portid);
		}

		rte_log(RTE_LOG_INFO, RTE_LOGTYPE_pre_ld, "done.\n");

		ret = rte_eth_promiscuous_enable(portid);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				 "rte_eth_promiscuous_enable:err=%s, port=%u\n",
				 rte_strerror(-ret), portid);
		}

		sprintf(ring_nm, "port%d_rxq_ring", portid);
		s_port_rxq_rings[portid] = rte_ring_create(ring_nm,
			dev_info[portid].max_rx_queues * 2, 0, 0);
		if (!s_port_rxq_rings[portid])
			rte_exit(EXIT_FAILURE, "create %s failed\n", ring_nm);

		for (i = 0; i < rxq_num[portid]; i++) {
			s_rxq_ids[portid][i] = i;
			if (i == (rxq_num[portid] - 1)) {
				/** Default flow, lowest priority.*/
				s_def_rxq[portid] = i;
				continue;
			}
			ret = rte_ring_enqueue(s_port_rxq_rings[portid],
				&s_rxq_ids[portid][i]);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"eq s_rxq_ids[%d][%d] to %s failed\n",
					portid, (int)i, ring_nm);
			}
		}

		sprintf(ring_nm, "port%d_txq_ring", portid);
		s_port_txq_rings[portid] = rte_ring_create(ring_nm,
			MAX_USR_FD_NUM, 0,
			RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (!s_port_txq_rings[portid])
			rte_exit(EXIT_FAILURE, "create %s failed\n", ring_nm);

		for (i = 0; i < txq_num[portid]; i++) {
			s_txq_ids[portid][i] = i;
			ret = rte_ring_enqueue(s_port_txq_rings[portid],
				&s_txq_ids[portid][i]);
			if (ret) {
				rte_exit(EXIT_FAILURE,
					"eq s_txq_ids[%d][%d] to %s failed\n",
					portid, (int)i, ring_nm);
			}
		}
	}

	if (type_ret == DOWN_LINK_TYPE) {
		pre_ld_configure_split_traffic(dl_id);
	} else if (type_ret == ALL_TYPE) {
		s_dir_ports.valid = 1;
		s_dir_ports.ext_id = ext_id;
		s_dir_ports.ul_id = ul_id;
		s_dir_ports.dl_id = dl_id;
		s_dir_ports.tap_id = tap_id;
		ret = rte_eal_mp_remote_launch(pre_ld_main_loop,
			NULL, SKIP_MAIN);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"remote launch thread failed!(%d)\n", ret);
		}
	} else {
		rte_exit(EXIT_FAILURE,
			"Invalid port(s) configuration(0x%02x)\n",
			type_ret);
	}

	if (s_statistic_print) {
		ret = pthread_create(&pid, NULL,
				pre_ld_data_path_statistics, NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Statistics thread create failed(%d)\n",
				ret);
		}
	}

	rte_free(dev_info);
	rte_free(port_conf);

	return 0;
}

static int
eal_create_dpaa2_mux_flow(int dpdmux_id,
	int dpdmux_ep_id, struct rte_flow_item pattern[])
{
	int ret;
	struct rte_flow_action actions[2];
	struct rte_flow_action_vf vf;

	memset(&vf, 0, sizeof(vf));

	vf.id = dpdmux_ep_id;

	actions[0].type = RTE_FLOW_ACTION_TYPE_VF;
	actions[0].conf = &vf;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;

	ret = rte_pmd_dpaa2_mux_flow_create(dpdmux_id,
			pattern, actions);
	if (ret < 0) {
		RTE_LOG(ERR, pre_ld,
			"%s: MUX flow create failed(%d)\n",
			__func__, ret);
	} else {
		s_dpdmux_entry_index = ret;
	}

	return ret >= 0 ? 0 : ret;
}

static int
eal_create_local_flow(int sockfd, uint16_t port_id,
	struct rte_flow_item pattern[],
	uint16_t rxq_id)
{
	struct rte_flow_action actions[1];
	struct rte_flow_action_queue ingress_queue;
	struct rte_flow_action flow_action[2];
	struct rte_flow_attr attr;
	struct rte_flow *flow;

	memset(actions, 0, sizeof(actions));

	memset(&ingress_queue, 0,
		sizeof(struct rte_flow_action_queue));
	ingress_queue.index = rxq_id;
	flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	flow_action[0].conf = &ingress_queue;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

	attr.group = 0;
	attr.priority = rxq_id;
	attr.ingress = 1;
	attr.egress = 0;

	flow = rte_flow_create(port_id, &attr, pattern,
			flow_action, NULL);
	if (!flow) {
		RTE_LOG(ERR, pre_ld,
			"%s: flow create failed\n", __func__);
		return -EIO;
	}

	s_fd_desc[sockfd].flow = flow;

	return 0;
}

static int
eal_create_flow(int sockfd, struct rte_flow_item pattern[])
{
	char config_str[256];
	int ret, udp_src = 0, udp_dst = 0;
	uint16_t rx_port, rxq_id;
	struct pre_ld_direct_entry *rx_entry;
	static int default_created;
	const char *prot_name;
	const struct rte_flow_item_udp *udp = NULL;
	const struct rte_flow_item_udp *mask = NULL;

	if (s_dpdmux_ep_name) {
		/**dpdmux flow : dpni flow = 1:1*/
		ret = eal_create_dpaa2_mux_flow(s_dpdmux_id,
				s_dpdmux_ep_id, pattern);
		if (ret)
			return ret;

		goto create_local_flow;
	}

	if (!s_uplink || !s_downlink || default_created)
		goto create_local_flow;

	if (pattern[0].type == RTE_FLOW_ITEM_TYPE_UDP) {
		prot_name = "udp";
		udp = pattern[0].spec;
		mask = pattern[0].mask;
		if (mask->hdr.src_port)
			udp_src = 1;
		if (mask->hdr.dst_port)
			udp_dst = 1;
	} else if (pattern[0].type == RTE_FLOW_ITEM_TYPE_GTP) {
		prot_name = "gtp";
	} else if (pattern[0].type == RTE_FLOW_ITEM_TYPE_ETH) {
		prot_name = "eth";
	} else if (pattern[0].type == RTE_FLOW_ITEM_TYPE_ECPRI) {
		prot_name = "ecpri";
	} else {
		prot_name = "unsupported protocol";
		RTE_LOG(ERR, pre_ld,
			"Unsupported protocol type(%d)\n",
			pattern[0].type);
	}

	if (udp_src && !udp_dst) {
		sprintf(config_str,
			"(%s, %s, %s, src, 0x%04x)",
			s_uplink, s_downlink, prot_name,
			rte_bswap16(udp->hdr.src_port));
	} else if (!udp_src && udp_dst) {
		sprintf(config_str,
			"(%s, %s, %s, dst, 0x%04x)",
			s_uplink, s_downlink, prot_name,
			rte_bswap16(udp->hdr.dst_port));
	} else if (udp_src && udp_dst) {
		sprintf(config_str,
			"(%s, %s, %s, src, 0x%04x), (%s, %s, %s, dst, 0x%04x)",
			s_uplink, s_downlink, prot_name,
			rte_bswap16(udp->hdr.src_port),
			s_uplink, s_downlink, prot_name,
			rte_bswap16(udp->hdr.dst_port));
	} else {
		sprintf(config_str,
			"(%s, %s, %s)",
			s_uplink, s_downlink, prot_name);
	}

	ret = rte_remote_direct_parse_config(config_str, 1);
	if (ret)
		return ret;
	ret = rte_remote_direct_traffic(RTE_REMOTE_DIR_REQ, NULL);
	if (ret)
		return ret;

	default_created = 1;

create_local_flow:
	if (s_fd_desc[sockfd].dp_type == FD_DP_DIRECT_TYPE) {
		rx_port = s_fd_desc[sockfd].dp_desc.hw_desc.rx_port;
		rxq_id = *s_fd_desc[sockfd].dp_desc.hw_desc.rxq_id;
	} else {
		rx_entry = s_fd_desc[sockfd].dp_desc.entry_desc.rx_entry;
		rx_port = rx_entry->poll.poll_port.port_id;
		rxq_id = *rx_entry->poll.poll_port.queue_id;
	}
	ret = eal_create_local_flow(sockfd, rx_port, pattern, rxq_id);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Port(%d) rxq(%d) flow create failed(%d)\n",
			rx_port, rxq_id, ret);
	}

	return ret;
}

static void
socket_hdr_init(struct eth_ipv4_udp_hdr *hdr)
{
	memset(hdr, 0, sizeof(struct eth_ipv4_udp_hdr));

	hdr->eth_hdr.ether_type =
		rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	hdr->ip_hdr.version_ihl = IP_VHL_DEF;
	hdr->ip_hdr.time_to_live = IP_DEFTTL;
	hdr->ip_hdr.next_proto_id = IPPROTO_UDP;
}

static void
usr_socket_fd_add(int sockfd)
{
	pthread_mutex_lock(&s_fd_list_mutex);
	TAILQ_INSERT_TAIL(&s_fd_desc_list, &s_fd_desc[sockfd], next);
	pthread_mutex_unlock(&s_fd_list_mutex);
}

static int
usr_socket_fd_desc_init(int sockfd,
	uint16_t rx_port, uint16_t tx_port)
{
	int ret = 0, i;
	struct pre_ld_lcore_direct_list *list = NULL;
	struct fd_desc *desc = NULL;
	struct pre_ld_direct_entry *rx_entry = NULL;
	struct pre_ld_direct_entry *tx_entry = NULL;
	uint16_t mtu, *rxq_id = NULL;
	char nm[RTE_MEMZONE_NAMESIZE];

	pthread_mutex_lock(&s_fd_mutex);
	if (sockfd < 0) {
		RTE_LOG(ERR, pre_ld,
			"create socket failed(%d)\n", sockfd);

		ret = -EINVAL;
		goto fd_init_quit;
	}
	if (sockfd >= MAX_USR_FD_NUM) {
		RTE_LOG(ERR, pre_ld,
			"Too many FDs(%d) >= %d\n",
			sockfd, MAX_USR_FD_NUM);

		ret = -EBADF;
		goto fd_init_quit;
	}
	desc = &s_fd_desc[sockfd];
	if (desc->fd >= 0) {
		RTE_LOG(ERR, pre_ld,
			"Duplicated FD[%d](%d)?\n",
			sockfd, desc->fd);

		ret = -EEXIST;
		goto fd_init_quit;
	}

	socket_hdr_init(&desc->hdr);

	desc->rx_buffer.head = 0;
	desc->rx_buffer.tail = 0;
	desc->rx_buffer.rx_bufs = rte_malloc(NULL,
		sizeof(void *) * MAX_PKT_BURST * 2, RTE_CACHE_LINE_SIZE);
	if (!desc->rx_buffer.rx_bufs) {
		RTE_LOG(ERR, pre_ld,
			"port%d: RX pool init failed for socket(%d)\n",
			rx_port, sockfd);

		goto fd_init_quit;
	}
	desc->rx_buffer.max_num = MAX_PKT_BURST * 2;

	ret = rte_ring_dequeue(s_port_rxq_rings[rx_port],
			(void **)&rxq_id);
	if (ret) {
		RTE_LOG(INFO, pre_ld,
			"port%d: RXQ allocated for socket(%d) failed(%d)\n",
			tx_port, sockfd, ret);
		rte_free(desc->rx_buffer.rx_bufs);
		desc->rx_buffer.rx_bufs = NULL;

		goto fd_init_quit;
	}
	RTE_LOG(INFO, pre_ld,
		"port%d: RXQ[%d] allocated for socket(%d)\n",
		tx_port, *rxq_id, sockfd);

	if (!s_dir_ports.valid) {
		desc->dp_type = FD_DP_DIRECT_TYPE;
		desc->dp_desc.hw_desc.rx_port = rx_port;
		desc->dp_desc.hw_desc.rxq_id = rxq_id;
		desc->dp_desc.hw_desc.tx_port = tx_port;
		desc->eal_thread = 1;
	} else {
		desc->dp_type = FD_DP_IN_DIRECT_TYPE;
		list = &s_pre_ld_lists[s_data_path_core];
		tx_entry = rte_zmalloc(NULL,
			sizeof(struct pre_ld_direct_entry), 0);
		if (!tx_entry) {
			ret = -ENOMEM;
			goto fd_init_quit;
		}
		tx_entry->poll_type = TX_RING;
		sprintf(nm, "tx_ring_fd%d", sockfd);
		tx_entry->poll.tx_ring = rte_ring_create(nm, MEMPOOL_USR_SIZE,
			0, RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (!tx_entry->poll.tx_ring) {
			ret = -ENOMEM;
			goto fd_init_quit;
		}
		tx_entry->dest_type = HW_PORT;
		tx_entry->dest.dest_port = tx_port;
		pre_ld_insert_dir_list_safe(list, tx_entry);
		desc->dp_desc.entry_desc.tx_entry = tx_entry;

		rx_entry = rte_zmalloc(NULL,
			sizeof(struct pre_ld_direct_entry), 0);
		if (!rx_entry) {
			ret = -ENOMEM;
			goto fd_init_quit;
		}
		rx_entry->poll_type = RX_QUEUE;
		rx_entry->poll.poll_port.port_id = rx_port;
		rx_entry->poll.poll_port.queue_id = rxq_id;
		if (s_fd_rte_ring) {
			sprintf(nm, "rx_ring_fd%d", sockfd);
			rx_entry->dest_type = RX_RING;
			rx_entry->dest.rx_ring = rte_ring_create(nm,
				MEMPOOL_USR_SIZE,
				0, RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (!rx_entry->dest.rx_ring) {
				ret = -ENOMEM;
				goto fd_init_quit;
			}
		} else {
			sprintf(nm, "pre_ld_rx_ring_fd%d", sockfd);
			rx_entry->dest_type = PRE_LD_RX_RING;
			rx_entry->dest.pre_ld_rx_ring = pre_ld_ring_create(nm,
				MEMPOOL_USR_SIZE);
			if (!rx_entry->dest.pre_ld_rx_ring) {
				ret = -ENOMEM;
				goto fd_init_quit;
			}
		}
		pre_ld_insert_dir_list_safe(list, rx_entry);
		desc->dp_desc.entry_desc.rx_entry = rx_entry;
		if (s_force_eal_thread)
			desc->eal_thread = 1;
		else
			desc->eal_thread = 0;
	}

	ret = rte_eth_dev_get_mtu(rx_port, &mtu);
	if (!ret)
		desc->rx_port_mtu = mtu;
	else
		desc->rx_port_mtu = RTE_ETHER_MTU;
	ret = rte_eth_dev_get_mtu(tx_port, &mtu);
	if (!ret)
		desc->tx_port_mtu = mtu;
	else
		desc->tx_port_mtu = RTE_ETHER_MTU;

	desc->hdr_init = HDR_INIT_NONE;

	desc->fd = sockfd;
	desc->eal_thread_nb = 0;
	memset(desc->th_desc, 0,
		sizeof(struct fd_thread_desc) * RTE_MAX_LCORE);
	for (i = 0; i < RTE_MAX_LCORE; i++)
		desc->th_desc[i].cpu = LCORE_ID_ANY;
	sprintf(nm, "tx_pool_fd%d", sockfd);
	desc->tx_pool = rte_pktmbuf_pool_create_by_ops(nm,
			MEMPOOL_USR_SIZE, MEMPOOL_CACHE_SIZE,
			PRE_LD_MP_PRIV_SIZE, PRE_LD_MBUF_MAX_SIZE,
			rte_socket_id(), RTE_MBUF_DEFAULT_MEMPOOL_OPS);
	if (!desc->tx_pool) {
		ret = -ENOMEM;
		RTE_LOG(ERR, pre_ld, "Create %s failed\n", nm);
	}
	rte_mempool_obj_iter(desc->tx_pool,
		pre_ld_pktmbuf_init, NULL);

fd_init_quit:
	if (ret) {
		if (rxq_id) {
			rte_ring_enqueue(s_port_rxq_rings[rx_port],
				rxq_id);
		}
		if (desc && desc->dp_type == FD_DP_IN_DIRECT_TYPE) {
			if (desc->dp_desc.entry_desc.tx_entry && list) {
				pre_ld_remove_dir_list_safe(list,
					desc->dp_desc.entry_desc.tx_entry);
			}
			if (desc->dp_desc.entry_desc.rx_entry && list) {
				pre_ld_remove_dir_list_safe(list,
					desc->dp_desc.entry_desc.rx_entry);
			}
			if (tx_entry && tx_entry->poll.tx_ring)
				rte_ring_free(tx_entry->poll.tx_ring);
			if (tx_entry)
				rte_free(tx_entry);
			if (rx_entry &&
				rx_entry->dest_type == RX_RING &&
				rx_entry->dest.rx_ring)
				rte_ring_free(rx_entry->dest.rx_ring);
			else if (rx_entry &&
				rx_entry->dest_type == PRE_LD_RX_RING &&
				rx_entry->dest.pre_ld_rx_ring)
				pre_ld_ring_free(rx_entry->dest.pre_ld_rx_ring);
			if (rx_entry)
				rte_free(rx_entry);
		}
		if (desc && desc->tx_pool)
			rte_mempool_free(desc->tx_pool);
	}
	pthread_mutex_unlock(&s_fd_mutex);

	return ret;
}

static void
dump_usr_fd(const char *s)
{
	char dump_str[4096];
	int count = 0, off = 0, max_fd = 0;
	struct fd_desc *usr, *tusr;

	RTE_TAILQ_FOREACH_SAFE(usr, &s_fd_desc_list, next, tusr) {
		off += sprintf(&dump_str[off], "%d, ", usr->fd);
		count++;
		if (usr->fd > max_fd)
			max_fd = usr->fd;
	}

	if (!count)
		return;

	RTE_LOG(INFO, pre_ld, "%s: total %d usr FD(s)(MAX=%d): %s\n",
		s, count, max_fd, dump_str);
}

static int eal_init(int domain, int type)
{
	uint8_t socket_type = type & SOCK_TYPE_MASK;
	int ret = 0;

	RTE_LOG(INFO, pre_ld,
		"%s: domain = %d, type = %d, inited(%d)\n",
		__func__, domain, socket_type, s_eal_inited);

	if (domain != AF_INET &&
		domain != AF_INET6 &&
		domain != AF_PACKET) {
		/**Support these domains only.*/
		return 0;
	}
	if (socket_type != SOCK_STREAM &&
		socket_type != SOCK_DGRAM &&
		socket_type != SOCK_RAW &&
		socket_type != SOCK_RDM &&
		socket_type != SOCK_SEQPACKET &&
		socket_type != SOCK_DCCP &&
		socket_type != SOCK_PACKET) {
		/**Support these types only.*/
		return 0;
	}

	pthread_mutex_lock(&s_eal_init_mutex);
	if (!s_eal_inited) {
		ret = eal_main();
		if (!ret) {
			s_eal_inited = 1;
		} else {
			RTE_LOG(ERR, pre_ld,
				"eal init failed(%d)\n", ret);
			pthread_mutex_unlock(&s_eal_init_mutex);
			exit(EXIT_FAILURE);
		}
	}
	pthread_mutex_unlock(&s_eal_init_mutex);

	return 1;
}

int
socket(int domain, int type, int protocol)
{
	int sockfd = INVALID_SOCKFD, ret;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: domain:0x%x, type:0x%x, proto:0x%04x\n",
			__func__, domain, type, ntohs(protocol));
		RTE_LOG(INFO, pre_ld,
			"%s starts: wrappers:%d, libc_socket:%p\n",
			__func__, s_socket_pre_set,
			libc_socket);
		dump_usr_fd(__func__);
	}

	if (s_socket_pre_set) {
		if (unlikely(!libc_socket)) {
			rte_panic("line %d\tassert \"%s\" failed\n",
				__LINE__, __func__);
		}
		sockfd = (*libc_socket)(domain, type, protocol);
		if (sockfd < 0) {
			RTE_LOG(ERR, pre_ld,
				"Socket FD created failed(%d)\n", sockfd);

			return sockfd;
		}
		if (!netwrap_is_usr_process())
			return sockfd;
		if (s_in_pre_loading)
			return sockfd;

		ret = eal_init(domain, type);
		if (ret > 0 && (type & SOCK_TYPE_MASK) == SOCK_DGRAM) {
			ret = usr_socket_fd_desc_init(sockfd,
					s_rx_port, s_tx_port);
			if (ret < 0) {
				RTE_LOG(ERR, pre_ld,
					"Init FD desc failed(%d)\n", ret);
				exit(EXIT_FAILURE);
			}
			usr_socket_fd_add(sockfd);
			RTE_LOG(INFO, pre_ld,
				"pre set user Socket FD(%d) created.\n",
				sockfd);
		}
	} else { /* pre init*/
		LIBC_FUNCTION(socket);

		if (!libc_socket) {
			RTE_LOG(ERR, pre_ld,
				"%s: not exist in libc.\n", __func__);
			errno = EACCES;

			return INVALID_SOCKFD;
		}

		sockfd = (*libc_socket)(domain, type, protocol);
		if (sockfd < 0) {
			RTE_LOG(ERR, pre_ld,
				"Socket FD created failed(%d)\n", sockfd);

			return sockfd;
		}
		if (!netwrap_is_usr_process())
			return sockfd;
		if (s_in_pre_loading)
			return sockfd;

		ret = eal_init(domain, type);
		if (ret > 0 && (type & SOCK_TYPE_MASK) == SOCK_DGRAM) {
			ret = usr_socket_fd_desc_init(sockfd,
					s_rx_port, s_tx_port);
			if (ret < 0) {
				RTE_LOG(ERR, pre_ld,
					"Init FD desc failed(%d)\n", ret);
				exit(EXIT_FAILURE);
			}
			usr_socket_fd_add(sockfd);
			RTE_LOG(INFO, pre_ld,
				"user Socket FD(%d) created.\n", sockfd);
		}
	}

	RTE_LOG(INFO, pre_ld,
		"Socket FD(%d) created, domain=%d, type=%d, protocol=%d\n",
		sockfd, domain, type, protocol);

	return sockfd;
}

int
shutdown(int sockfd, int how)
{
	int shutdown_value = 0, ret;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, libc_shutdown:%p\n",
			__func__, sockfd, libc_shutdown);
		RTE_LOG(INFO, pre_ld,
			"%s starts: wrappers:%d, libc_socket:%p\n",
			__func__, s_socket_pre_set,
			libc_socket);
		dump_usr_fd(__func__);
	}

	if (is_usr_socket(sockfd)) {
		usr_socket_fd_remove(sockfd);
		if (libc_shutdown)
			shutdown_value = (*libc_shutdown)(sockfd, how);
		ret = usr_socket_fd_release(sockfd);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s Failed(%d) release fd:%d\n",
				__func__, ret, sockfd);
		}
	} else if (libc_shutdown) {
		shutdown_value = (*libc_shutdown)(sockfd, how);
	} else {
		LIBC_FUNCTION(shutdown);

		if (libc_shutdown)
			shutdown_value = (*libc_shutdown)(sockfd, how);
		else {
			shutdown_value = -1;
			errno = EACCES;
		}
	}

	return shutdown_value;
}

int
close(int sockfd)
{
	int close_value = 0, ret;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, libc_close:%p\n",
			__func__, sockfd, libc_close);
		dump_usr_fd(__func__);
	}

	if (is_usr_socket(sockfd)) {
		usr_socket_fd_remove(sockfd);
		if (libc_close)
			close_value = (*libc_close)(sockfd);
		ret = usr_socket_fd_release(sockfd);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s release sockfd(%d) failed\n",
				__func__, sockfd);
		}
	} else if (libc_close) {
		close_value = (*libc_close)(sockfd);
	} else { /* pre init*/
		LIBC_FUNCTION(close);

		if (libc_close) {
			close_value = (*libc_close)(sockfd);
		} else {
			close_value = -ENOTSUP;
			errno = EACCES;
		}
	}

	return close_value;
}

/**Borrowed from iperf3*/
static void
map_ipv4_to_regular_ipv4(char *str)
{
	const char *prefix = "::ffff:";
	int prefix_len, str_len;

	prefix_len = strlen(prefix);
	if (!strncmp(str, prefix, prefix_len)) {
		str_len = strlen(str);
		memmove(str, str + prefix_len, str_len - prefix_len + 1);
	}
}

static int
netwrap_get_local_ip(int sockfd)
{
	struct sockaddr_in ia;
	socklen_t addrlen;
	int ret;
	struct eth_ipv4_udp_hdr *hdr;
	char ipl[INET6_ADDRSTRLEN];

	if ((s_fd_desc[sockfd].hdr_init &
		(LOCAL_IP_INIT | LOCAL_UDP_INIT)) ==
		(LOCAL_IP_INIT | LOCAL_UDP_INIT))
		return 0;

	ia.sin_family = AF_INET;
	ia.sin_addr.s_addr = htonl(INADDR_ANY);
	ia.sin_port = 0;
	addrlen = sizeof(ia);
	hdr = &s_fd_desc[sockfd].hdr;

	ret = getsockname(sockfd, (struct sockaddr *)&ia, &addrlen);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s: Get socket(%d) local name failed(%d)(AF_INET)\n",
			__func__, sockfd, ret);
	}

	if (ia.sin_family == AF_INET) {
		ret = convert_ip_addr_to_str(ipl,
			&ia.sin_addr.s_addr, 4);
		if (ret)
			return ret;

		RTE_LOG(INFO, pre_ld,
			"%s fd:%d, AF_INET: port=%x, IP addr=%s\n",
			__func__, sockfd,
			ntohs(ia.sin_port), ipl);
		hdr->ip_hdr.src_addr = ia.sin_addr.s_addr;
		hdr->udp_hdr.src_port = ia.sin_port;
	} else if (ia.sin_family == AF_INET6) {
		struct sockaddr_storage local_addr;
		struct sockaddr_in6 *ia6;

		/** Get socket name again.*/
		addrlen = sizeof(struct sockaddr_storage);
		ret = getsockname(sockfd, (struct sockaddr *)&local_addr,
			&addrlen);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: Get socket(%d) local name failed(%d)(AF_INET6)\n",
				__func__, sockfd, ret);

			return ret;
		}
		ia6 = (void *)&local_addr;
		inet_ntop(AF_INET6, (void *)&ia6->sin6_addr, ipl, sizeof(ipl));
		map_ipv4_to_regular_ipv4(ipl);

		hdr->ip_hdr.src_addr = ia6->sin6_addr.__in6_u.__u6_addr32[3];
		hdr->udp_hdr.src_port = ia6->sin6_port;
		RTE_LOG(INFO, pre_ld,
			"%s fd:%d, AF_INET6: port=%x, IP addr=%s\n",
			__func__, sockfd, ntohs(ia6->sin6_port), ipl);
	} else {
		RTE_LOG(ERR, pre_ld,
			"%s: Get socket(%d) local name: unsuppored family(%d)\n",
			__func__, sockfd, ia.sin_family);

		return -ENOTSUP;
	}

	s_fd_desc[sockfd].hdr_init |= (LOCAL_IP_INIT | LOCAL_UDP_INIT);

	return 0;
}

static int
netwrap_get_remote_hw(int sockfd)
{
	int ret = 0, offset = 0, i, arp_s, close_ret;
	struct arpreq arpreq;
	char mac_addr[64];
	uint8_t *ip4_addr;
	uint8_t addr_bytes[RTE_ETHER_ADDR_LEN];
	struct sockaddr_in ia;
	struct eth_ipv4_udp_hdr *hdr = &s_fd_desc[sockfd].hdr;

	if (!s_slow_if) {
		RTE_LOG(ERR, pre_ld,
			"%s: No tap port specified!\n", __func__);
		return -EINVAL;
	}

	if ((s_fd_desc[sockfd].hdr_init &
		(REMOTE_IP_INIT | REMOTE_UDP_INIT)) !=
		(REMOTE_IP_INIT | REMOTE_UDP_INIT)) {
		RTE_LOG(ERR, pre_ld,
			"%s: fd:%d, remote IP/UDP not initialized.\n",
			__func__, sockfd);
		return -EINVAL;
	}
	memset(&ia, 0, sizeof(ia));
	ia.sin_family = AF_INET;
	ia.sin_addr.s_addr = hdr->ip_hdr.dst_addr;
	ia.sin_port = hdr->udp_hdr.dst_port;

	memset(&arpreq, 0, sizeof(struct arpreq));
	rte_memcpy(&arpreq.arp_pa, &ia, sizeof(struct sockaddr_in));
	snprintf(arpreq.arp_dev, IFNAMSIZ, "%s", s_slow_if);
	arpreq.arp_pa.sa_family = AF_INET;
	arpreq.arp_ha.sa_family = AF_UNSPEC;

	if (!libc_socket)
		LIBC_FUNCTION(socket);

	if (!libc_close)
		LIBC_FUNCTION(close);

	arp_s = libc_socket(AF_INET, SOCK_STREAM, 0);
	if (arp_s < 0) {
		RTE_LOG(INFO, pre_ld,
			"%s: Create arp socket failed(%d)\n",
			__func__, arp_s);

		return arp_s;
	}
	ip4_addr = (void *)&ia.sin_addr.s_addr;
	ret = ioctl(arp_s, SIOCGARP, &arpreq);
	if (ret) {
		RTE_LOG(WARNING, pre_ld,
			"%s: Get arp table by %d.%d.%d.%d failed(%d)\n",
			__func__, ip4_addr[0], ip4_addr[1],
			ip4_addr[2], ip4_addr[3], ret);
		ret = xfm_find_sa_addrs_by_sp_addrs(NULL,
				(const xfrm_address_t *)&hdr->ip_hdr.dst_addr,
				AF_INET, XFRM_POLICY_OUT, NULL,
				(xfrm_address_t *)&ia.sin_addr.s_addr);
		if (ret)
			goto close_arp_socket;
		ip4_addr = (void *)&ia.sin_addr.s_addr;
		rte_memcpy(&arpreq.arp_pa, &ia, sizeof(struct sockaddr_in));
		ret = ioctl(arp_s, SIOCGARP, &arpreq);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: Get arp table by %d.%d.%d.%d failed(%d)\n",
				__func__, ip4_addr[0], ip4_addr[1],
				ip4_addr[2], ip4_addr[3], ret);
			goto close_arp_socket;
		}
	}

	rte_memcpy(&s_fd_desc[sockfd].hdr.eth_hdr.dst_addr,
		&arpreq.arp_ha.sa_data,
		RTE_ETHER_ADDR_LEN);
	rte_memcpy(addr_bytes, &arpreq.arp_ha.sa_data,
		RTE_ETHER_ADDR_LEN);
	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
		if (i != (RTE_ETHER_ADDR_LEN - 1)) {
			offset += sprintf(&mac_addr[offset],
				"%02x:", addr_bytes[i]);
		} else {
			offset += sprintf(&mac_addr[offset],
				"%02x", addr_bytes[i]);
		}
	}
	RTE_LOG(INFO, pre_ld,
		"%s: socket fd:%d, Get Remote Mac: %s by %d.%d.%d.%d\n",
		__func__, sockfd, mac_addr,
		ip4_addr[0], ip4_addr[1], ip4_addr[2], ip4_addr[3]);

	s_fd_desc[sockfd].hdr_init |= REMOTE_ETH_INIT;

close_arp_socket:
	close_ret = (*libc_close)(arp_s);
	if (close_ret) {
		RTE_LOG(INFO, pre_ld,
			"%s: close arp socket(%d) failed(%d)\n",
			__func__, arp_s, close_ret);
	}

	return ret;
}

static int
netwrap_get_remote_ip(int sockfd)
{
	int ret;
	struct sockaddr_in ia;
	socklen_t addrlen;
	char ipl[INET6_ADDRSTRLEN];
	struct eth_ipv4_udp_hdr *hdr;

	ia.sin_family = AF_INET;
	ia.sin_addr.s_addr = htonl(INADDR_ANY);
	ia.sin_port = 0;
	addrlen = sizeof(ia);

	ret = getpeername(sockfd, (struct sockaddr *)&ia, &addrlen);
	if (ret < 0) {
		RTE_LOG(ERR, pre_ld,
			"%s: Get socket(%d) peer name failed(%d)(AF_INET)\n",
			__func__, sockfd, ret);

		return ret;
	}

	hdr = &s_fd_desc[sockfd].hdr;
	if (ia.sin_family == AF_INET) {
		ret = convert_ip_addr_to_str(ipl,
				&ia.sin_addr.s_addr, 4);
		if (ret)
			return ret;

		RTE_LOG(INFO, pre_ld,
			"%s fd:%d, remote AF_INET, port=%x, IP addr=%s\n",
			__func__, sockfd,
			ntohs(ia.sin_port), ipl);

		hdr->ip_hdr.dst_addr = ia.sin_addr.s_addr;
		hdr->udp_hdr.dst_port = ia.sin_port;
	} else if (ia.sin_family == AF_INET6) {
		struct sockaddr_storage local_addr;
		struct sockaddr_in6 *ia6;

		/** Get socket name again.*/
		addrlen = sizeof(struct sockaddr_storage);
		ret = getpeername(sockfd, (struct sockaddr *)&local_addr,
				&addrlen);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: Get socket(%d) peer name failed(%d)(AF_INET6)\n",
				__func__, sockfd, ret);

			return ret;
		}
		ia6 = (void *)&local_addr;
		inet_ntop(AF_INET6, (void *)&ia6->sin6_addr, ipl, sizeof(ipl));
		map_ipv4_to_regular_ipv4(ipl);

		hdr->ip_hdr.dst_addr = ia6->sin6_addr.__in6_u.__u6_addr32[3];
		hdr->udp_hdr.dst_port = ia6->sin6_port;
		RTE_LOG(INFO, pre_ld,
			"%s fd:%d, AF_INET6: port=%x, IP addr=%s\n",
			__func__, sockfd, ntohs(ia6->sin6_port), ipl);
	} else {
		RTE_LOG(ERR, pre_ld,
			"%s: Get socket(%d) peer name: unsuppored family(%d)\n",
			__func__, sockfd, ia.sin_family);

		return ret;
	}

	s_fd_desc[sockfd].hdr_init |= (REMOTE_IP_INIT | REMOTE_UDP_INIT);

	return 0;
}

static int
netwrap_get_local_hw(int sockfd)
{
	int ret, offset = 0, i;
	struct ifreq ifr;
	char mac_addr[64];
	uint8_t addr_bytes[RTE_ETHER_ADDR_LEN];

	if ((s_fd_desc[sockfd].hdr_init & LOCAL_ETH_INIT) ==
		LOCAL_ETH_INIT)
		return 0;

	if (!s_slow_if) {
		RTE_LOG(ERR, pre_ld,
			"%s: No tap port specified!\n", __func__);
		return -EINVAL;
	}

	ifr.ifr_addr.sa_family = AF_INET;
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", s_slow_if);

	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if (ret < 0) {
		RTE_LOG(ERR, pre_ld,
			"ioctl SIOCGIFHWADDR error:%d\n", ret);
		return ret;
	}

	rte_memcpy(&s_fd_desc[sockfd].hdr.eth_hdr.src_addr,
		&ifr.ifr_hwaddr.sa_data,
		RTE_ETHER_ADDR_LEN);
	rte_memcpy(addr_bytes, &ifr.ifr_hwaddr.sa_data,
		RTE_ETHER_ADDR_LEN);
	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
		if (i != (RTE_ETHER_ADDR_LEN - 1)) {
			offset += sprintf(&mac_addr[offset],
				"%02x:", addr_bytes[i]);
		} else {
			offset += sprintf(&mac_addr[offset],
				"%02x",	addr_bytes[i]);
		}
	}
	RTE_LOG(INFO, pre_ld,
		"%s: socket fd:%d, Local Mac: %s\n",
		__func__, sockfd, mac_addr);

	s_fd_desc[sockfd].hdr_init |= LOCAL_ETH_INIT;

	return 0;
}

static int
netwrap_collect_info(int sockfd)
{
	int ret;

	ret = netwrap_get_local_ip(sockfd);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s: User socket(%d) Get local IP failed(%d)\n",
			__func__, sockfd, ret);
		return ret;
	}
	ret = netwrap_get_local_hw(sockfd);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s: User socket(%d) Get local HW failed(%d)\n",
			__func__, sockfd, ret);
		return ret;
	}
	ret = netwrap_get_remote_ip(sockfd);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s: User socket(%d) Get remote info failed(%d)\n",
			__func__, sockfd, ret);
		return ret;
	}
	ret = netwrap_get_remote_hw(sockfd);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s: User socket(%d) Get remote HW failed(%d)\n",
			__func__, sockfd, ret);
		return ret;
	}

	RTE_LOG(ERR, pre_ld,
		"User socket(%d) collect info successfully.\n",
		sockfd);

	return 0;
}

static int
socket_create_ingress_flow(int sockfd)
{
	struct rte_flow_item pattern[2];
	struct rte_flow_item_udp udp_item;
	struct rte_flow_item_udp udp_mask;

	if ((s_fd_desc[sockfd].hdr_init &
		(LOCAL_UDP_INIT | REMOTE_UDP_INIT)) !=
		(LOCAL_UDP_INIT | REMOTE_UDP_INIT)) {
		RTE_LOG(INFO, pre_ld,
			"%s: Socket(%d) UDP header not initialized.\n",
			__func__, sockfd);
		return -EINVAL;
	}

	memset(pattern, 0, sizeof(pattern));
	memset(&udp_item, 0, sizeof(udp_item));
	memset(&udp_mask, 0, sizeof(udp_mask));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[0].spec = &udp_item;
	pattern[0].mask = &udp_mask;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
	/** src received == local dst.*/
	udp_item.hdr.src_port =
		s_fd_desc[sockfd].hdr.udp_hdr.dst_port;
	udp_mask.hdr.src_port = 0xffff;
	/** dst received == local src.*/
	udp_item.hdr.dst_port =
		s_fd_desc[sockfd].hdr.udp_hdr.src_port;
	udp_mask.hdr.dst_port = 0xffff;

	return eal_create_flow(sockfd, pattern);
}

int
bind(int sockfd, const struct sockaddr *addr,
	socklen_t addrlen)
{
	int bind_value = 0;
	const struct sockaddr_in *sa = (const void *)addr;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, libc_bind:%p\n",
			__func__, sockfd, libc_bind);
		dump_usr_fd(__func__);
	}

	if (libc_bind) {
		bind_value = (*libc_bind)(sockfd, addr, addrlen);
	} else { /* pre init*/
		LIBC_FUNCTION(bind);

		if (libc_bind)
			bind_value = (*libc_bind)(sockfd, addr, addrlen);
		else {
			bind_value = -EACCES;
			errno = EACCES;
		}
	}

	RTE_LOG(INFO, pre_ld,
		"%s sockfd:%d, family(%d), port(%04x) %s.\n",
		__func__, sockfd, sa->sin_family,
		rte_be_to_cpu_16(sa->sin_port),
		bind_value ? "failed" : "successfully");

	return bind_value;
}

int
accept(int sockfd, struct sockaddr *addr,
	socklen_t *addrlen)
{
	int accept_value = 0;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, libc_bind:%p\n",
			__func__, sockfd, libc_accept);
		dump_usr_fd(__func__);
	}

	if (libc_accept) {
		accept_value = (*libc_accept)(sockfd, addr, addrlen);
	} else { /* pre init*/
		LIBC_FUNCTION(accept);

		if (libc_accept)
			accept_value = (*libc_accept)(sockfd, addr, addrlen);
		else {
			accept_value = -EACCES;
			errno = EACCES;
		}
	}

	return accept_value;
}

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int connect_value = 0, ret, offset = 0, connect_times = 0;
	const struct sockaddr_in *sa = (const void *)addr;
	const struct sockaddr_in6 *ia6 = (const void *)addr;
	char connect_info[512];
	char ipl[INET6_ADDRSTRLEN];
	const uint8_t *ip_addr;
#define CONNECT_MAX_TIMES 5

	if (unlikely(!libc_connect)) {
		LIBC_FUNCTION(connect);
		if (!libc_connect)
			rte_panic("Get libc %s failed!\n", __func__);
	}

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, libc_connect:%p\n",
			__func__, sockfd, libc_connect);
		dump_usr_fd(__func__);
	}

	if (is_usr_socket(sockfd)) {
connect_usr:
		connect_value = (*libc_connect)(sockfd, addr, addrlen);
		connect_times++;
		if (connect_times < CONNECT_MAX_TIMES && connect_value) {
			sleep(1);
			RTE_LOG(WARNING, pre_ld,
				"Connect user fd:%d failed, try again\n",
				sockfd);
			goto connect_usr;
		}
		if (connect_value)
			goto connect_quit;

		ret = netwrap_collect_info(sockfd);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s fd:%d, collect info failed(%d)\n",
				__func__, sockfd, ret);
			connect_value = ret;
			goto connect_quit;
		}

		connect_value = socket_create_ingress_flow(sockfd);
	} else {
connect_sys:
		connect_value = (*libc_connect)(sockfd, addr, addrlen);
		connect_times++;
		if (connect_times < CONNECT_MAX_TIMES && connect_value) {
			sleep(1);
			RTE_LOG(WARNING, pre_ld,
				"Connect sys fd:%d failed, try again\n",
				sockfd);
			goto connect_sys;
		}
	}

connect_quit:
	if (connect_value)
		offset = sprintf(connect_info, "failed(%d):", connect_value);
	else
		offset = sprintf(connect_info, "successfully:");

	if (sa->sin_family == AF_INET6) {
		inet_ntop(AF_INET6, &ia6->sin6_addr, ipl, sizeof(ipl));
		map_ipv4_to_regular_ipv4(ipl);
		sprintf(&connect_info[offset],
			"family(%d), port(%04x), addr(%s)",
			sa->sin_family, rte_be_to_cpu_16(sa->sin_port),
			ipl);
	} else {
		ip_addr = (const void *)&sa->sin_addr.s_addr;
		sprintf(&connect_info[offset],
			"family(%d), port(%04x), addr(%d.%d.%d.%d)",
			sa->sin_family, rte_be_to_cpu_16(sa->sin_port),
			ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
	}
	RTE_LOG(INFO, pre_ld, "Connect fd:%d, addrlen(%d) %s\n",
		sockfd, addrlen, connect_info);

	return connect_value;
}

ssize_t
read(int sockfd, void *buf, size_t len)
{
	ssize_t read_value;
	int ret;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, libc_read:%p\n",
			__func__, sockfd, libc_read);
		dump_usr_fd(__func__);
	}

	if (is_usr_socket(sockfd) && s_fd_desc[sockfd].flow)
		return eal_recv(sockfd, buf, len, 0);

	if (libc_read) {
		read_value = (*libc_read)(sockfd, buf, len);
	} else {
		LIBC_FUNCTION(read);

		if (libc_read) {
			read_value = (*libc_read)(sockfd, buf, len);
		} else {
			read_value = -EACCES;
			errno = EACCES;
		}
	}

	if (is_usr_socket(sockfd)) {
		ret = netwrap_collect_info(sockfd);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s Socket(%d) collect info failed(%d)\n",
				__func__, sockfd, ret);
		}

		ret = socket_create_ingress_flow(sockfd);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s Socket(%d) create ingress flow failed(%d)\n",
				__func__, sockfd, ret);
		}
	}

	return read_value;
}

ssize_t
write(int sockfd, const void *buf, size_t len)
{
	ssize_t write_value;
	int ret;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, libc_write:%p\n",
			__func__, sockfd, libc_write);
		dump_usr_fd(__func__);
	}

	if (likely(is_usr_socket(sockfd))) {
		if (unlikely((s_fd_desc[sockfd].hdr_init &
			HDR_INIT_ALL) != HDR_INIT_ALL)) {
			ret = netwrap_collect_info(sockfd);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"%s sockfd(%d) collect info failed(%d)\n",
					__func__, sockfd, ret);
				goto send_to_kernel;
			}
		}
		write_value = eal_send(sockfd, buf, len, 0);
		errno = 0;

		return write_value;
	}

send_to_kernel:
	if (libc_write) {
		write_value = (*libc_write)(sockfd, buf, len);
	} else {
		LIBC_FUNCTION(write);
		if (libc_write) {
			write_value = (*libc_write)(sockfd, buf, len);
		} else {
			write_value = -EACCES;
			errno = EACCES;
		}
	}

	return write_value;
}

ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t recv_value;
	int ret;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, libc_recv:%p\n",
			__func__, sockfd, libc_recv);
		dump_usr_fd(__func__);
	}

	if (is_usr_socket(sockfd) && s_fd_desc[sockfd].flow)
		return eal_recv(sockfd, buf, len, flags);

	if (libc_recv) {
		recv_value = (*libc_recv)(sockfd, buf, len, flags);
	} else { /* pre init*/
		LIBC_FUNCTION(recv);

		if (libc_recv) {
			recv_value = (*libc_recv)(sockfd, buf, len, flags);
		} else {
			recv_value = -EACCES;
			errno = EACCES;
		}
	}

	if (is_usr_socket(sockfd)) {
		ret = netwrap_collect_info(sockfd);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s Socket(%d) collect info failed(%d)\n",
				__func__, sockfd, ret);
		}

		ret = socket_create_ingress_flow(sockfd);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s Socket(%d) create ingress flow failed(%d)\n",
				__func__, sockfd, ret);
		}
	}

	return recv_value;
}

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
	ssize_t send_value;
	int ret;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, libc_send:%p\n",
			__func__, sockfd, libc_send);
		dump_usr_fd(__func__);
	}

	if (likely(is_usr_socket(sockfd))) {
		if (unlikely((s_fd_desc[sockfd].hdr_init &
			HDR_INIT_ALL) != HDR_INIT_ALL)) {
			ret = netwrap_collect_info(sockfd);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"%s sockfd(%d) collect info failed(%d)\n",
					__func__, sockfd, ret);
				goto send_to_kernel;
			}
		}
		send_value = eal_send(sockfd, buf, len, flags);
		errno = 0;

		return send_value;
	}

send_to_kernel:

	if (libc_send) {
		send_value = (*libc_send)(sockfd, buf, len, flags);
	} else {
		LIBC_FUNCTION(send);

		if (libc_send) {
			send_value = (*libc_send)(sockfd, buf, len, flags);
		} else {
			send_value = -EACCES;
			errno = EACCES;
		}
	}

	return send_value;
}

static int
select_usr_sys(int nfds, int usr_fd_num,
	int usr_fd[], int sys_fd_num, int sys_fd[],
	fd_set *readfds, struct timeval *timeout,
	fd_set *writefds, fd_set *exceptfds)
{
	struct timeval sys_timeout;
	int64_t total_usec = 1;
	fd_set sys_readfds;
	int select_value, i;

	sys_timeout.tv_sec = 0;
	sys_timeout.tv_usec = 1000 * 1000;

	if (timeout) {
		total_usec = timeout->tv_sec * 1000 * 1000 +
			sys_timeout.tv_usec;
	}
	select_value = 0;

	if (!usr_fd_num) {
		return (*libc_select)(nfds, readfds, writefds,
				exceptfds, timeout);
	}
	if (!sys_fd_num) {
		memset(readfds, 0, sizeof(fd_set));
		while (total_usec >= 0) {
			for (i = 0; i < usr_fd_num; i++) {
				if (recv_frame_available(usr_fd[i])) {
					select_value++;
					FD_SET(usr_fd[i], readfds);
				}
			}
			if (select_value > 0)
				break;
			if (timeout)
				total_usec -= sys_timeout.tv_usec;
		}
		return select_value;
	}

	while (total_usec >= 0) {
		memset(&sys_readfds, 0, sizeof(fd_set));
		for (i = 0; i < sys_fd_num; i++)
			FD_SET(sys_fd[i], &sys_readfds);
		select_value = (*libc_select)(nfds, &sys_readfds, writefds,
			exceptfds, &sys_timeout);
		for (i = 0; i < usr_fd_num; i++) {
			if (recv_frame_available(usr_fd[i])) {
				select_value++;
				FD_SET(usr_fd[i], &sys_readfds);
			}
		}
		if (select_value > 0) {
			rte_memcpy(readfds, &sys_readfds, sizeof(fd_set));
			break;
		}
		if (timeout)
			total_usec -= sys_timeout.tv_usec;
	}
	return select_value;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout)
{
	int select_value = 0, usr_fd_num = 0, sys_fd_num = 0;
	int ret, i, j, off;
	fd_set usr_readfds;
	fd_set sys_readfds;
	uint8_t *_usr, *_sys;
	const uint8_t *_fds;
	char usr_fd_buf[128];
	char sys_fd_buf[128];
	char sel_fd_buf[128];
	int usr_fd[MAX_USR_FD_NUM];
	int sys_fd[sizeof(fd_set) * 8];
	struct fd_desc *usr, *tusr;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: nfds:%d, libc_select:%p\n",
			__func__, nfds, libc_select);
		dump_usr_fd(__func__);
	}

	if (RTE_TAILQ_FIRST(&s_fd_desc_list) && readfds) {
		if (unlikely(!libc_select)) {
			LIBC_FUNCTION(select);
			if (!libc_select) {
				select_value = -1;
				errno = EACCES;

				return select_value;
			}
		}

		RTE_TAILQ_FOREACH_SAFE(usr, &s_fd_desc_list, next, tusr) {
			if (FD_ISSET(usr->fd, readfds) && usr->flow) {
				usr_fd[usr_fd_num] = usr->fd;
				usr_fd_num++;
			}
		}

		if (!usr_fd_num) {
			select_value = (*libc_select)(nfds, readfds, writefds,
				exceptfds, timeout);
			return select_value;
		}
		memset(&usr_readfds, 0, sizeof(fd_set));
		for (i = 0; i < usr_fd_num; i++)
			FD_SET(usr_fd[i], &usr_readfds);
		ret = memcmp(&usr_readfds, readfds, sizeof(fd_set));
		if (likely(!ret)) {
			/**User FD select only.*/
			return select_usr_sys(nfds, usr_fd_num, usr_fd,
				0, NULL, readfds, timeout,
				writefds, exceptfds);
		}

		off = 0;
		memset(usr_fd_buf, 0, sizeof(usr_fd_buf));
		memset(sys_fd_buf, 0, sizeof(sys_fd_buf));
		memset(sel_fd_buf, 0, sizeof(sys_fd_buf));
		for (i = 0; i < usr_fd_num; i++)
			off += sprintf(&usr_fd_buf[off], "%d ", usr_fd[i]);

		memset(&sys_readfds, 0, sizeof(fd_set));
		_usr = (void *)&usr_readfds;
		_sys = (void *)&sys_readfds;
		_fds = (void *)readfds;
		off = 0;
		for (i = 0; i < (int)sizeof(fd_set); i++) {
			_sys[i] = _fds[i] & (~_usr[i]);
			if (_sys[i]) {
				for (j = 0; j < 8; j++) {
					if ((1 << j) & _sys[i]) {
						sys_fd[sys_fd_num] = j + 8 * i;
						off += sprintf(&sys_fd_buf[off],
							"%d ",
							sys_fd[sys_fd_num]);
						sys_fd_num++;
					}
				}
			}
		}

		RTE_LOG(DEBUG, pre_ld,
			"Select user FDs(%d): %s and system FDs(%d): %s on core%d(%d)\n",
			usr_fd_num, usr_fd_buf, sys_fd_num, sys_fd_buf,
			sched_getcpu(), rte_lcore_id());

		if (1) {
			select_value = (*libc_select)(nfds, readfds, writefds,
				exceptfds, timeout);
		} else {
			select_value = select_usr_sys(nfds, usr_fd_num, usr_fd,
				sys_fd_num, sys_fd, readfds, timeout,
				writefds, exceptfds);
		}
	} else if (libc_select) {
		select_value = (*libc_select)(nfds, readfds, writefds,
			exceptfds, timeout);
	} else {
		LIBC_FUNCTION(select);

		if (libc_select) {
			select_value = (*libc_select)(nfds, readfds, writefds,
				exceptfds, timeout);
		} else {
			select_value = -1;
			errno = EACCES;
		}
	}

	if (select_value < 0) {
		RTE_LOG(ERR, pre_ld,
			"Select system FDs err(%d)\n", select_value);
	}

	return select_value;
}

__attribute__((destructor)) static void netwrap_main_dtor(void)
{
	if (!netwrap_is_usr_process())
		return;

	eal_quit();
	if (s_fd_desc)
		free(s_fd_desc);
	s_fd_desc = NULL;
	if (s_downlink)
		rte_free(s_downlink);
	s_downlink = NULL;
	if (s_uplink)
		rte_free(s_uplink);
	s_uplink = NULL;
	unsetenv(PRE_LOAD_USR_APP_NAME_ENV);
}

static void *
pre_ld_ipsec_restart(void *arg)
{
#define SWANCTL_CONF_DEFAULT_NAME "host-host1"
	int ret;
	char cmd[1024];
	char *desc = getenv("SWANCTL_CONF_NAME");
	char *env;

	env = getenv("IPSEC_RESTART");
	if (env && atoi(env)) {
		/** ALERT!: This command starts daemon which will
		 * prevent DPDK process running again.
		 * User should perform "ipsec stop" before running
		 * DPDK next time.
		 */
		ret = system("ipsec restart");
		sleep(2);
	}
	env = getenv("SWANCTL_LOAD_ALL");
	if (env && atoi(env)) {
		ret = system("swanctl --load-all");
		sleep(2);
	}
	env = getenv("STROKE_DOWN_UP");
	if (!env || !atoi(env))
		return arg;

	sprintf(cmd, "%s down %s", IPSEC_STROKE_PROCESS_NAME,
		desc ? desc : SWANCTL_CONF_DEFAULT_NAME);
	ret = system(cmd);
	RTE_LOG(INFO, pre_ld, "%s down %s\n",
		IPSEC_STROKE_PROCESS_NAME,
		ret ? "failed" : "success");
	sleep(1);
	sprintf(cmd, "%s up %s", IPSEC_STROKE_PROCESS_NAME,
		desc ? desc : SWANCTL_CONF_DEFAULT_NAME);
	ret = system(cmd);
	RTE_LOG(INFO, pre_ld, "%s up %s\n",
		IPSEC_STROKE_PROCESS_NAME,
		ret ? "failed" : "success");

	return arg;
}

static void
pre_ld_signal_handler(int signum)
{
	RTE_LOG(INFO, pre_ld,
		"Receive signum(%d)\n", signum);
	s_pre_ld_quit = 1;
}

__attribute__((constructor(PRE_LD_CONSTRUCTOR_PRIO)))
static void setup_wrappers(void)
{
	char *env;
	int i, ret;
	pthread_t pid;

	if (!netwrap_is_usr_process())
		return;

	for (i = 0; i < RTE_MAX_LCORE; i++) {
		s_pre_ld_lists[i].tqh_first = NULL;
		s_pre_ld_lists[i].tqh_last = &s_pre_ld_lists[i].tqh_first;
	}

	signal(SIGINT, pre_ld_signal_handler);
	signal(SIGTERM, pre_ld_signal_handler);

	if (!getenv("DPAA2_TX_CONF"))
		setenv("DPAA2_TX_CONF", "1", 1);

	if (!getenv("DPAA2_TX_DYNAMIC_CONF"))
		setenv("DPAA2_TX_DYNAMIC_CONF", "1", 1);

	if (!getenv("DPAA2_RX_GET_PROTOCOL_OFFSET"))
		setenv("DPAA2_RX_GET_PROTOCOL_OFFSET", "1", 1);

	s_in_pre_loading = 1;
	s_eal_file_prefix = getenv("file_prefix");

	env = getenv("PRE_LOAD_WRAP_LOG");
	if (env)
		s_socket_dbg = atoi(env);

	env = getenv("PRE_LOAD_STATISTIC_PRINT");
	if (env)
		s_statistic_print = atoi(env);

	env = getenv("PRE_LOAD_WRAP_CPU_START");
	if (env)
		s_cpu_start = atoi(env);

	env = getenv("PRE_LOAD_MANUAL_RESTART_IPSEC");
	if (env)
		s_manual_restart_ipsec = atoi(env);

	env = getenv("PRE_LOAD_IPSEC_BUF_SWAP");
	if (env)
		s_ipsec_buf_swap = atoi(env);

	env = getenv("PRE_LOAD_SET_MTU");
	if (env) {
		s_mtu_set = atoi(env);
		if (s_mtu_set < RTE_ETHER_MTU ||
			s_mtu_set > MAX_HUGE_FRAME_SIZE) {
			RTE_LOG(WARNING, pre_ld,
				"Invalid MTU size(%d) to set\n",
				s_mtu_set);
			s_mtu_set = 0;
		}
	}

	env = getenv("PRE_LOAD_DUMP_TRAFFIC_FLOW");
	if (env)
		s_dump_traffic_flow = atoi(env);

	env = getenv("PRE_LOAD_L3_DUMP_PROTOCOL");
	if (env)
		s_l3_traffic_dump = atoi(env);

	env = getenv("PRE_LOAD_L4_DUMP_PROTOCOL");
	if (env)
		s_l4_traffic_dump = atoi(env);

	env = getenv("PRE_LOAD_FLOW_CONTROL_ENABLE");
	if (env)
		s_flow_control = atoi(env);

	env = getenv("PRE_LOAD_FORCE_EAL_THREAD");
	if (env)
		s_force_eal_thread = atoi(env);

	env = getenv("PRE_LOAD_FD_RTE_RING");
	if (env)
		s_fd_rte_ring = atoi(env);

	if (!is_cpu_detected(s_cpu_start) ||
		!is_cpu_detected(s_cpu_start + 1)) {
		rte_exit(EXIT_FAILURE,
			"CPUs(%d, %d) not detected!\n",
			s_cpu_start, s_cpu_start + 1);
	}

	if (s_cpu_start == SYS_CORE_ID ||
		(s_cpu_start + 1) == SYS_CORE_ID) {
		rte_exit(EXIT_FAILURE,
			"CPUs(%d, %d) conflict with sys core(%d)!\n",
			s_cpu_start, s_cpu_start + 1, SYS_CORE_ID);
	}

	s_fd_desc = malloc(sizeof(struct fd_desc) * MAX_USR_FD_NUM);
	if (!s_fd_desc) {
		RTE_LOG(ERR, pre_ld,
			"Malloc %d FD descriptors failed\n",
			MAX_USR_FD_NUM);

		exit(EXIT_FAILURE);
	}
	for (i = 0; i < MAX_USR_FD_NUM; i++)
		s_fd_desc[i].fd = INVALID_SOCKFD;

	if (PRE_LD_CONSTRUCTOR_PRIO <= RTE_PRIORITY_LAST) {
		s_in_pre_loading = 0;
		return;
	}

	LIBC_FUNCTION(socket);
	LIBC_FUNCTION(shutdown);
	LIBC_FUNCTION(close);
	LIBC_FUNCTION(bind);
	LIBC_FUNCTION(accept);
	LIBC_FUNCTION(connect);
	LIBC_FUNCTION(read);
	LIBC_FUNCTION(write);
	LIBC_FUNCTION(recv);
	LIBC_FUNCTION(send);
	LIBC_FUNCTION(select);
	s_socket_pre_set = 1;

	/** Make sure all the (RTE_INIT)s have been done before here.
	 * user can manually change the RTE_PRIORITY_LAST to value
	 * less(higher prio) than this constructor function.
	 */
	ret = eal_main();
	if (!ret) {
		s_eal_inited = 1;
	} else {
		RTE_LOG(ERR, pre_ld,
			"eal init failed(%d)\n", ret);
		exit(EXIT_FAILURE);
	}

	if (!s_manual_restart_ipsec) {
		ret = pthread_create(&pid, NULL, pre_ld_ipsec_restart, NULL);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Create thread to restart ipsec failed(%d)\n",
				ret);
		}
	} else {
		/** Example of re-start ipsec manually on another terminal:
		 *
		 ipsec restart
		 swanctl --load-all
		 /usr/lib/ipsec/stroke down host-host1
		 /usr/lib/ipsec/stroke up host-host1
		 */
	}

	if (s_pre_ld_quit) {
		netwrap_main_dtor();
		RTE_LOG(INFO, pre_ld, "Exit from preload!\n");
		exit(0);
	}

	s_in_pre_loading = 0;
}
