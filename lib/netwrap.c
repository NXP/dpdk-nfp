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

#define PRE_LD_DIR_UPDATE_TIME_OUT (1000 * 1000 * 10)/**us*/
#define PRE_LD_DIR_UPDATE_WAIT_INTERVAL 10/**us*/

#define PRE_LD_DRAIN_RETRY_TIMES 10000

static int s_socket_pre_set;
static int s_in_pre_loading;

static int s_eal_inited;
static pthread_mutex_t s_eal_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_dp_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint16_t s_cpu_start = 1;
#define SYS_CORE_ID 0

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
static const char *s_slow_if;

static int s_manual_restart_ipsec;
static int s_flow_control;
static int s_force_eal_thread;

static int s_fd_rte_ring;
static int s_fd_mbuf_malloc_direct;
static int s_fd_mbuf_malloc_hw_pool;

static uint16_t s_fd_mbuf_avail_threshold = 128;

static uint16_t s_l3_traffic_dump;
static uint8_t s_l4_traffic_dump;

static char *s_ls_listni_info;
static const char *s_safe_ls_listni_info;

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

enum fd_access_type {
	FD_HARDWARE_ACCESS,
	FD_THREAD_ACCESS
};

struct fd_hw_desc {
	struct pre_ld_port_rx_flow *rx_flow;
	uint16_t tx_port;
};

struct fd_entry_desc {
	struct pre_ld_direct_entry *rx_entry;
	struct pre_ld_direct_entry *tx_entry;
	struct pre_ld_direct_entry *free_entry;
	struct pre_ld_direct_entry *malloc_entry;
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
	enum fd_access_type access_type;
	union fd_data_path_desc dp_desc;
	struct rte_mempool *tx_pool;
	struct pre_ld_rx_pool rx_buffer;

	rte_spinlock_t rx_lock;
	rte_spinlock_t tx_lock;
	int rx_enable;
	int tx_enable;

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

static int s_ipsec_ib_flow_ip_addr_extract;

pthread_mutex_t s_fd_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct fd_desc *s_fd_desc;

TAILQ_HEAD(fd_desc_list, fd_desc);
static struct fd_desc_list s_fd_desc_list =
	TAILQ_HEAD_INITIALIZER(s_fd_desc_list);

static rte_spinlock_t s_fd_list_lock;

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
static struct rte_ring *s_port_flow_r[RTE_MAX_ETHPORTS];
static struct pre_ld_port_rx_flow *s_def_flow[RTE_MAX_ETHPORTS];

static struct rte_ring *s_crypt_queue_ring[CRYPT_DEV_MAX_NUM];
static uint16_t *s_crypt_queue_ids[CRYPT_DEV_MAX_NUM];

static struct rte_eth_conf s_port_conf = {
	.rxmode = {0},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

enum pre_ld_dir_msg_type {
	INSERT_ENTRY_REQ = 1,
	REMOVE_ENTRY_REQ,
	UPDATE_ENTRY_SUCCESS_RSP,
	UPDATE_ENTRY_FAILED_RSP
};

struct pre_ld_dir_entry_update_msg {
	enum pre_ld_dir_msg_type msg_type;
	struct pre_ld_direct_entry *dir;
};

static struct rte_ring *s_dir_msg_req_r[RTE_MAX_LCORE];
static struct rte_ring *s_dir_msg_rsp_r[RTE_MAX_LCORE];

static struct rte_mempool *s_pre_ld_rx_pool;

struct pre_ld_dir_ul_dl_pair {
	int ul_id;
	int dl_id;
};

struct pre_ld_dir_kif {
	uint16_t tap_id;
	const char *kernel_nm;
};

#define PRE_LD_DIR_MAX_IF_NUM 8
struct pre_ld_dir_cfg {
	uint16_t ext_id[PRE_LD_DIR_MAX_IF_NUM];
	uint8_t ext_num;
	struct pre_ld_dir_ul_dl_pair pair[PRE_LD_DIR_MAX_IF_NUM];
	uint8_t pair_num;
	struct pre_ld_dir_ul_dl_pair recyc_pair[PRE_LD_DIR_MAX_IF_NUM];
	uint8_t recyc_pair_num;
	struct pre_ld_dir_kif kif[PRE_LD_DIR_MAX_IF_NUM];
	uint8_t kif_num;
};

#define PRE_LD_MUX_MAX_IF_NUM 8
struct pre_ld_mux_cfg {
	uint16_t mux_id;
	uint16_t def_id;
	const char *def_nm;
	const char *kernel_nm;
	uint16_t ep_id[PRE_LD_MUX_MAX_IF_NUM];
	const char *ep_nm[PRE_LD_MUX_MAX_IF_NUM];
	uint16_t port_id[PRE_LD_MUX_MAX_IF_NUM];
	int entry_id[PRE_LD_MUX_MAX_IF_NUM];
	uint8_t if_num;
};

#define PRE_LD_PROC_MAX_IF_NUM 8
struct pre_ld_proc_cfg {
	char def_nm[RTE_ETH_NAME_MAX_LEN];
	const char *kernel_nm;
	char uplink_nm[RTE_ETH_NAME_MAX_LEN];
	char downlink_nm[PRE_LD_PROC_MAX_IF_NUM][RTE_ETH_NAME_MAX_LEN];
	uint16_t port_id[PRE_LD_PROC_MAX_IF_NUM];
	int dir_configured[PRE_LD_PROC_MAX_IF_NUM];
	uint8_t if_num;
};

#define PRE_LD_MUX_MAX_NUM 4
static struct pre_ld_mux_cfg s_mux_cfg[PRE_LD_MUX_MAX_NUM];
static uint8_t s_mux_num;
static int s_mux_index = -1;

#define PRE_LD_PROC_MAX_NUM 4
static struct pre_ld_proc_cfg s_proc_cfg[PRE_LD_PROC_MAX_NUM];
static uint8_t s_proc_num;
static int s_proc_index = -1;

static struct pre_ld_dir_cfg s_dir_ports;
static int s_dir_recyc;

enum pre_ld_port_type {
	NULL_TYPE = 0,
	EXTERNAL_TYPE = (1 << 0),
	UP_LINK_TYPE = (1 << 1),
	DOWN_LINK_TYPE = (1 << 2),
	PROC_DOWN_LINK_TYPE = (1 << 3),
	MUX_DOWN_LINK_TYPE = (1 << 4),
	KERNEL_TAP_TYPE = (1 << 5),
	RECYCLE_UP_LINK_TYPE = (1 << 6),
	RECYCLE_DOWN_LINK_TYPE = (1 << 7)
};

#define IP_DEFTTL       64
#define IP_VERSION      0x40
#define IP_HDRLEN       0x05
#define IP_VHL_DEF      (IP_VERSION | IP_HDRLEN)

TAILQ_HEAD(pre_ld_lcore_direct_list, pre_ld_direct_entry);
static struct pre_ld_lcore_direct_list s_pre_ld_lists[RTE_MAX_LCORE];

/** Single core support only now.*/
static int s_pre_ld_quit;

/** Single rx/tx ports pair support only now, default 0.*/
static uint16_t s_rx_port;
static uint16_t s_tx_port;

static int s_data_path_core = -1;

static int s_ipsec_buf_swap;

#define MAX_HUGE_FRAME_SIZE 9600
static uint16_t s_mtu_set;
static int s_dump_traffic_flow;
static int s_select_dbg;

static int s_data_verify;
static int s_data_verify_err_panic;

static uint16_t s_mempool_cache_size;
static int s_pause_traffic_flow_updating;

struct pre_ld_default_direction {
	struct rte_remote_dir_req *def_dir;
	const struct pre_ld_port_rx_flow *rx_flows[MAX_DEF_DIR_NUM];
	uint16_t to_ids[MAX_DEF_DIR_NUM];
	struct rte_flow *flows[MAX_DEF_DIR_NUM];
};

static struct pre_ld_default_direction s_pre_ld_def_dir;

static struct pre_ld_port_rx_flow *s_pre_ld_rx_flows[RTE_MAX_ETHPORTS];
static struct pre_ld_port_rx_source *s_pre_ld_rx_src[RTE_MAX_ETHPORTS];

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
		if (unlikely(idx == num))
			break;
		plr->pre_ld_elems[pos] = elem[idx];
		idx++;
		pos = (pos + 1) & (plr->pre_ld_size - 1);
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
		if (unlikely(idx == num))
			break;
		elem[idx] = plr->pre_ld_elems[pos];
		idx++;
		pos = (pos + 1) & (plr->pre_ld_size - 1);
	}
	rte_io_wmb();
	rte_io_rmb();
	plr->pre_ld_head = pos;

	return idx;
}

static inline uint16_t
pre_ld_ring_count(const struct pre_ld_ring *plr)
{
	if (plr->pre_ld_tail >= plr->pre_ld_head)
		return plr->pre_ld_tail - plr->pre_ld_head;

	return plr->pre_ld_size - plr->pre_ld_head - 1 + plr->pre_ld_tail;
}

static inline int
pre_ld_update_dir_list_safe(struct pre_ld_direct_entry *dir,
	enum pre_ld_dir_msg_type type)
{
	struct pre_ld_dir_entry_update_msg req, *rsp;
	struct rte_ring *req_r, *rsp_r;
	int ret, timeout = PRE_LD_DIR_UPDATE_TIME_OUT;

	if (s_data_path_core < 0)
		return -EACCES;

	req_r = s_dir_msg_req_r[s_data_path_core];
	rsp_r = s_dir_msg_rsp_r[s_data_path_core];

	req.msg_type = type;
	req.dir = dir;

req_again:
	ret = rte_ring_enqueue(req_r, &req);
	if (ret) {
		usleep(PRE_LD_DIR_UPDATE_WAIT_INTERVAL);
		timeout -= PRE_LD_DIR_UPDATE_WAIT_INTERVAL;
		if (timeout < 0)
			return -EBUSY;
		goto req_again;
	}

	timeout = PRE_LD_DIR_UPDATE_TIME_OUT;
rsp_again:
	ret = rte_ring_dequeue(rsp_r, (void **)&rsp);
	if (ret) {
		usleep(PRE_LD_DIR_UPDATE_WAIT_INTERVAL);
		timeout -= PRE_LD_DIR_UPDATE_WAIT_INTERVAL;
		if (timeout < 0)
			return -EBUSY;
		goto rsp_again;
	}
	if (rsp != &req) {
		RTE_LOG(ERR, pre_ld,
			"%s: response(%p) != request(%p)\n",
			__func__, rsp, &req);
		return -EIO;
	}
	if (rsp->msg_type != UPDATE_ENTRY_SUCCESS_RSP) {
		RTE_LOG(ERR, pre_ld,
			"%s: Get failed or un-expected response(%d)\n",
			__func__, rsp->msg_type);
		return -EINVAL;
	}

	return 0;
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
			RTE_LOG(DEBUG, pre_ld,
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

		RTE_LOG(DEBUG, pre_ld,
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

static void
pre_ld_rx_flow_verify_set(struct pre_ld_port_rx_flow *rx_flow,
	enum pre_ld_cmp_offset type, uint8_t offset, uint8_t size,
	const uint8_t *cmp_data)
{
	if (!s_data_verify || !size) {
		rx_flow->cmp_offset_type = PRE_LD_NO_CMP;
		return;
	}
	rx_flow->cmp_offset_type = type;
	rx_flow->cmp_offset = offset;
	rx_flow->cmp_size = size;
	rte_memcpy(rx_flow->cmp_data, cmp_data, size);
}

static int
pre_ld_flow_destroy(uint16_t port, struct rte_flow *flow)
{
	int ret, times = PRE_LD_FLOW_DESTROY_TRY_TIMES;

again:
	ret = rte_flow_destroy(port, flow, NULL);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s: Destroy flow failed(%d), times=%d\n",
			__func__, ret, times);
	}
	if (ret == -EAGAIN && times > 0) {
		times--;
		goto again;
	}

	return ret;
}

static void
eal_destroy_dpaa2_mux_flow(void)
{
	int ret, i, j, entry;
	uint32_t id;

	for (i = 0; i < s_mux_num; i++) {
		for (j = 0; j < PRE_LD_MUX_MAX_IF_NUM; j++) {
			entry = s_mux_cfg[i].entry_id[j];
			id = s_mux_cfg[i].mux_id;
			if (entry < 0)
				continue;
			ret = rte_pmd_dpaa2_mux_flow_destroy(id, entry);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"Destroy MUX%d's flow entry%d failed(%d)\n",
					id, entry, ret);
			}
			s_mux_cfg[i].entry_id[j] = -1;
		}
	}
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

static inline int
is_usr_socket_connected(int sockfd)
{
	struct fd_desc *desc = &s_fd_desc[sockfd];

	if (desc->access_type == FD_THREAD_ACCESS &&
		desc->dp_desc.entry_desc.rx_entry &&
		desc->dp_desc.entry_desc.rx_entry->poll.rx_flow &&
		desc->dp_desc.entry_desc.rx_entry->poll.rx_flow->flow)
		return true;

	if (desc->access_type == FD_HARDWARE_ACCESS &&
		desc->dp_desc.hw_desc.rx_flow &&
		desc->dp_desc.hw_desc.rx_flow->flow)
		return true;

	return false;
}

static void
usr_socket_fd_remove(int sockfd)
{
	rte_spinlock_lock(&s_fd_list_lock);
	TAILQ_REMOVE(&s_fd_desc_list, &s_fd_desc[sockfd], next);
	rte_spinlock_unlock(&s_fd_list_lock);
	RTE_LOG(INFO, pre_ld, "FD(%d) was removed from user sockets.\n",
		sockfd);
}

static int
usr_socket_fd_release(int sockfd)
{
	int ret = 0, i;
	uint16_t rx_port;
	struct pre_ld_rx_pool *rx_pool;
	struct rte_ring *tx_ring = NULL, *rx_ring = NULL;
	struct rte_ring *malloc_ring = NULL, *free_ring = NULL;
	struct pre_ld_ring *pre_ld_tx_ring = NULL;
	struct pre_ld_ring *pre_ld_rx_ring = NULL;
	struct pre_ld_ring *pre_ld_free_ring = NULL;
	struct pre_ld_ring *pre_ld_malloc_ring = NULL;
	struct pre_ld_port_rx_flow *rx_flow = NULL;
	struct fd_thread_desc *th_desc;
	struct fd_desc *desc = &s_fd_desc[sockfd];
	struct pre_ld_direct_entry *rx_entry = NULL;
	struct pre_ld_direct_entry *tx_entry = NULL;
	struct pre_ld_direct_entry *free_entry = NULL;
	struct pre_ld_direct_entry *malloc_entry = NULL;
	struct rte_mempool *malloc_pool = NULL;

	pthread_mutex_lock(&s_fd_mutex);

	rte_spinlock_lock(&desc->rx_lock);
	desc->rx_enable = false;
	rte_spinlock_unlock(&desc->rx_lock);
	rte_spinlock_lock(&desc->tx_lock);
	desc->tx_enable = false;
	rte_spinlock_unlock(&desc->tx_lock);

	if (desc->tx_pool) {
		malloc_pool = desc->tx_pool;
	} else if (desc->access_type == FD_THREAD_ACCESS) {
		malloc_entry = desc->dp_desc.entry_desc.malloc_entry;
		if (malloc_entry &&
			malloc_entry->poll.malloc_pool != s_pre_ld_rx_pool)
			malloc_pool = malloc_entry->poll.malloc_pool;
	}

	if (desc->access_type == FD_HARDWARE_ACCESS) {
		rx_flow = desc->dp_desc.hw_desc.rx_flow;
		rx_port = rx_flow->src->port_id;
	} else {
		rx_entry = desc->dp_desc.entry_desc.rx_entry;
		tx_entry = desc->dp_desc.entry_desc.tx_entry;
		free_entry = desc->dp_desc.entry_desc.free_entry;
		rx_flow = rx_entry->poll.rx_flow;
		rx_port = rx_flow->src->port_id;
		if (rx_entry && rx_entry->dest_type == RX_RING)
			rx_ring = rx_entry->dest.rx_ring;
		else if (rx_entry)
			pre_ld_rx_ring = rx_entry->dest.pre_ld_rx_ring;
		if (tx_entry && tx_entry->poll_type == TX_RING)
			tx_ring = tx_entry->poll.tx_ring;
		else if (tx_entry)
			pre_ld_tx_ring = tx_entry->poll.pre_ld_tx_ring;
		if (free_entry && free_entry->poll_type == MBUF_FREE_RING)
			free_ring = free_entry->poll.free_ring;
		else if (free_entry)
			pre_ld_free_ring = free_entry->poll.pre_ld_free_ring;
	}

	if (malloc_entry && malloc_entry->dest_type == MALLOC_RING)
		malloc_ring = malloc_entry->dest.malloc_ring;
	else if (malloc_entry)
		pre_ld_malloc_ring = malloc_entry->dest.pre_ld_malloc_ring;

	if (rx_entry && is_usr_socket_connected(sockfd)) {
		ret = pre_ld_update_dir_list_safe(rx_entry, REMOVE_ENTRY_REQ);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s remove FD[%d]'s RX entry failed(%d)\n",
				__func__, sockfd, ret);
		}
		if (ret == (-EBUSY) && rx_flow && rx_flow->flow) {
			ret = pre_ld_flow_destroy(rx_port, rx_flow->flow);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"%s line %d: destroy FD[%d]'s flow failed(%d)\n",
					__func__, __LINE__, sockfd, ret);
			}
		}
	}
	if (rx_entry && rx_entry->poll_prefix)
		rte_free(rx_entry->poll_prefix);
	if (rx_entry && rx_entry->action_prefix)
		rte_free(rx_entry->action_prefix);
	if (rx_entry) {
		rte_free(rx_entry);
		desc->dp_desc.entry_desc.rx_entry = NULL;
	}

	if (tx_entry) {
		ret = pre_ld_update_dir_list_safe(tx_entry, REMOVE_ENTRY_REQ);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s remove FD[%d]'s TX entry failed(%d)\n",
				__func__, sockfd, ret);
		}
		if (tx_entry->poll_prefix)
			rte_free(tx_entry->poll_prefix);
		if (tx_entry->action_prefix)
			rte_free(tx_entry->action_prefix);
		rte_free(tx_entry);
		desc->dp_desc.entry_desc.tx_entry = NULL;
	}

	if (free_entry) {
		ret = pre_ld_update_dir_list_safe(free_entry, REMOVE_ENTRY_REQ);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s remove FD[%d]'s free entry failed(%d)\n",
				__func__, sockfd, ret);
		}
		if (free_entry->poll_prefix)
			rte_free(free_entry->poll_prefix);
		if (free_entry->action_prefix)
			rte_free(free_entry->action_prefix);
		rte_free(free_entry);
		desc->dp_desc.entry_desc.free_entry = NULL;
	}

	if (malloc_entry) {
		ret = pre_ld_update_dir_list_safe(malloc_entry,
			REMOVE_ENTRY_REQ);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s remove FD[%d]'s malloc entry failed(%d)\n",
				__func__, sockfd, ret);
		}
		if (malloc_entry->poll_prefix)
			rte_free(malloc_entry->poll_prefix);
		if (malloc_entry->action_prefix)
			rte_free(malloc_entry->action_prefix);
		rte_free(malloc_entry);
		desc->dp_desc.entry_desc.malloc_entry = NULL;
	}

	if (desc->access_type == FD_HARDWARE_ACCESS) {
		ret = pre_ld_flow_destroy(rx_port, rx_flow->flow);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s destroy FD[%d]'s rte flow failed(%d)\n",
				__func__, sockfd, ret);
		}
		rx_flow->flow = NULL;
	}

	ret = rte_ring_enqueue(s_port_flow_r[rx_port], rx_flow);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s release FD[%d]'s RX flow failed(%d)\n",
			__func__, sockfd, ret);
	}

	if (pre_ld_rx_ring)
		pre_ld_ring_free(pre_ld_rx_ring);

	if (rx_ring)
		rte_ring_free(rx_ring);

	if (pre_ld_tx_ring)
		pre_ld_ring_free(pre_ld_tx_ring);

	if (tx_ring)
		rte_ring_free(tx_ring);

	if (pre_ld_free_ring)
		pre_ld_ring_free(pre_ld_free_ring);

	if (free_ring)
		rte_ring_free(free_ring);

	if (pre_ld_malloc_ring)
		pre_ld_ring_free(pre_ld_malloc_ring);

	if (malloc_ring)
		rte_ring_free(malloc_ring);

	rx_pool = &desc->rx_buffer;
	if (rx_pool->rx_bufs) {
		while (rx_pool->head != rx_pool->tail) {
			rte_pktmbuf_free(rx_pool->rx_bufs[rx_pool->head]);
			rx_pool->head = (rx_pool->head + 1) &
				(rx_pool->max_num - 1);
		}
		rte_free(desc->rx_buffer.rx_bufs);
	}

	if (malloc_pool)
		rte_mempool_free(malloc_pool);

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

static inline int
pre_ld_drain_traffic_again(struct rte_mbuf *mbufs[], uint16_t nb_rx,
	uint16_t *drain_times)
{
	if (nb_rx) {
		rte_pktmbuf_free_bulk(mbufs, nb_rx);
		*drain_times = 0;
		return true;
	}
	(*drain_times)++;
	if ((*drain_times) > PRE_LD_DRAIN_RETRY_TIMES)
		return false;
	return true;
}
static void eal_quit(void)
{
	uint16_t portid;
	int ret;
	struct pre_ld_lcore_direct_list *list;
	struct pre_ld_direct_entry *entry;
	const struct pre_ld_port_rx_source *src;

	usr_socket_force_release();

	if (s_data_path_core >= 0) {
		list = &s_pre_ld_lists[s_data_path_core];
		while (RTE_TAILQ_FIRST(list)) {
			entry = RTE_TAILQ_FIRST(list);
			ret = pre_ld_update_dir_list_safe(entry,
				REMOVE_ENTRY_REQ);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"%s: Remove entry failed(%d)",
					__func__, ret);
				if (ret == (-EBUSY) &&
					entry->poll_type == RX_QUEUE &&
					entry->poll.rx_flow &&
					entry->poll.rx_flow->flow) {
					src = entry->poll.rx_flow->src;
					ret = pre_ld_flow_destroy(src->port_id,
						entry->poll.rx_flow->flow);
					if (ret) {
						RTE_LOG(ERR, pre_ld,
							"%s: remove flow failed(%d)\n",
							__func__, ret);
					}
				}
			}
			rte_free(entry);
		}
	}

	s_pre_ld_quit = 1;

	eal_destroy_dpaa2_mux_flow();
	RTE_ETH_FOREACH_DEV(portid) {
		RTE_LOG(INFO, pre_ld, "Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"rte_eth_dev_stop: err=%d, port=%d\n",
				ret, portid);
		}
		rte_eth_dev_close(portid);
		rte_ring_free(s_port_flow_r[portid]);
		s_port_flow_r[portid] = NULL;
		s_def_flow[portid] = NULL;
		rte_free(s_pre_ld_rx_flows[portid]);
		s_pre_ld_rx_flows[portid] = NULL;
		rte_free(s_pre_ld_rx_src[portid]);
		s_pre_ld_rx_src[portid] = NULL;
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
		if (s_data_verify_err_panic) {
			rte_panic("%s line %d: verify failure!\r\n",
				__func__, __LINE__);
		}
		return -EINVAL;
	}

	udp_hdr = rte_pktmbuf_mtod_offset(mbuf, void *, l4_offset);
	if (unlikely(udp_hdr->src_port != flow_hdr->dst_port ||
		udp_hdr->dst_port != flow_hdr->src_port)) {
		RTE_LOG(WARNING, pre_ld,
			"FD(%d): UDP(%p) RX ERR(src %04x!=%04x, dst %04x!=%04x)\n",
			sockfd, udp_hdr, udp_hdr->src_port, flow_hdr->dst_port,
			udp_hdr->dst_port, flow_hdr->src_port);
		rte_pktmbuf_dump(stdout, mbuf, 60);
		if (s_data_verify_err_panic) {
			rte_panic("%s line %d: verify failure!\r\n",
				__func__, __LINE__);
		}
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

static void
usr_data_path_free_mbuf(struct fd_desc *desc,
	struct rte_mbuf *mbufs[], uint32_t count)
{
	uint32_t freed = 0;
	struct pre_ld_direct_entry *free_entry;
	struct rte_ring *free_ring;
	struct pre_ld_ring *pre_ld_free_ring;

	if (desc->access_type == FD_THREAD_ACCESS) {
		free_entry = desc->dp_desc.entry_desc.free_entry;
		if (unlikely(!free_entry)) {
			/** FD close, have to leak memory*/
			return;
		}
		if (free_entry->poll_type == MBUF_FREE_RING) {
			free_ring = free_entry->poll.free_ring;
			if (unlikely(!free_ring)) {
				/** FD close, have to leak memory*/
				return;
			}
			while (freed != count) {
				freed += rte_ring_enqueue_burst(free_ring,
					(void * const *)&mbufs[freed],
					count - freed, NULL);
			}
		} else if (free_entry->poll_type == PRE_LD_MBUF_FREE_RING) {
			pre_ld_free_ring = free_entry->poll.pre_ld_free_ring;
			if (unlikely(!pre_ld_free_ring)) {
				/** FD close, have to leak memory*/
				return;
			}
			while (freed != count) {
				freed += pre_ld_ring_eq(pre_ld_free_ring,
					(void **)&mbufs[freed], count - freed);
			}
		} else {
			RTE_LOG(ERR, pre_ld,
				"%s: Invalid poll type(%d)\n",
				__func__, free_entry->poll_type);
		}
	} else {
		rte_pktmbuf_free_bulk(mbufs, count);
	}
}

static int
usr_data_path_malloc_mbuf(struct fd_desc *desc,
	struct rte_mbuf *mbufs[], uint32_t count)
{
	uint16_t alloc;
	struct pre_ld_direct_entry *entry;

	if (desc->tx_pool)
		return rte_pktmbuf_alloc_bulk(desc->tx_pool, mbufs, count);

	entry = desc->dp_desc.entry_desc.malloc_entry;
	if (entry->dest_type == MALLOC_RING) {
		alloc = rte_ring_dequeue_bulk(entry->dest.malloc_ring,
			(void **)mbufs, count, NULL);
		if (!alloc)
			return -ENOENT;
		return 0;
	}

	if (pre_ld_ring_count(entry->dest.pre_ld_malloc_ring) < count)
		return -ENOENT;

	alloc = pre_ld_ring_dq(entry->dest.pre_ld_malloc_ring,
			(void **)mbufs, count);
	RTE_ASSERT(alloc == count);

	return 0;
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
	struct fd_desc *desc;
	struct pre_ld_rx_pool *rx_pool;
	struct pre_ld_direct_entry *rx_entry;
	struct fd_hw_desc *hw_desc;

	RTE_SET_USED(flags);

	rte_spinlock_lock(&s_fd_list_lock);
	if (unlikely(!is_usr_socket(sockfd))) {
		rte_spinlock_unlock(&s_fd_list_lock);
		return 0;
	}
	rte_spinlock_unlock(&s_fd_list_lock);

	desc = &s_fd_desc[sockfd];
	rx_pool = &desc->rx_buffer;

	ret = eal_data_path_thread_register(desc);
	if (ret)
		return ret;

	rte_spinlock_lock(&desc->rx_lock);

	if (unlikely(!desc->rx_enable))
		goto finsh_recv;

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
			usr_data_path_free_mbuf(desc, free_burst, i);
			i = 0;
		}
	}

	if (i > 0)
		usr_data_path_free_mbuf(desc, free_burst, i);

	if (!remain)
		goto finsh_recv;

	if (desc->access_type == FD_THREAD_ACCESS) {
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
		nb_rx = rte_eth_rx_burst(hw_desc->rx_flow->src->port_id,
			hw_desc->rx_flow->src->queue_id, pkts_burst,
			MAX_PKT_BURST);
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

	usr_data_path_free_mbuf(desc, free_burst, j);
	while (i != nb_rx) {
		if (unlikely(((rx_pool->tail + 1) &
			(rx_pool->max_num - 1)) == rx_pool->head)) {
			RTE_LOG(ERR, pre_ld,
				"RX pool is too small?\n");
			usr_data_path_free_mbuf(desc, &pkts_burst[i],
				nb_rx - i);
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
	rte_spinlock_unlock(&desc->rx_lock);

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
	struct pre_ld_direct_entry *tx_entry;
	struct fd_hw_desc *hw_desc;
	struct fd_desc *desc;

	RTE_SET_USED(flags);
	rte_spinlock_lock(&s_fd_list_lock);
	if (unlikely(!is_usr_socket(sockfd))) {
		rte_spinlock_unlock(&s_fd_list_lock);
		return 0;
	}
	rte_spinlock_unlock(&s_fd_list_lock);

	desc = &s_fd_desc[sockfd];

	ret = eal_data_path_thread_register(desc);
	if (ret)
		return 0;

	rte_spinlock_lock(&desc->tx_lock);

	if (unlikely(!desc->tx_enable))
		goto quit_send;

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
	ret = usr_data_path_malloc_mbuf(desc, mbufs, count);
	if (unlikely(ret)) {
		ret = 0;
		count = 0;
		goto quit_send;
	}

	eal_send_fill_mbufs(sockfd, buf, lens, mbufs, count);

	if (desc->access_type == FD_THREAD_ACCESS) {
		tx_entry = desc->dp_desc.entry_desc.tx_entry;
		if (tx_entry->poll_type == TX_RING) {
			sent = rte_ring_enqueue_bulk(tx_entry->poll.tx_ring,
				(void * const *)mbufs, count, NULL);
		} else {
			sent = pre_ld_ring_eq(tx_entry->poll.pre_ld_tx_ring,
				(void **)mbufs, count);
		}
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

	rte_spinlock_unlock(&desc->tx_lock);

	return ret;
}

void
pre_ld_deconfigure_sec_path(struct pre_ld_ipsec_sp_entry *sp)
{
	uint16_t queue_id, rx_port, sec_id;
	uint16_t *sec_qid;
	char src_info[128], sec_info[128], dst_info[128];
	int ret;
	struct pre_ld_direct_entry *entry_to_sec;
	struct pre_ld_direct_entry *entry_from_sec;

	entry_to_sec = sp->entry_to_sec;
	entry_from_sec = sp->entry_from_sec;
	sp->entry_to_sec = NULL;
	sp->entry_from_sec = NULL;
	rx_port = entry_to_sec->poll.rx_flow->src->port_id;
	queue_id = entry_to_sec->poll.rx_flow->src->queue_id;
	sec_id = entry_to_sec->dest.dest_sec.sec_id;
	sec_qid = entry_to_sec->dest.dest_sec.queue_id;
	sprintf(src_info, "Port%d/rxq%d", rx_port, queue_id);
	sprintf(sec_info, "Sec%d/queue%d", sec_id, *sec_qid);
	ret = pre_ld_update_dir_list_safe(entry_to_sec, REMOVE_ENTRY_REQ);
	if (ret) {
		RTE_LOG(ERR, pre_ld, "%s: remove SEC eq entry failed(%d)\n",
			__func__, ret);
		if (ret == (-EBUSY) && entry_to_sec->poll.rx_flow->flow) {
			ret = pre_ld_flow_destroy(rx_port,
				entry_to_sec->poll.rx_flow->flow);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"%s line %d: remove flow -> SEC failed(%d)\n",
					__func__, __LINE__, ret);
			}
		}
	}
	ret = rte_ring_enqueue(s_port_flow_r[rx_port],
		entry_to_sec->poll.rx_flow);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s: Free RX flow to %s failed(%d)\n",
			__func__, s_port_flow_r[rx_port]->name, ret);
	}
	sprintf(dst_info, "Port%d", entry_from_sec->dest.dest_port);
	ret = pre_ld_update_dir_list_safe(entry_from_sec, REMOVE_ENTRY_REQ);
	if (ret) {
		RTE_LOG(ERR, pre_ld, "%s: remove SEC dq entry failed(%d)\n",
			__func__, ret);
	}

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

static void
pre_ld_entry_traffic_dump(const char *prefix,
	uint16_t nb_rx, struct rte_mbuf *mbufs[])
{
	uint16_t i;

	if (unlikely(s_l3_traffic_dump || s_l4_traffic_dump)) {
		for (i = 0; i < nb_rx; i++)
			pre_ld_l3_l4_traffic_dump(mbufs[i], prefix);
	}
	if (unlikely(s_dump_traffic_flow && nb_rx > 0)) {
		RTE_LOG(INFO, pre_ld, "%s\n", prefix);
		for (i = 0; i < nb_rx; i++)
			rte_pktmbuf_dump(stdout, mbufs[i], 60);
		RTE_LOG(INFO, pre_ld, "%s done(%d mbuf(s))\n",
			prefix, nb_rx);
	}
}

static int
pre_ld_entry_rx_flow_verify(struct rte_mbuf *mbuf,
	struct pre_ld_direct_entry *entry)
{
	int ret = 0, i;
	uint8_t offset = 0xff, *data, off = 0;
	const struct pre_ld_port_rx_flow *rx_flow;
	char cmp1[64], cmp2[64];

	rx_flow = entry->poll.rx_flow;
	if (rx_flow->cmp_offset_type == PRE_LD_CMP_L3_OFFSET)
		ret = rte_pmd_dpaa2_rx_get_offset(mbuf, &offset, NULL, NULL);
	else if (rx_flow->cmp_offset_type == PRE_LD_CMP_L4_OFFSET)
		ret = rte_pmd_dpaa2_rx_get_offset(mbuf, NULL, &offset, NULL);
	else if (rx_flow->cmp_offset_type == PRE_LD_CMP_L5_OFFSET)
		ret = rte_pmd_dpaa2_rx_get_offset(mbuf, NULL, NULL, &offset);
	else
		return 0;

	if (unlikely(ret) || offset == 0xff) {
		RTE_LOG(WARNING, pre_ld,
			"%s parse %s %s failed\n",
			rx_flow->cmp_offset_type == PRE_LD_CMP_L3_OFFSET ?
			"L3" :
			rx_flow->cmp_offset_type == PRE_LD_CMP_L4_OFFSET ?
			"L4" : "L5",
			entry->poll_prefix, entry->action_prefix);
		rte_pktmbuf_dump(stdout, mbuf, 60);
		if (s_data_verify_err_panic) {
			rte_panic("%s line %d: verify failure!\r\n",
				__func__, __LINE__);
		}
		return -EINVAL;
	}
	offset += rx_flow->cmp_offset;
	data = rte_pktmbuf_mtod_offset(mbuf, void *, offset);
	if (!memcmp(data, rx_flow->cmp_data, rx_flow->cmp_size))
		return 0;

	for (i = 0; i < rx_flow->cmp_size; i++) {
		sprintf(&cmp1[off], "%02x ", rx_flow->cmp_data[i]);
		off += sprintf(&cmp2[off], "%02x ", data[i]);
	}
	RTE_LOG(ERR, pre_ld,
		"%s %s: data received %s don't match: %s\n",
		entry->poll_prefix, entry->action_prefix, cmp2, cmp1);
	rte_pktmbuf_dump(stdout, mbuf, 60);
	if (s_data_verify_err_panic) {
		rte_panic("%s line %d: verify failure!\r\n",
			__func__, __LINE__);
	}

	return -EACCES;
}

static uint16_t
pre_ld_entry_port_recv(struct pre_ld_direct_entry *entry,
	struct rte_mbuf *mbufs[], uint64_t lens[])
{
	uint16_t nb_rx, i, j = 0;
	const struct pre_ld_port_rx_flow *rx_flow;
	struct rte_mbuf *rx_mbufs[MAX_PKT_BURST];
	struct rte_mbuf **pmbufs;
	int ret;

	rx_flow = entry->poll.rx_flow;

	if (rx_flow->cmp_offset_type == PRE_LD_NO_CMP)
		pmbufs = mbufs;
	else
		pmbufs = rx_mbufs;

	nb_rx = rte_eth_rx_burst(rx_flow->src->port_id,
		rx_flow->src->queue_id, pmbufs, MAX_PKT_BURST);
	if (unlikely(!nb_rx))
		return 0;

	if (rx_flow->cmp_offset_type != PRE_LD_NO_CMP)
		goto cmp_rx_data;

	for (i = 0; i < nb_rx; i++)
		lens[i] = mbufs[i]->pkt_len + RTE_TM_ETH_FRAMING_OVERHEAD_FCS;

	goto recv_complete;

cmp_rx_data:
	for (i = 0; i < nb_rx; i++) {
		ret = pre_ld_entry_rx_flow_verify(rx_mbufs[i], entry);
		if (ret) {
			rte_pktmbuf_free(rx_mbufs[i]);
			continue;
		}
		mbufs[j] = rx_mbufs[i];
		lens[j] = mbufs[j]->pkt_len + RTE_TM_ETH_FRAMING_OVERHEAD_FCS;
		j++;
	}
	nb_rx = j;

recv_complete:
	pre_ld_entry_traffic_dump(entry->poll_prefix, nb_rx, mbufs);

	return nb_rx;
}

static void
pre_ld_entry_stat_update(struct pre_ld_dir_statistic *stat,
	uint64_t lens[], uint16_t nb_rx, int is_sec)
{
	uint16_t i;

	if (is_sec && lens) {
		for (i = 0; i < nb_rx; i++)
			stat->sec_bytes += lens[i];
	} else if (lens) {
		for (i = 0; i < nb_rx; i++)
			stat->oh_bytes += lens[i];
	}

	stat->pkts += nb_rx;
	stat->count++;
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

static uint16_t
pre_ld_direct_to_crypto(struct pre_ld_direct_entry *entry,
	struct rte_mbuf *mbufs[], uint16_t nb_rx)
{
	uint16_t crypto_id = entry->dest.dest_sec.sec_id;
	uint16_t queueid = *entry->dest.dest_sec.queue_id;
	void *sa = NULL;
	enum pre_ld_crypto_dir dir = EGRESS_CRYPTO_EQ;
	uint16_t i;
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

	return pre_ld_ipsec_sa_enqueue(mbufs, sa, nb_rx,
		crypto_id, queueid);
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

static void
pre_ld_entry_sec_start(struct pre_ld_direct_entry *entry,
	int drain)
{
	uint16_t nb_rx, nb_tx, i, drain_times = 0;
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	uint64_t lens[MAX_PKT_BURST];

	RTE_ASSERT(entry->poll_type == RX_QUEUE &&
		(entry->dest_type == SEC_EGRESS ||
		entry->dest_type == SEC_INGRESS));

drain_again:
	nb_rx = pre_ld_entry_port_recv(entry, mbufs, lens);
	if (unlikely(drain)) {
		if (pre_ld_drain_traffic_again(mbufs, nb_rx, &drain_times))
			goto drain_again;
		return;
	}

	pre_ld_entry_stat_update(&entry->rx_stat, lens, nb_rx, false);

	for (i = 0; i < nb_rx; i++)
		lens[i] = mbufs[i]->pkt_len - sizeof(struct rte_ether_hdr);

	nb_tx = pre_ld_direct_to_crypto(entry, mbufs, nb_rx);

	pre_ld_entry_stat_update(&entry->tx_stat, lens, nb_tx, true);

	if (unlikely(nb_tx < nb_rx))
		rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_rx - nb_tx);
}

static void
pre_ld_entry_sec_complete(struct pre_ld_direct_entry *entry,
	int drain)
{
	uint16_t portid, queueid, crypto_id, nb_rx, nb_tx, i;
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	uint64_t lens[MAX_PKT_BURST];
	uint16_t drain_times = 0;

	RTE_ASSERT((entry->poll_type == SEC_IN_COMPLETE ||
		entry->poll_type == SEC_EG_COMPLETE) &&
		entry->dest_type == HW_PORT);

	crypto_id = entry->poll.poll_sec.sec_id;
	queueid = *entry->poll.poll_sec.queue_id;
drain_again:
	nb_rx = pre_ld_ipsec_dequeue(mbufs, MAX_PKT_BURST,
			crypto_id, queueid);
	if (unlikely(drain)) {
		if (pre_ld_drain_traffic_again(mbufs, nb_rx, &drain_times))
			goto drain_again;
		return;
	}
	if (unlikely(!nb_rx))
		return;

	for (i = 0; i < nb_rx; i++) {
		lens[i] = mbufs[i]->pkt_len;
		pre_ld_adjust_ipv4(mbufs[i],
			entry->poll_type == SEC_IN_COMPLETE ?
			INGRESS_CRYPTO_DQ : EGRESS_CRYPTO_DQ);
	}
	pre_ld_entry_stat_update(&entry->rx_stat, lens, nb_rx, true);
	pre_ld_entry_traffic_dump(entry->poll_prefix, nb_rx, mbufs);

	for (i = 0; i < nb_rx; i++)
		lens[i] = mbufs[i]->pkt_len + RTE_TM_ETH_FRAMING_OVERHEAD_FCS;

	portid = entry->dest.dest_port;
	nb_tx = rte_eth_tx_burst(portid, 0, mbufs, nb_rx);

	pre_ld_entry_stat_update(&entry->tx_stat, lens, nb_tx, false);

	if (unlikely(nb_tx < nb_rx))
		rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_rx - nb_tx);
}

int
pre_ld_configure_sec_path(struct pre_ld_ipsec_sp_entry *sp,
	rte_be32_t spi)
{
	uint16_t idx = 0, offset, size, *crypt_qid = NULL;
	struct pre_ld_direct_entry *dir_to_sec = NULL;
	struct pre_ld_direct_entry *dir_from_sec = NULL;
	struct pre_ld_sp_node *sp_node = NULL;
	int to_sec_inserted = 0, from_sec_inserted = 0, ret, fail_ret;
	struct pre_ld_port_rx_flow *rx_flow = NULL;
	const uint8_t *cmp_data;
	uint16_t rx_port, tx_port;
	enum pre_ld_dir_poll_type poll_type;
	enum pre_ld_dir_dest_type dest_type;

	if (s_data_path_core < 0) {
		rte_exit(EXIT_FAILURE,
			"Data path code not specified!\n");

		return -EINVAL;
	}

	if (sp->dir == XFRM_POLICY_IN) {
		if (s_dir_recyc) {
			rx_port = s_dir_ports.recyc_pair[0].dl_id;
			tx_port = s_dir_ports.recyc_pair[0].dl_id;
		} else {
			rx_port = s_dir_ports.pair[0].dl_id;
			tx_port = s_dir_ports.pair[0].ul_id;
		}
		dest_type = SEC_INGRESS;
		poll_type = SEC_IN_COMPLETE;
	} else if (sp->dir == XFRM_POLICY_OUT) {
		if (s_dir_recyc)
			rx_port = s_dir_ports.recyc_pair[0].ul_id;
		else
			rx_port = s_dir_ports.pair[0].ul_id;
		tx_port = s_dir_ports.ext_id[0];
		dest_type = SEC_EGRESS;
		poll_type = SEC_EG_COMPLETE;
	} else {
		return -EINVAL;
	}

	ret = rte_ring_dequeue(s_port_flow_r[rx_port],
		(void **)&rx_flow);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"No RX flow available from ring(%s)\n",
			s_port_flow_r[rx_port]->name);
		goto failure_return;
	}
	memset(&rx_flow->flow, 0,
		sizeof(struct pre_ld_port_rx_flow) -
		offsetof(struct pre_ld_port_rx_flow, flow));

	if (sp->family == AF_INET &&
		(sp->dir == XFRM_POLICY_OUT ||
		s_ipsec_ib_flow_ip_addr_extract)) {
		rx_flow->type[idx] = RTE_FLOW_ITEM_TYPE_IPV4;
		rte_memcpy(&rx_flow->items[idx].ipv4_spec.hdr.src_addr,
			&sp->src, sizeof(rte_be32_t));
		rte_memcpy(&rx_flow->items[idx].ipv4_spec.hdr.dst_addr,
			&sp->dst, sizeof(rte_be32_t));
		rx_flow->masks[idx].ipv4_spec.hdr.src_addr = 0xffffffff;
		rx_flow->masks[idx].ipv4_spec.hdr.dst_addr = 0xffffffff;

		cmp_data = (void *)&rx_flow->items[idx].ipv4_spec.hdr.src_addr;
		offset = offsetof(struct rte_ipv4_hdr, src_addr);
		size = sizeof(rte_be32_t) * 2;
		idx++;
	} else if (sp->family == AF_INET6 &&
		(sp->dir == XFRM_POLICY_OUT ||
		s_ipsec_ib_flow_ip_addr_extract)) {
		rx_flow->type[idx] = RTE_FLOW_ITEM_TYPE_IPV6;
		rte_memcpy(&rx_flow->items[idx].ipv6_spec.hdr.src_addr,
			&sp->src, 16);
		rte_memcpy(&rx_flow->items[idx].ipv6_spec.hdr.dst_addr,
			&sp->dst, 16);
		memset(&rx_flow->masks[idx].ipv6_spec.hdr.src_addr,
			0xff, 16);
		memset(&rx_flow->masks[idx].ipv6_spec.hdr.dst_addr,
			0xff, 16);

		cmp_data = rx_flow->items[idx].ipv6_spec.hdr.src_addr;
		offset = offsetof(struct rte_ipv6_hdr, src_addr);
		size = 16 * 2;
		idx++;
	}

	if (sp->dir == XFRM_POLICY_IN) {
		rx_flow->type[idx] = RTE_FLOW_ITEM_TYPE_ESP;
		rx_flow->items[idx].esp_spec.hdr.spi = spi;
		rx_flow->masks[idx].esp_spec.hdr.spi = 0xffffffff;

		offset = sp->family == AF_INET ?
			sizeof(struct rte_ipv4_hdr) :
			sizeof(struct rte_ipv6_hdr);
		offset += offsetof(struct rte_esp_hdr, spi);
		size = sizeof(rte_be32_t);
		cmp_data = (void *)&rx_flow->items[idx].esp_spec.hdr.spi;
		idx++;
	}
	if (!idx) {
		RTE_LOG(ERR, pre_ld,
			"%s: Invalid IP family(%d) or direction(%d)\n",
			__func__, sp->family, sp->dir);
		ret = -EINVAL;
		goto failure_return;
	}

	rx_flow->type[idx] = RTE_FLOW_ITEM_TYPE_END;

	pre_ld_rx_flow_verify_set(rx_flow,
		PRE_LD_CMP_L3_OFFSET, offset, size, cmp_data);

	dir_to_sec = rte_zmalloc(NULL,
		sizeof(struct pre_ld_direct_entry), 0);
	if (!dir_to_sec) {
		ret = -ENOMEM;
		goto failure_return;
	}
	sp_node = rte_zmalloc(NULL, sizeof(struct pre_ld_sp_node), 0);
	if (!sp_node) {
		return -ENOMEM;
		goto failure_return;
	}
	sp_node->sp = sp;
	sp_node->next = NULL;

	ret = rte_ring_dequeue(s_crypt_queue_ring[sp->crypt_id],
		(void **)&crypt_qid);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"No crypt queue available from ring(%s)\n",
			s_crypt_queue_ring[sp->crypt_id]->name);

		goto failure_return;
	}

	dir_to_sec->poll_type = RX_QUEUE;
	dir_to_sec->poll.rx_flow = rx_flow;
	dir_to_sec->dest_type = dest_type;

	dir_to_sec->dest.dest_sec.queue_id = crypt_qid;
	dir_to_sec->dest.dest_sec.sec_id = sp->crypt_id;
	dir_to_sec->dest.dest_sec.sp_list = sp_node;
	dir_to_sec->entry_cb = pre_ld_entry_sec_start;
	dir_to_sec->poll_prefix = rte_zmalloc(NULL, 1024, 0);
	if (dir_to_sec->poll_prefix) {
		sprintf(dir_to_sec->poll_prefix,
			"Receive from port%d/queue%d",
			rx_flow->src->port_id, rx_flow->src->queue_id);
	}
	dir_to_sec->action_prefix = rte_zmalloc(NULL, 1024, 0);
	if (dir_to_sec->action_prefix) {
		sprintf(dir_to_sec->action_prefix,
			"-> %s with sec%d/queue%d",
			dest_type == SEC_EGRESS ? "encap" : "decap",
			sp->crypt_id, *crypt_qid);
	}

	dir_from_sec = rte_zmalloc(NULL,
		sizeof(struct pre_ld_direct_entry), 0);
	if (!dir_from_sec) {
		ret = -ENOMEM;
		goto failure_return;
	}

	dir_from_sec->poll.poll_sec.sp_list = NULL;
	dir_from_sec->poll_type = poll_type;
	dir_from_sec->poll.poll_sec.queue_id = crypt_qid;
	dir_from_sec->poll.poll_sec.sec_id = sp->crypt_id;

	dir_from_sec->dest_type = HW_PORT;
	dir_from_sec->dest.dest_port = tx_port;
	dir_from_sec->entry_cb = pre_ld_entry_sec_complete;
	dir_from_sec->poll_prefix = rte_zmalloc(NULL, 1024, 0);
	if (dir_from_sec->poll_prefix) {
		sprintf(dir_from_sec->poll_prefix,
			"%s from sec%d/queue%d",
			poll_type == SEC_IN_COMPLETE ? "Decap" : "Encap",
			sp->crypt_id, *crypt_qid);
	}
	dir_from_sec->action_prefix = rte_zmalloc(NULL, 1024, 0);
	if (dir_from_sec->action_prefix) {
		sprintf(dir_from_sec->action_prefix,
			"-> send to port%d", tx_port);
	}

	sp->entry_to_sec = dir_to_sec;
	sp->entry_from_sec = dir_from_sec;

	ret = pre_ld_update_dir_list_safe(dir_from_sec, INSERT_ENTRY_REQ);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s: Insert SEC dq entry failed(%d)\n", __func__, ret);

		goto failure_return;
	}
	from_sec_inserted = 1;

	ret = pre_ld_update_dir_list_safe(dir_to_sec, INSERT_ENTRY_REQ);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"%s: Insert SEC eq entry failed(%d)\n", __func__, ret);

		goto failure_return;
	}
	sp->flow = dir_to_sec->poll.rx_flow->flow;
	to_sec_inserted = 1;

	return 0;

failure_return:
	fail_ret = ret;
	if (to_sec_inserted) {
		ret = pre_ld_update_dir_list_safe(dir_to_sec,
			REMOVE_ENTRY_REQ);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s line %d: Recover SEC eq entry failed(%d)",
				__func__, __LINE__, ret);
		}
	}
	if (from_sec_inserted) {
		ret = pre_ld_update_dir_list_safe(dir_from_sec,
			REMOVE_ENTRY_REQ);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s line %d: Recover SEC dq entry failed(%d)",
				__func__, __LINE__, ret);
		}
	}

	if (dir_to_sec)
		rte_free(dir_to_sec);
	if (dir_from_sec)
		rte_free(dir_from_sec);
	if (sp_node)
		rte_free(sp_node);
	if (crypt_qid) {
		ret = rte_ring_enqueue(s_crypt_queue_ring[sp->crypt_id],
			crypt_qid);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: Recover Crypto%d's queue%d failed(%d)",
				__func__, sp->crypt_id, *crypt_qid, ret);
		}
	}
	if (rx_flow) {
		ret = rte_ring_enqueue(s_port_flow_r[rx_port],
			rx_flow);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: Recover port%d's rx flow failed(%d)",
				__func__, rx_port, ret);
		}
	}

	return fail_ret;
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
			entry->poll.rx_flow->flow == sp->flow) {
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

static void
pre_ld_configure_default_flow(struct pre_ld_port_rx_flow *def_flow)
{
	def_flow->type[0] = RTE_FLOW_ITEM_TYPE_ETH;
	memset(&def_flow->masks[0], 0, sizeof(union pre_ld_flow_item));
	def_flow->type[1] = RTE_FLOW_ITEM_TYPE_END;
}

static void
pre_ld_entry_port_fwd(struct pre_ld_direct_entry *entry, int drain)
{
	uint16_t nb_rx, nb_tx, drain_times = 0;
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	uint64_t lens[MAX_PKT_BURST];

	RTE_ASSERT(entry->poll_type == RX_QUEUE &&
		entry->dest_type == HW_PORT);

drain_again:
	nb_rx = pre_ld_entry_port_recv(entry, mbufs, lens);
	if (unlikely(drain)) {
		if (pre_ld_drain_traffic_again(mbufs, nb_rx, &drain_times))
			goto drain_again;
		return;
	}

	pre_ld_entry_stat_update(&entry->rx_stat, lens, nb_rx, false);

	nb_tx = rte_eth_tx_burst(entry->dest.dest_port, 0, mbufs, nb_rx);

	pre_ld_entry_stat_update(&entry->tx_stat, lens, nb_tx, false);

	if (unlikely(nb_tx < nb_rx))
		rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_rx - nb_tx);
}

static inline struct rte_flow *
pre_ld_add_port_dir_entry(struct pre_ld_port_rx_flow *rx_flow,
	uint16_t to_id)
{
	struct pre_ld_direct_entry *entry;

	entry = rte_zmalloc(NULL, sizeof(struct pre_ld_direct_entry), 0);
	if (!entry)
		rte_panic("Data path alloc failed\n");

	entry->poll_type = RX_QUEUE;
	entry->poll.rx_flow = rx_flow;
	entry->dest_type = HW_PORT;
	entry->dest.dest_port = to_id;
	entry->entry_cb = pre_ld_entry_port_fwd;
	entry->poll_prefix = rte_zmalloc(NULL, 1024, 0);
	if (entry->poll_prefix) {
		sprintf(entry->poll_prefix,
			"Receive from port%d/queue%d",
			rx_flow->src->port_id, rx_flow->src->queue_id);
	}
	entry->action_prefix = rte_zmalloc(NULL, 1024, 0);
	if (entry->action_prefix) {
		sprintf(entry->action_prefix,
			"-> send to port%d", to_id);
	}
	if (pre_ld_update_dir_list_safe(entry, INSERT_ENTRY_REQ)) {
		rte_panic("%s, line %d: Insert entry failed\n",
			__func__, __LINE__);
	}

	return entry->poll.rx_flow->flow;
}

static inline struct rte_flow *
pre_ld_sw_default_direct(struct pre_ld_port_rx_flow *def_flow,
	uint16_t to_id)
{
	pre_ld_configure_default_flow(def_flow);
	return pre_ld_add_port_dir_entry(def_flow, to_id);
}

static inline void
pre_ld_def_dir_add(const char *from_nm,
	const char *to_nm, const struct pre_ld_port_rx_flow *rx_flow,
	uint16_t to_id, struct rte_flow *flow)
{
	if (!s_pre_ld_def_dir.def_dir)
		s_pre_ld_def_dir.def_dir = s_def_dir;

	strcpy(s_pre_ld_def_dir.def_dir[s_def_dir_num].from_name,
		from_nm);
	strcpy(s_pre_ld_def_dir.def_dir[s_def_dir_num].to_name,
		to_nm);
	s_pre_ld_def_dir.rx_flows[s_def_dir_num] = rx_flow;
	s_pre_ld_def_dir.to_ids[s_def_dir_num] = to_id;
	s_pre_ld_def_dir.flows[s_def_dir_num] = flow;
	s_def_dir_num++;
}

static void
pre_ld_build_def_direct_traffic(const char *from_nm,
	const char *to_nm, uint16_t from_id, uint16_t to_id)
{
	struct rte_flow *flow;

	if (rte_pmd_dpaa2_dev_is_dpaa2(from_id)) {
		if (s_dump_traffic_flow) {
			flow = pre_ld_sw_default_direct(s_def_flow[from_id],
				to_id);
		} else {
			flow = rte_remote_default_direct(from_nm,
				to_nm, NULL, s_def_flow[from_id]->src->tc_id,
				s_def_flow[from_id]->src->flow_id);
		}
	} else {
		flow = pre_ld_add_port_dir_entry(s_def_flow[from_id],
			to_id);
	}
	pre_ld_def_dir_add(from_nm, to_nm, s_def_flow[from_id], to_id, flow);
}

static void
pre_ld_configure_direct_traffic(uint16_t ext_id,
	uint16_t ul_id, uint16_t dl_id, uint16_t tap_id,
	int is_recyc)
{
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

	pre_ld_build_def_direct_traffic(dl_nm, tap_nm, dl_id, tap_id);
	if (is_recyc) {
		pre_ld_build_def_direct_traffic(tap_nm, ul_nm, tap_id, ul_id);
		pre_ld_build_def_direct_traffic(ext_nm, dl_nm, ext_id, dl_id);
	} else {
		pre_ld_build_def_direct_traffic(tap_nm, dl_nm, tap_id, dl_id);
		pre_ld_build_def_direct_traffic(ext_nm, ul_nm, ext_id, ul_id);
	}
	pre_ld_build_def_direct_traffic(ul_nm, ext_nm, ul_id, ext_id);
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

static void
pre_ld_loop_drain_ports(struct pre_ld_lcore_direct_list *list)
{
	int ret;
	struct pre_ld_direct_entry *entry, *tentry;
	uint16_t id, qid, nb, drain_times, i, total;
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	uint16_t retry;
	char *env;

	if (!s_pause_traffic_flow_updating)
		return;

	env = getenv("PRE_LD_DRAIN_RETRY");
	if (env)
		retry = atoi(env);
	else
		retry = PRE_LD_DRAIN_RETRY_TIMES;

	for (i = 0; i < s_dir_ports.ext_num; i++) {
		/** Down link ext port causes connection lost.*/
		continue;
		ret = rte_eth_dev_set_link_down(s_dir_ports.ext_id[i]);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"DOWN ext port%d failed(%d)\n",
				s_dir_ports.ext_id[i], ret);
		}
	}

	RTE_TAILQ_FOREACH_SAFE(entry, list, next, tentry) {
		drain_times = 0;
		if (entry->dest_type == HW_PORT) {
			id = entry->dest.dest_port;
			total = 0;
clean_tx_again:
			nb = rte_pmd_dpaa2_clean_tx_conf(id, 0);
			if (nb) {
				drain_times = 0;
				total += nb;
				goto clean_tx_again;
			}
			drain_times++;
			if (drain_times > retry) {
				RTE_LOG(INFO, pre_ld,
					"Clean %d buffer(s) from port%d's TX conf\n",
					total, id);
				continue;
			}
		}
	}

	/** Down all poll ports*/
	RTE_TAILQ_FOREACH_SAFE(entry, list, next, tentry) {
		drain_times = 0;
		if (entry->poll_type == RX_QUEUE) {
			id = entry->poll.rx_flow->src->port_id;
			ret = rte_eth_dev_set_link_down(id);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"DOWN port%d failed(%d)\n", id, ret);
			}
		}
	}

	RTE_TAILQ_FOREACH_SAFE(entry, list, next, tentry) {
		drain_times = 0;
		if (entry->poll_type == RX_QUEUE) {
			id = entry->poll.rx_flow->src->port_id;
			qid = entry->poll.rx_flow->src->queue_id;
			total = 0;
port_rx_again:
			nb = rte_eth_rx_burst(id, qid, mbufs, MAX_PKT_BURST);
			if (nb) {
				rte_pktmbuf_free_bulk(mbufs, nb);
				drain_times = 0;
				total += nb;
				goto port_rx_again;
			}
			drain_times++;
			if (drain_times < retry)
				goto port_rx_again;
			RTE_LOG(INFO, pre_ld,
				"Clean %d frame(s) from port%d's RXQ%d\n",
				total, id, qid);
		} else if (entry->poll_type == SEC_IN_COMPLETE ||
			entry->poll_type == SEC_EG_COMPLETE) {
			id = entry->poll.poll_sec.sec_id;
			qid = *entry->poll.poll_sec.queue_id;
			total = 0;
sec_dq_again:
			nb = pre_ld_ipsec_dequeue(mbufs, MAX_PKT_BURST,
				id, qid);
			if (nb) {
				rte_pktmbuf_free_bulk(mbufs, nb);
				drain_times = 0;
				total += nb;
				goto sec_dq_again;
			}
			drain_times++;
			if (drain_times < retry)
				goto sec_dq_again;
			RTE_LOG(INFO, pre_ld,
				"Clean %d frame(s) from SEC%d's %s queue%d\n",
				total, id, entry->poll_type == SEC_IN_COMPLETE ?
				"Ingress" : "Egress", qid);
		}
	}
}

static void
pre_ld_loop_up_ports(struct pre_ld_lcore_direct_list *list)
{
	int ret;
	struct pre_ld_direct_entry *entry, *tentry;
	uint16_t id, i;

	if (!s_pause_traffic_flow_updating)
		return;

	RTE_TAILQ_FOREACH_SAFE(entry, list, next, tentry) {
		if (entry->poll_type == RX_QUEUE) {
			id = entry->poll.rx_flow->src->port_id;
			ret = rte_eth_dev_set_link_up(id);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"UP port%d failed(%d)\n", id, ret);
			}
		}
	}

	for (i = 0; i < s_dir_ports.ext_num; i++) {
		/** Down link ext port causes connection lost.*/
		continue;
		ret = rte_eth_dev_set_link_up(s_dir_ports.ext_id[i]);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"UP ext port%d failed(%d)\n",
				s_dir_ports.ext_id[i], ret);
		}
	}
}

static int
pre_ld_port_rx_flow_update(struct pre_ld_port_rx_flow *rx_flow,
	enum pre_ld_dir_msg_type msg_type)
{
	struct rte_flow_attr flow_attr;
	struct rte_flow_item flow_item[PRE_LD_FLOW_MAX_ITEM];
	struct rte_flow_action flow_action[2];
	struct rte_flow_action_queue rxq;
	union pre_ld_flow_item zero_mask;
	int i = 0, ret;

	memset(&zero_mask, 0, sizeof(union pre_ld_flow_item));

	if (msg_type == REMOVE_ENTRY_REQ) {
		return pre_ld_flow_destroy(rx_flow->src->port_id,
			rx_flow->flow);
	}

	memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
	flow_attr.group = rx_flow->src->tc_id;
	flow_attr.priority = rx_flow->src->flow_id;
	flow_attr.ingress = 1;
	flow_attr.egress = 0;

	while (rx_flow->type[i] != RTE_FLOW_ITEM_TYPE_END) {
		flow_item[i].type = rx_flow->type[i];
		if (!memcmp(&zero_mask, &rx_flow->masks[i],
			sizeof(union pre_ld_flow_item))) {
			flow_item[i].spec = NULL;
			flow_item[i].mask = NULL;
		} else {
			flow_item[i].spec = &rx_flow->items[i];
			flow_item[i].mask = &rx_flow->masks[i];
		}
		flow_item[i].last = NULL;
		i++;
	}
	flow_item[i].type = RTE_FLOW_ITEM_TYPE_END;

	flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	rxq.index = rx_flow->src->queue_id;
	flow_action[0].conf = &rxq;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;
	ret = rte_flow_validate(rx_flow->src->port_id, &flow_attr,
		flow_item, flow_action, NULL);
	if (ret) {
		RTE_LOG(ERR, pre_ld, "%s: flow validate failed(%d)",
			__func__, ret);
		return ret;
	}
	rx_flow->flow = rte_flow_create(rx_flow->src->port_id, &flow_attr,
		flow_item, flow_action, NULL);
	if (!rx_flow->flow) {
		RTE_LOG(ERR, pre_ld, "%s: flow create failed", __func__);

		return -EIO;
	}

	return 0;
}

static int
pre_ld_main_loop(void *dummy)
{
	uint32_t lcore_id;
	int ret, found;
	struct pre_ld_lcore_direct_list *list;
	struct pre_ld_direct_entry *entry, *tentry, *dir;
	uint16_t ul_id, dl_id;
	char nm[RTE_MEMZONE_NAMESIZE];
	struct pre_ld_dir_entry_update_msg *msg = NULL;
	enum pre_ld_dir_msg_type msg_req, msg_rsp;

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

	if (s_dir_recyc) {
		ul_id = s_dir_ports.recyc_pair[0].ul_id;
		dl_id = s_dir_ports.recyc_pair[0].dl_id;
	} else {
		ul_id = s_dir_ports.pair[0].ul_id;
		dl_id = s_dir_ports.pair[0].dl_id;
	}
	pre_ld_configure_direct_traffic(s_dir_ports.ext_id[0],
		ul_id, dl_id, s_dir_ports.kif[0].tap_id,
		s_dir_recyc);

	pthread_mutex_unlock(&s_dp_init_mutex);

	RTE_LOG(INFO, pre_ld,
		"entering main loop on lcore %u\n", lcore_id);

	ret = pre_ld_crypto_init(s_pre_ld_rx_pool);
	if (ret) {
		RTE_LOG(ERR, pre_ld, "Crypto init failed(%d)\n", ret);
		return ret;
	}

	sprintf(nm, "dir_core%d_flow_req", lcore_id);
	s_dir_msg_req_r[lcore_id] = rte_ring_create(nm, 128, 0, 0);
	sprintf(nm, "dir_core%d_flow_rsp", lcore_id);
	s_dir_msg_rsp_r[lcore_id] = rte_ring_create(nm, 128, 0, 0);

for_ever_loop:
	if (s_pre_ld_quit)
		return 0;

	RTE_TAILQ_FOREACH_SAFE(entry, list, next, tentry) {
		if (likely(entry->entry_cb))
			entry->entry_cb(entry, false);
	}

	ret = rte_ring_dequeue(s_dir_msg_req_r[lcore_id], (void **)&msg);
	if (likely(ret))
		goto for_ever_loop;

	ret = 0;
	found = 0;
	RTE_TAILQ_FOREACH_SAFE(entry, list, next, tentry) {
		if (entry == msg->dir) {
			found = 1;
			break;
		}
	}
	msg_req = msg->msg_type;
	if (!found && msg->msg_type == REMOVE_ENTRY_REQ) {
		msg->msg_type = UPDATE_ENTRY_FAILED_RSP;
		RTE_LOG(INFO, pre_ld,
			"Entry(%p) to be removed was NOT in list!\n",
			msg->dir);
		goto rsp_again;
	} else if (found && msg->msg_type == INSERT_ENTRY_REQ) {
		msg->msg_type = UPDATE_ENTRY_FAILED_RSP;
		RTE_LOG(INFO, pre_ld,
			"Entry(%p) to be inserted has been in list!\n",
			msg->dir);
		goto rsp_again;
	} else if (msg->msg_type != INSERT_ENTRY_REQ &&
		msg->msg_type != REMOVE_ENTRY_REQ) {
		RTE_LOG(INFO, pre_ld,
			"Invalid entry message type(%d)\n",
			msg->msg_type);
		msg->msg_type = UPDATE_ENTRY_FAILED_RSP;
		goto rsp_again;
	}

	RTE_LOG(INFO, pre_ld, "%s entry(%p) %s %s\n",
		msg->msg_type == INSERT_ENTRY_REQ ?
		"Insert" : "Remove", msg->dir, msg->dir->poll_prefix,
		msg->dir->action_prefix);

	pre_ld_loop_drain_ports(list);

	if (msg->msg_type == INSERT_ENTRY_REQ)
		TAILQ_INSERT_TAIL(list, msg->dir, next);
	else
		TAILQ_REMOVE(list, msg->dir, next);

	if (msg->dir->poll_type == RX_QUEUE) {
		ret = pre_ld_port_rx_flow_update(msg->dir->poll.rx_flow,
			msg->msg_type);
	}
	if (msg->msg_type == REMOVE_ENTRY_REQ)
		msg->dir->entry_cb(msg->dir, true);

	pre_ld_loop_up_ports(list);
	if (!ret)
		msg->msg_type = UPDATE_ENTRY_SUCCESS_RSP;
	else
		msg->msg_type = UPDATE_ENTRY_FAILED_RSP;

rsp_again:
	msg_rsp = msg->msg_type;
	dir = msg->dir;
	ret = rte_ring_enqueue(s_dir_msg_rsp_r[lcore_id], msg);
	if (ret)
		goto rsp_again;
	if (msg_req == INSERT_ENTRY_REQ || msg_req == REMOVE_ENTRY_REQ) {
		RTE_LOG(INFO, pre_ld, "%s entry(%p) %s.\n",
			msg_req == INSERT_ENTRY_REQ ? "Insert" : "Remove",
			dir, msg_rsp == UPDATE_ENTRY_SUCCESS_RSP ?
			"successfully" : "Failed");
	} else {
		RTE_LOG(ERR, pre_ld, "Invalid msg(%d) of entry(%p)\n",
			msg_req, dir);
	}

	goto for_ever_loop;

	return 0;
}

static void
pre_ld_ls_listni_clean(void)
{
	if (s_ls_listni_info)
		rte_free(s_ls_listni_info);
	s_ls_listni_info = NULL;
	s_safe_ls_listni_info = NULL;
}

static int
pre_ld_ls_listni_dump(void)
{
	char cmd[512], *env, rst[128], *info;
	struct stat st;
	size_t size;
	int ret;
	FILE *f = NULL;

	if (s_safe_ls_listni_info)
		return 0;

	env = getenv("LISTNI_RESULT");
	if (env)
		sprintf(rst, "/tmp/%s", env);
	else
		sprintf(rst, "/tmp/listni_rst");
	sprintf(cmd, "ls-listni > %s", rst);
	ret = system(cmd);
	if (ret)
		return ret;

	ret = stat(rst, &st);
	if (ret)
		return ret;

	info = rte_malloc(NULL, st.st_size * 2, 0);
	if (!info)
		return -ENOMEM;

	f = fopen(rst, "r");
	if (f) {
		size = fread(info, sizeof(char), st.st_size, f);
		if (size != (size_t)st.st_size) {
			RTE_LOG(WARNING, pre_ld,
				"Read %s length(%ld) != length(%ld) of state\n",
				rst, size, (size_t)st.st_size);
		}
		s_ls_listni_info = info;
		s_safe_ls_listni_info = info;
		fclose(f);

		return 0;
	}

	rte_free(s_ls_listni_info);
	s_ls_listni_info = NULL;

	return -EIO;
}

static int
pre_ld_ls_listni_peer_info(const char *dpni_nm,
	uint8_t *dprc_num, char *eth_nm)
{
	int i = 0;
	char search[128];
	char *found, *dprc_pos, *eth_pos;
	uint8_t num;

	if (!s_safe_ls_listni_info)
		return -ENOMEM;

	sprintf(search, "/%s", dpni_nm);
	found = strstr(s_safe_ls_listni_info, search);
	if (!found)
		return -EEXIST;

	/** Assume dprc number is less than 10.*/
	dprc_pos = found - strlen("dprc.1");
	if (dprc_pos < s_safe_ls_listni_info)
		return -EEXIST;

	if (strncmp(dprc_pos, "dprc.", strlen("dprc.")))
		return -EEXIST;

	num = *(dprc_pos + strlen("dprc.")) - '0';
	if (dprc_num)
		*dprc_num = num;

	if (num == 1) {
		/**ROOT DPRC*/
		eth_pos = found + strlen(search) +
			strlen(" (interface: ");
		if (eth_nm) {
			while (eth_pos[i] != ' ') {
				eth_nm[i] = eth_pos[i];
				i++;
			}
			eth_nm[i] = 0;
		}
	}

	return 0;
}

static void
pre_ld_set_port_type(enum pre_ld_port_type port_type[],
	uint16_t size)
{
	uint16_t portid1, portid2, port_num;
	char port_name[RTE_ETH_NAME_MAX_LEN];
	const char *peer_name;
	int ret;
	const char *eth_nm;
	uint8_t dprc_num, i;
	int mux_id, ep_id, found;
	struct pre_ld_mux_cfg *mux_cfg;
	struct pre_ld_dir_ul_dl_pair *pair;
	struct pre_ld_dir_ul_dl_pair *recyc_pair;
	struct pre_ld_dir_kif *kif;
	struct rte_remote_query_rsp rsp;

	for (port_num = 0; port_num < size; port_num++)
		port_type[port_num] = NULL_TYPE;

	port_num = 0;

	RTE_ETH_FOREACH_DEV(portid1) {
		if (!rte_pmd_dpaa2_dev_is_dpaa2(portid1)) {
			port_type[portid1] = EXTERNAL_TYPE;
			s_dir_ports.ext_id[s_dir_ports.ext_num] = portid1;
			s_dir_ports.ext_num++;
			continue;
		}
		peer_name = rte_pmd_dpaa2_ep_name(portid1);
		if (!peer_name ||
			!strncmp(peer_name, "dpmac.", strlen("dpmac."))) {
			port_type[portid1] = EXTERNAL_TYPE;
			s_dir_ports.ext_id[s_dir_ports.ext_num] = portid1;
			s_dir_ports.ext_num++;
		}
	}

	RTE_ETH_FOREACH_DEV(portid1) {
		if (!rte_pmd_dpaa2_dev_is_dpaa2(portid1))
			continue;
		if (port_type[portid1] != NULL_TYPE)
			continue;
		peer_name = rte_pmd_dpaa2_ep_name(portid1);
		RTE_ETH_FOREACH_DEV(portid2) {
			pair = &s_dir_ports.pair[s_dir_ports.pair_num];
			if (portid2 == portid1)
				continue;
			ret = rte_eth_dev_get_name_by_port(portid2, port_name);
			if (ret)
				continue;
			if (peer_name && !strcmp(peer_name, port_name)) {
				pair->ul_id = portid1;
				pair->dl_id = portid2;
				port_type[portid1] = UP_LINK_TYPE;
				port_type[portid2] = DOWN_LINK_TYPE;
				s_dir_ports.pair_num++;
				break;
			}
		}
	}

	recyc_pair = s_dir_ports.recyc_pair;
	RTE_ETH_FOREACH_DEV(portid1) {
		if (!rte_pmd_dpaa2_dev_is_dpaa2(portid1))
			continue;
		if (port_type[portid1] != NULL_TYPE)
			continue;
		ret = rte_eth_dev_get_name_by_port(portid1, port_name);
		if (ret)
			continue;
		peer_name = rte_pmd_dpaa2_ep_name(portid1);
		if (peer_name && !strcmp(peer_name, port_name)) {
			if (recyc_pair->ul_id < 0) {
				recyc_pair->ul_id = portid1;
				port_type[portid1] = RECYCLE_UP_LINK_TYPE;
			} else if (recyc_pair->dl_id < 0) {
				recyc_pair->dl_id = portid1;
				port_type[portid1] = RECYCLE_DOWN_LINK_TYPE;
			}
			if (recyc_pair->ul_id >= 0 && recyc_pair->dl_id >= 0) {
				s_dir_ports.recyc_pair_num++;
				recyc_pair++;
			}
		}
	}

	RTE_ETH_FOREACH_DEV(portid1) {
		kif = &s_dir_ports.kif[s_dir_ports.kif_num];
		if (!rte_pmd_dpaa2_dev_is_dpaa2(portid1))
			continue;
		if (port_type[portid1] != NULL_TYPE)
			continue;
		peer_name = rte_pmd_dpaa2_ep_name(portid1);
		if (!peer_name)
			continue;
		if (strncmp(peer_name, REMOTE_EP_NAME_PREFIX,
			strlen(REMOTE_EP_NAME_PREFIX)))
			continue;
		if (pre_ld_ls_listni_peer_info(peer_name, &dprc_num, NULL))
			continue;
		if (dprc_num != 1)
			continue;
		eth_nm = pre_ld_get_tap_kernel_if_nm(peer_name);
		if (eth_nm) {
			kif->tap_id = portid1;
			kif->kernel_nm = eth_nm;
			port_type[portid1] = KERNEL_TAP_TYPE;
			s_dir_ports.kif_num++;
		}
	}

	RTE_ETH_FOREACH_DEV(portid1) {
		if (!rte_pmd_dpaa2_dev_is_dpaa2(portid1))
			continue;
		if (port_type[portid1] != NULL_TYPE)
			continue;
		peer_name = rte_pmd_dpaa2_ep_name(portid1);
		if (!peer_name)
			continue;
		if (strncmp(peer_name, REMOTE_EP_NAME_PREFIX,
			strlen(REMOTE_EP_NAME_PREFIX)))
			continue;
		if (pre_ld_ls_listni_peer_info(peer_name, &dprc_num, NULL))
			continue;
		if (dprc_num == 1)
			continue;
		port_type[portid1] = PROC_DOWN_LINK_TYPE;
		ret = remote_direct_query(&rsp);
		if (ret)
			continue;

		/** We support single proc pair only now.*/
		if (!s_proc_cfg[0].uplink_nm[0])
			strcpy(s_proc_cfg[0].uplink_nm, rsp.uplink_nm);
		if (!s_proc_cfg[0].def_nm[0])
			strcpy(s_proc_cfg[0].def_nm, rsp.taplink_nm);

		if (!s_proc_cfg[0].kernel_nm) {
			s_proc_cfg[0].kernel_nm =
				pre_ld_get_tap_kernel_if_nm(rsp.taplink_end_nm);
		}

		strcpy(s_proc_cfg[0].downlink_nm[s_proc_cfg[0].if_num],
			rsp.downlink_nm);
		s_proc_cfg[0].port_id[s_proc_cfg[0].if_num] = portid1;
		s_proc_cfg[0].if_num++;
		s_proc_num = 1;
	}

	RTE_ETH_FOREACH_DEV(portid1) {
		if (!rte_pmd_dpaa2_dev_is_dpaa2(portid1))
			continue;
		if (port_type[portid1] != NULL_TYPE)
			continue;
		peer_name = rte_pmd_dpaa2_ep_name(portid1);
		if (!peer_name)
			continue;
		ret = rte_remote_mux_parse_ep_name(peer_name,
			NULL, &mux_id, NULL, &ep_id);
		if (ret)
			continue;
		port_type[portid1] = MUX_DOWN_LINK_TYPE;
		found = 0;
		for (i = 0; i < s_mux_num; i++) {
			if (s_mux_cfg[i].mux_id != mux_id)
				continue;
			s_mux_cfg[i].port_id[s_mux_cfg[i].if_num] = portid1;
			s_mux_cfg[i].ep_nm[s_mux_cfg[i].if_num] = peer_name;
			s_mux_cfg[i].ep_id[s_mux_cfg[i].if_num] = ep_id;
			s_mux_cfg[i].if_num++;
			found = 1;
			break;
		}
		if (found)
			continue;

		mux_cfg = &s_mux_cfg[s_mux_num];

		ret = rte_pmd_dpaa2_mux_default_id(mux_id,
				&mux_cfg->def_id);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"Get default ID of dpdmux%d failed(%d)\n",
				mux_id, ret);
			continue;
		}
		ret = rte_pmd_dpaa2_mux_ep_name(mux_id,
				mux_cfg->def_id, &mux_cfg->def_nm);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"Get default name of dpdmux%d failed(%d)\n",
				mux_id, ret);
			continue;
		}
		mux_cfg->kernel_nm =
			pre_ld_get_tap_kernel_if_nm(mux_cfg->def_nm);
		mux_cfg->port_id[0] = portid1;
		mux_cfg->ep_nm[0] = peer_name;
		mux_cfg->ep_id[0] = ep_id;
		mux_cfg->if_num++;
		s_mux_num++;
	}
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
	char rx_stat_info[512], tx_stat_info[512];
	const char *space = "        ";
	struct fd_desc *usr, *tusr;

statistics_loop:
	if (s_data_path_core < 0)
		goto usr_fd_statistics;

	list = &s_pre_ld_lists[s_data_path_core];
	i = 0;
	RTE_TAILQ_FOREACH_SAFE(entry, list, next, tentry) {
		pre_ld_st_entry_info_and_update(tx_stat_info,
			PRE_LD_STAT_TX, &entry->tx_stat, &entry->tx_old_stat);

		pre_ld_st_entry_info_and_update(rx_stat_info,
			PRE_LD_STAT_RX, &entry->rx_stat, &entry->rx_old_stat);

		RTE_LOG(INFO, pre_ld,
			"DIRECT ENTRY[%d] on core%d:\n%s%s %s\n%s%s\n%s%s\n\n",
			i, s_data_path_core,
			space, entry->poll_prefix, entry->action_prefix,
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

static struct pre_ld_port_rx_flow *
pre_ld_port_default_flow(uint16_t portid, uint16_t num)
{
	uint16_t i, def_flow = 0;
	uint8_t def_tc = 0;
	int idx = -1;
	const struct pre_ld_port_rx_source *src;

	/** Flow with max TC ID and max flow ID is lowest priority.*/
	for (i = 0; i < num; i++) {
		if (!s_pre_ld_rx_flows[portid][i].src)
			continue;
		src = s_pre_ld_rx_flows[portid][i].src;
		if (src->tc_id > def_tc)
			def_tc = src->tc_id;
	}

	for (i = 0; i < num; i++) {
		if (!s_pre_ld_rx_flows[portid][i].src)
			continue;
		src = s_pre_ld_rx_flows[portid][i].src;
		if (src->tc_id != def_tc)
			continue;
		if (idx < 0) {
			def_flow = src->flow_id;
			idx = i;
		}
		if (src->flow_id > def_flow) {
			def_flow = src->flow_id;
			idx = i;
		}
	}
	src = s_pre_ld_rx_flows[portid][idx].src;
	RTE_LOG(INFO, pre_ld,
		"Port%d's default flow: TC%d.flow%d: rxq%d\n",
		portid, src->tc_id, src->flow_id, src->queue_id);

	return &s_pre_ld_rx_flows[portid][idx];
}

static int
pre_ld_port_rx_flow_init(uint16_t portid,
	const struct rte_eth_dev_info *dev_info, uint16_t num)
{
	uint16_t i, flow_id, fs_entries, total_num = 0, dist_size;
	uint8_t tc_index;
	int ret;
	char ring_nm[RTE_MEMZONE_NAMESIZE];
	struct pre_ld_port_rx_source *src;
	struct rte_eth_rxq_info qinfo;

	if (portid >= RTE_MAX_ETHPORTS)
		return -EINVAL;

	if (!s_pre_ld_rx_flows[portid]) {
		s_pre_ld_rx_flows[portid] = rte_zmalloc(NULL,
			sizeof(struct pre_ld_port_rx_flow) * num, 0);
		if (!s_pre_ld_rx_flows[portid]) {
			ret = -ENOMEM;
			goto fail_return;
		}
	}
	if (!s_pre_ld_rx_src[portid]) {
		s_pre_ld_rx_src[portid] = rte_zmalloc(NULL,
			sizeof(struct pre_ld_port_rx_source) * num, 0);
		if (!s_pre_ld_rx_src[portid]) {
			ret = -ENOMEM;
			goto fail_return;
		}
	}
	fs_entries = 0;
	dist_size = 0;
	rte_pmd_dpaa2_dev_parse_tc_info(dev_info, NULL, NULL,
		&fs_entries, &dist_size);
	dist_size = RTE_MIN(fs_entries, dist_size);
	if (!dist_size) {
		RTE_LOG(ERR, pre_ld, "No distribution size of port%d\n",
			portid);
		return -EINVAL;
	}

	for (i = 0; i < num; i++) {
		ret = rte_eth_rx_queue_info_get(portid, i, &qinfo);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"Get info of port%d-rxq%d failed(%d)\n",
				portid, i, ret);
			return ret;
		}
		rte_pmd_dpaa2_rxq_parse_tc_info(&qinfo, &tc_index, &flow_id);
		if (flow_id >= dist_size)
			continue;
		src = &s_pre_ld_rx_src[portid][i];
		s_pre_ld_rx_flows[portid][total_num].src = src;
		src->port_id = portid;
		src->tc_id = tc_index;
		src->flow_id = flow_id;
		src->queue_id = i;
		total_num++;
	}

	s_def_flow[portid] = pre_ld_port_default_flow(portid, total_num);
	s_def_flow[portid]->cmp_offset_type = PRE_LD_NO_CMP;
	sprintf(ring_nm, "port%d_flow_r", portid);
	s_port_flow_r[portid] = rte_ring_create(ring_nm, num * 2, 0,
		RING_F_EXACT_SZ);
	if (!s_port_flow_r[portid])
		return -ENOMEM;

	for (i = 0; i < total_num; i++) {
		if (!s_pre_ld_rx_flows[portid][i].src)
			continue;
		if (&s_pre_ld_rx_flows[portid][i] == s_def_flow[portid])
			continue;
		ret = rte_ring_enqueue(s_port_flow_r[portid],
			&s_pre_ld_rx_flows[portid][i]);
		if (ret)
			return ret;
	}

	return 0;
fail_return:
	if (s_port_flow_r[portid]) {
		rte_ring_free(s_port_flow_r[portid]);
		s_port_flow_r[portid] = NULL;
	}
	if (s_pre_ld_rx_flows[portid]) {
		rte_free(s_pre_ld_rx_flows[portid]);
		s_pre_ld_rx_flows[portid] = NULL;
	}
	if (s_pre_ld_rx_src[portid]) {
		rte_free(s_pre_ld_rx_src[portid]);
		s_pre_ld_rx_src[portid] = NULL;
	}
	s_def_flow[portid] = NULL;

	return ret;
}

static void pre_ld_dump_port_toplogy(void)
{
	int off, i, j, ret;
	uint16_t portid;
	char nm[RTE_ETH_NAME_MAX_LEN];
	const char *space = "        ";
	char *info = rte_malloc(NULL, 4096, 0);

	if (!info)
		return;

	if (!s_dir_ports.ext_num && !s_dir_ports.pair_num &&
		!s_dir_ports.kif_num)
		goto skip_dir_dump;

	off = sprintf(info,
		"Direct: %d ext port(s)/%d pair(s)/%d tap(s)\n",
		s_dir_ports.ext_num, s_dir_ports.pair_num,
		s_dir_ports.kif_num);
	if (s_dir_ports.ext_num)
		off += sprintf(&info[off], "%s", space);
	for (i = 0; i < s_dir_ports.ext_num; i++) {
		portid = s_dir_ports.ext_id[i];
		ret = rte_eth_dev_get_name_by_port(portid, nm);
		if (ret)
			goto skip_print_ext;
		off += sprintf(&info[off], "ext%d(port%d/%s) ",
			i, portid, nm);
skip_print_ext:
		if ((i + 1) == s_dir_ports.ext_num)
			off += sprintf(&info[off], "\r\n");
	}

	if (s_dir_ports.pair_num)
		off += sprintf(&info[off], "%s", space);
	for (i = 0; i < s_dir_ports.pair_num; i++) {
		portid = s_dir_ports.pair[i].ul_id;
		ret = rte_eth_dev_get_name_by_port(portid, nm);
		if (ret)
			goto skip_print_pair;
		off += sprintf(&info[off], "pair%d(ul%d/%s",
			i, portid, nm);
		portid = s_dir_ports.pair[i].dl_id;
		ret = rte_eth_dev_get_name_by_port(portid, nm);
		if (ret)
			goto skip_print_pair;
		off += sprintf(&info[off], "-dl%d/%s) ", portid, nm);
skip_print_pair:
		if ((i + 1) == s_dir_ports.pair_num)
			off += sprintf(&info[off], "\r\n");
	}
	if (s_dir_ports.kif_num)
		off += sprintf(&info[off], "%s", space);
	for (i = 0; i < s_dir_ports.kif_num; i++) {
		portid = s_dir_ports.kif[i].tap_id;
		ret = rte_eth_dev_get_name_by_port(portid, nm);
		if (ret)
			goto skip_print_kif;
		off += sprintf(&info[off], "tap%d(port%d/%s/%s) ",
			i, portid, nm, s_dir_ports.kif[i].kernel_nm);
skip_print_kif:
		if ((i + 1) == s_dir_ports.kif_num)
			off += sprintf(&info[off], "\r\n");
	}
	RTE_LOG(INFO, pre_ld, "%s\n", info);

skip_dir_dump:
	if (!s_mux_num)
		goto skip_mux_dump;

	off = sprintf(info, "%d DPDMUX(s)\n%s", s_mux_num, space);
	for (i = 0; i < s_mux_num; i++) {
		off += sprintf(&info[off],
			"DPDMUX%d: default(%s<->%s) ",
			s_mux_cfg[i].mux_id, s_mux_cfg[i].def_nm,
			s_mux_cfg[i].kernel_nm);
		for (j = 0; j < s_mux_cfg[i].if_num; j++) {
			portid = s_mux_cfg[i].port_id[j];
			ret = rte_eth_dev_get_name_by_port(portid, nm);
			if (ret)
				continue;
			off += sprintf(&info[off], "IF%d(%s<->%s) ",
				j, s_mux_cfg[i].ep_nm[j], nm);
		}
		if ((i + 1) == s_mux_num)
			off += sprintf(&info[off], "\r\n");
	}
	RTE_LOG(INFO, pre_ld, "%s\n", info);

skip_mux_dump:
	if (!s_proc_num) {
		rte_free(info);
		return;
	}

	off = sprintf(info, "%d PROC(s)\n%s", s_proc_num, space);
	for (i = 0; i < s_proc_num; i++) {
		off += sprintf(&info[off],
			"PROC%d: default(%s<->%s) uplink(%s) ",
			i, s_proc_cfg[i].def_nm, s_proc_cfg[i].kernel_nm,
			s_proc_cfg[i].uplink_nm);
		for (j = 0; j < s_proc_cfg[i].if_num; j++) {
			portid = s_proc_cfg[i].port_id[j];
			ret = rte_eth_dev_get_name_by_port(portid, nm);
			if (ret)
				continue;
			off += sprintf(&info[off], "IF%d(%s<->%s) ",
				j, s_proc_cfg[i].downlink_nm[j], nm);
		}
		if ((i + 1) == s_proc_num)
			off += sprintf(&info[off], "\r\n");
	}
	RTE_LOG(INFO, pre_ld, "%s\n", info);
	rte_free(info);
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
	enum pre_ld_port_type port_type[RTE_MAX_ETHPORTS];
	size_t eal_argc = 0;
	char *eal_argv[MAX_ARGV_NUM];
	char func_nm[64], s_cpu[32], s_cpu_mask[32];
	char s_file_prefix[32], s_file_prefix_val[32];
	uint32_t cpu_mask;
	pthread_t pid;
	struct rte_eth_fc_conf fc_conf;

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

	rte_spinlock_init(&s_fd_list_lock);

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
		MEMPOOL_ELEM_SIZE, s_mempool_cache_size,
		PRE_LD_MP_PRIV_SIZE,
		PRE_LD_MBUF_MAX_SIZE, rte_socket_id());
	if (!s_pre_ld_rx_pool)
		rte_exit(EXIT_FAILURE, "Cannot init rx pool\n");

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

	ret = pre_ld_ls_listni_dump();
	if (ret) {
		RTE_LOG(ERR, pre_ld, "ls-listni dump failed(%d)\n", ret);
	} else {
		RTE_LOG(INFO, pre_ld, "ls-listni dump created:\n%s\n",
			s_safe_ls_listni_info);
	}
	pre_ld_set_port_type(port_type, RTE_MAX_ETHPORTS);

	pre_ld_ls_listni_clean();
	RTE_ETH_FOREACH_DEV(portid) {
		nb_ports_available++;
		rxq_num[portid] = 0;

		/* init port */
		RTE_LOG(INFO, pre_ld, "Configuring port%u, type:%d(%s)... ",
			portid, port_type[portid],
			port_type[portid] == EXTERNAL_TYPE ?
			"external" :
			port_type[portid] == UP_LINK_TYPE ?
			"up" :
			port_type[portid] == DOWN_LINK_TYPE ?
			"down" :
			port_type[portid] == PROC_DOWN_LINK_TYPE ?
			"proc down" :
			port_type[portid] == MUX_DOWN_LINK_TYPE ?
			"mux down" :
			port_type[portid] == KERNEL_TAP_TYPE ?
			"kernel tap" :
			port_type[portid] == RECYCLE_UP_LINK_TYPE ?
			"recycle up" :
			port_type[portid] == RECYCLE_DOWN_LINK_TYPE ?
			"recycle down" : "unknown");

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
			rxq_num[portid] = 1;
			txq_num[portid] = 1;
		} else if (port_type[portid] == UP_LINK_TYPE ||
			port_type[portid] == RECYCLE_UP_LINK_TYPE) {
			rxq_num[portid] = dev_info[portid].max_rx_queues;
			txq_num[portid] = dev_info[portid].max_tx_queues;
		} else if (port_type[portid] == DOWN_LINK_TYPE ||
			port_type[portid] == PROC_DOWN_LINK_TYPE ||
			port_type[portid] == MUX_DOWN_LINK_TYPE ||
			port_type[portid] == RECYCLE_DOWN_LINK_TYPE) {
			rxq_num[portid] = dev_info[portid].max_rx_queues;
			txq_num[portid] = dev_info[portid].max_tx_queues;
		} else if (port_type[portid] == KERNEL_TAP_TYPE) {
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

		if (!rte_pmd_dpaa2_dev_is_dpaa2(portid))
			continue;

		ret = pre_ld_port_rx_flow_init(portid, &dev_info[portid],
			rxq_num[portid]);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				 "Port%d's RX flow initalization failed(%d)\n",
				 portid, ret);
		}
	}

	pre_ld_dump_port_toplogy();

	if (s_dir_ports.ext_num > 0 &&
		(s_dir_ports.pair_num > 0 ||
		s_dir_ports.recyc_pair_num > 0) &&
		s_dir_ports.kif_num > 0) {
		/** We support single thread/single toplogy only.*/
		if (s_dir_ports.pair_num > 0) {
			s_rx_port = s_dir_ports.pair[0].dl_id;
			s_tx_port = s_dir_ports.pair[0].dl_id;
		} else {
			s_rx_port = s_dir_ports.recyc_pair[0].dl_id;
			s_tx_port = s_dir_ports.recyc_pair[0].ul_id;
			s_dir_recyc = 1;
		}
		s_slow_if = s_dir_ports.kif[0].kernel_nm;
		ret = rte_eal_mp_remote_launch(pre_ld_main_loop,
			NULL, SKIP_MAIN);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"remote launch thread failed!(%d)\n", ret);
		}
		while (s_data_path_core < 0) {
			/** Wait for data path thread running.*/
			usleep(1);
		}
	} else {
		for (i = 0; i < s_mux_num; i++) {
			if (!s_mux_cfg[i].if_num || !s_mux_cfg[i].kernel_nm)
				continue;
			s_rx_port = s_mux_cfg[i].port_id[0];
			s_tx_port = s_mux_cfg[i].port_id[0];
			s_slow_if = s_mux_cfg[i].kernel_nm;
			s_mux_index = i;
			break;
		}
		if (s_mux_index < 0) {
			for (i = 0; i < s_proc_num; i++) {
				if (!s_proc_cfg[i].if_num ||
					!s_proc_cfg[i].kernel_nm)
					continue;
				s_rx_port = s_proc_cfg[i].port_id[0];
				s_tx_port = s_proc_cfg[i].port_id[0];
				s_slow_if = s_proc_cfg[i].kernel_nm;
				s_proc_index = i;
				break;
			}
		}
		if (s_mux_index < 0 && s_proc_index < 0)
			rte_exit(EXIT_FAILURE, "Port toplogy not supported!\n");
		s_fd_mbuf_malloc_direct = 1;
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
	}

	return ret;
}

static int
eal_create_local_flow(int sockfd)
{
	struct rte_flow_action actions[1];
	struct rte_flow_action_queue ingress_queue;
	struct rte_flow_action flow_action[2];
	struct rte_flow_item pattern[PRE_LD_FLOW_MAX_ITEM];
	struct rte_flow_attr attr;
	int i = 0;
	struct pre_ld_port_rx_flow *rx_flow;
	struct pre_ld_direct_entry *entry;

	if (s_fd_desc[sockfd].access_type == FD_THREAD_ACCESS) {
		entry = s_fd_desc[sockfd].dp_desc.entry_desc.rx_entry;

		return pre_ld_update_dir_list_safe(entry, INSERT_ENTRY_REQ);
	}

	rx_flow = s_fd_desc[sockfd].dp_desc.hw_desc.rx_flow;

	memset(actions, 0, sizeof(actions));

	memset(&ingress_queue, 0,
		sizeof(struct rte_flow_action_queue));
	ingress_queue.index = rx_flow->src->queue_id;
	flow_action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	flow_action[0].conf = &ingress_queue;
	flow_action[1].type = RTE_FLOW_ACTION_TYPE_END;

	while (rx_flow->type[i] != RTE_FLOW_ITEM_TYPE_END) {
		pattern[i].type = rx_flow->type[i];
		pattern[i].spec = &rx_flow->items[i];
		pattern[i].mask = &rx_flow->masks[i];
		pattern[i].last = NULL;
		i++;
	}
	pattern[i].type = RTE_FLOW_ITEM_TYPE_END;

	attr.group = rx_flow->src->tc_id;
	attr.priority = rx_flow->src->flow_id;
	attr.ingress = 1;
	attr.egress = 0;

	rx_flow->flow = rte_flow_create(rx_flow->src->port_id, &attr,
		pattern, flow_action, NULL);
	if (!rx_flow->flow) {
		RTE_LOG(ERR, pre_ld,
			"%s: flow create failed\n", __func__);
		return -EIO;
	}

	return 0;
}

static int
eal_create_flow(int sockfd)
{
	char config_str[256];
	int ret, udp_src = 0, udp_dst = 0, offset = 0;
	struct pre_ld_direct_entry *rx_entry;
	const char *prot_name;
	const struct rte_flow_item_udp *udp = NULL;
	const struct rte_flow_item_udp *mask = NULL;
	struct pre_ld_port_rx_flow *rx_flow;
	uint8_t rule[32], rule_size = 0, l3_offset = 0;
	struct pre_ld_proc_cfg *proc_cfg;
	struct pre_ld_mux_cfg *mux_cfg;
	struct rte_flow_item pattern[2];

	if (s_fd_desc[sockfd].access_type == FD_HARDWARE_ACCESS) {
		rx_flow = s_fd_desc[sockfd].dp_desc.hw_desc.rx_flow;
	} else {
		rx_entry = s_fd_desc[sockfd].dp_desc.entry_desc.rx_entry;
		rx_flow = rx_entry->poll.rx_flow;
	}

	if (rx_flow->type[0] == RTE_FLOW_ITEM_TYPE_UDP) {
		prot_name = "udp";
		udp = &rx_flow->items[0].udp_spec;
		mask = &rx_flow->masks[0].udp_spec;
		if (mask->hdr.src_port)
			udp_src = 1;
		if (mask->hdr.dst_port)
			udp_dst = 1;
	} else if (rx_flow->type[0] == RTE_FLOW_ITEM_TYPE_GTP) {
		prot_name = "gtp";
	} else if (rx_flow->type[0] == RTE_FLOW_ITEM_TYPE_ETH) {
		prot_name = "eth";
	} else if (rx_flow->type[0] == RTE_FLOW_ITEM_TYPE_ECPRI) {
		prot_name = "ecpri";
	} else {
		prot_name = "unsupported protocol";
		RTE_LOG(ERR, pre_ld,
			"Unsupported protocol type(%d)\n",
			rx_flow->type[0]);
	}

	if (udp_src && !udp_dst) {
		rte_memcpy(rule, &udp->hdr.src_port, sizeof(rte_be16_t));
		rule_size = sizeof(rte_be16_t);
		l3_offset = 0;
	} else if (!udp_src && udp_dst) {
		rte_memcpy(rule, &udp->hdr.dst_port, sizeof(rte_be16_t));
		rule_size = sizeof(rte_be16_t);
		l3_offset = offsetof(struct rte_udp_hdr, dst_port);
	} else if (udp_src && udp_dst) {
		rte_memcpy(rule, &udp->hdr.src_port, sizeof(rte_be16_t) * 2);
		rule_size = sizeof(rte_be16_t) * 2;
		l3_offset = offsetof(struct rte_udp_hdr, src_port);
	}

	if (s_mux_index < 0)
		goto skip_mux_flow;

	pattern[0].type = rx_flow->type[0];
	pattern[0].spec = &rx_flow->items[0];
	pattern[0].mask = &rx_flow->masks[0];
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
	mux_cfg = &s_mux_cfg[s_mux_index];

	/** Single EP only.*/
	ret = eal_create_dpaa2_mux_flow(mux_cfg->mux_id,
			mux_cfg->ep_id[0], pattern);
	if (ret < 0) {
		RTE_LOG(ERR, pre_ld,
			"MUX%d(id=%d).EP%d's flow create failed(%d)\n",
			s_mux_index, mux_cfg->mux_id, 0, ret);
	}
	mux_cfg->entry_id[0] = ret;

skip_mux_flow:

	if (s_proc_index < 0)
		goto skip_proc_flow;

	proc_cfg = &s_proc_cfg[s_proc_index];

	if (proc_cfg->dir_configured[0])
		goto skip_proc_flow;

	if (udp_src) {
		offset += sprintf(&config_str[offset],
			"(%s, %s, %s, src, 0x%04x)",
			proc_cfg->uplink_nm,
			proc_cfg->downlink_nm[0], prot_name,
			rte_bswap16(udp->hdr.src_port));
	}

	if (udp_dst) {
		if (udp_src)
			offset += sprintf(&config_str[offset], ", ");
		offset += sprintf(&config_str[offset],
			"(%s, %s, %s, dst, 0x%04x)",
			proc_cfg->uplink_nm,
			proc_cfg->downlink_nm[0], prot_name,
			rte_bswap16(udp->hdr.dst_port));
	}

	if (!udp_src && !udp_dst) {
		sprintf(config_str,
			"(%s, %s, %s)", proc_cfg->uplink_nm,
			proc_cfg->downlink_nm[0], prot_name);
	}
	proc_cfg->dir_configured[0] = true;
	ret = rte_remote_direct_parse_config(config_str, 1);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Remote direct parse: %s failed(%d)\n",
			config_str, ret);
		goto skip_proc_flow;
	}
	ret = rte_remote_direct_traffic(RTE_REMOTE_DIR_REQ, NULL);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Remote direct request failed(%d)\n", ret);
	}

skip_proc_flow:

	pre_ld_rx_flow_verify_set(rx_flow,
		PRE_LD_CMP_L4_OFFSET, l3_offset, rule_size, rule);
	ret = eal_create_local_flow(sockfd);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Port%d/tc%d/flow%d->rxq%d flow create failed(%d)\n",
			rx_flow->src->port_id, rx_flow->src->tc_id,
			rx_flow->src->flow_id, rx_flow->src->queue_id, ret);
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
	rte_spinlock_lock(&s_fd_list_lock);
	TAILQ_INSERT_TAIL(&s_fd_desc_list, &s_fd_desc[sockfd], next);
	rte_spinlock_unlock(&s_fd_list_lock);
}

static void
pre_ld_entry_usr_tx_process(struct pre_ld_direct_entry *entry,
	int drain)
{
	uint16_t nb_rx, nb_tx, i, drain_times = 0;
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	uint64_t lens[MAX_PKT_BURST];

	RTE_ASSERT((entry->poll_type == TX_RING ||
		entry->poll_type == PRE_LD_TX_RING) &&
		entry->dest_type == HW_PORT);

drain_again:
	if (entry->poll_type == TX_RING) {
		nb_rx = rte_ring_dequeue_burst(entry->poll.tx_ring,
			(void **)mbufs, MAX_PKT_BURST, NULL);
	} else {
		nb_rx = pre_ld_ring_dq(entry->poll.pre_ld_tx_ring,
			(void **)mbufs, MAX_PKT_BURST);
	}
	if (unlikely(drain)) {
		if (pre_ld_drain_traffic_again(mbufs, nb_rx, &drain_times))
			goto drain_again;
		return;
	}
	if (unlikely(!nb_rx))
		return;

	for (i = 0; i < nb_rx; i++)
		lens[i] = mbufs[i]->pkt_len + RTE_TM_ETH_FRAMING_OVERHEAD_FCS;

	pre_ld_entry_stat_update(&entry->rx_stat, lens, nb_rx, false);

	nb_tx = rte_eth_tx_burst(entry->dest.dest_port, 0, mbufs, nb_rx);

	pre_ld_entry_stat_update(&entry->tx_stat, lens, nb_tx, false);

	if (unlikely(nb_tx < nb_rx))
		rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_rx - nb_tx);
}

static void
pre_ld_entry_usr_rx_process(struct pre_ld_direct_entry *entry,
	int drain)
{
	uint16_t nb_rx, nb_tx, drain_times = 0;
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	uint64_t lens[MAX_PKT_BURST];

	RTE_ASSERT(entry->poll_type == RX_QUEUE &&
		(entry->dest_type == RX_RING ||
		entry->dest_type == PRE_LD_RX_RING));

drain_again:
	nb_rx = pre_ld_entry_port_recv(entry, mbufs, lens);
	if (unlikely(drain)) {
		if (pre_ld_drain_traffic_again(mbufs, nb_rx, &drain_times))
			goto drain_again;
		return;
	}
	if (!nb_rx)
		return;

	pre_ld_entry_stat_update(&entry->rx_stat, lens, nb_rx, false);

	if (entry->dest_type == RX_RING) {
		nb_tx = rte_ring_enqueue_burst(entry->dest.rx_ring,
					(void * const *)mbufs, nb_rx, NULL);
	} else {
		nb_tx = pre_ld_ring_eq(entry->dest.pre_ld_rx_ring,
			(void **)mbufs, nb_rx);
	}

	pre_ld_entry_stat_update(&entry->tx_stat, lens, nb_tx, false);

	if (unlikely(nb_tx < nb_rx))
		rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_rx - nb_tx);
}

static void
pre_ld_entry_free_mbufs(struct pre_ld_direct_entry *entry, int drain)
{
	uint16_t nb_rx, drain_times = 0;
	struct rte_mbuf *mbufs[MAX_PKT_BURST];

	RTE_ASSERT((entry->poll_type == MBUF_FREE_RING ||
		entry->poll_type == PRE_LD_MBUF_FREE_RING) &&
		entry->dest_type == FREE_MBUF);

drain_again:
	if (entry->poll_type == MBUF_FREE_RING) {
		nb_rx = rte_ring_dequeue_burst(entry->poll.free_ring,
				(void **)mbufs, MAX_PKT_BURST, NULL);
	} else {
		nb_rx = pre_ld_ring_dq(entry->poll.pre_ld_free_ring,
				(void **)mbufs, MAX_PKT_BURST);
	}
	if (unlikely(drain)) {
		if (pre_ld_drain_traffic_again(mbufs, nb_rx, &drain_times))
			goto drain_again;
		return;
	}

	pre_ld_entry_stat_update(&entry->rx_stat, NULL, nb_rx, false);

	rte_pktmbuf_free_bulk(mbufs, nb_rx);

	pre_ld_entry_stat_update(&entry->tx_stat, NULL, nb_rx, false);
}

static void
pre_ld_entry_malloc_mbufs(struct pre_ld_direct_entry *entry, int drain)
{
	uint16_t nb_tx, count;
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	int ret;

	RTE_ASSERT(entry->poll_type == MBUF_MALLOC_POOL &&
		(entry->dest_type == PRE_LD_MALLOC_RING ||
		entry->dest_type == MALLOC_RING));

	if (entry->dest_type == PRE_LD_MALLOC_RING)
		count = pre_ld_ring_count(entry->dest.pre_ld_malloc_ring);
	else
		count = rte_ring_count(entry->dest.malloc_ring);

	if (unlikely(drain)) {
		if (entry->dest_type == PRE_LD_MALLOC_RING) {
			while (pre_ld_ring_dq(entry->dest.pre_ld_malloc_ring,
				(void **)mbufs, 1))
				rte_pktmbuf_free(mbufs[0]);
		} else {
			while (!rte_ring_dequeue(entry->dest.malloc_ring,
				(void **)mbufs))
				rte_pktmbuf_free(mbufs[0]);
		}
		return;
	}

	if (count >= s_fd_mbuf_avail_threshold)
		return;

	ret = rte_pktmbuf_alloc_bulk(entry->poll.malloc_pool,
		mbufs, MAX_PKT_BURST);
	if (ret)
		return;

	pre_ld_entry_stat_update(&entry->rx_stat, NULL,
		MAX_PKT_BURST, false);

	if (entry->dest_type == PRE_LD_MALLOC_RING) {
		nb_tx = pre_ld_ring_eq(entry->dest.pre_ld_malloc_ring,
			(void **)mbufs, MAX_PKT_BURST);
	} else {
		nb_tx = rte_ring_enqueue_burst(entry->dest.malloc_ring,
			(void * const *)mbufs, MAX_PKT_BURST, NULL);
	}
	pre_ld_entry_stat_update(&entry->tx_stat, NULL, nb_tx, false);

	if (nb_tx < MAX_PKT_BURST)
		rte_pktmbuf_free_bulk(&mbufs[nb_tx], MAX_PKT_BURST - nb_tx);
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
	struct pre_ld_direct_entry *free_entry = NULL;
	struct pre_ld_direct_entry *malloc_entry = NULL;
	struct pre_ld_direct_entry *rm;
	struct pre_ld_port_rx_flow *rx_flow = NULL;
	uint16_t mtu;
	char nm[RTE_MEMZONE_NAMESIZE];
	struct rte_mempool *tx_pool = NULL;

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
	rte_spinlock_init(&desc->rx_lock);
	rte_spinlock_init(&desc->tx_lock);

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

	ret = rte_ring_dequeue(s_port_flow_r[rx_port],
			(void **)&rx_flow);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"port%d: RX flow allocated for socket(%d) failed(%d)\n",
			tx_port, sockfd, ret);

		goto fd_init_quit;
	}
	memset(&rx_flow->flow, 0,
		sizeof(struct pre_ld_port_rx_flow) -
		offsetof(struct pre_ld_port_rx_flow, flow));

	if (s_data_path_core < 0) {
		desc->access_type = FD_HARDWARE_ACCESS;
		desc->dp_desc.hw_desc.rx_flow = rx_flow;
		desc->dp_desc.hw_desc.tx_port = tx_port;
		desc->eal_thread = 1;
	} else {
		desc->access_type = FD_THREAD_ACCESS;
		list = &s_pre_ld_lists[s_data_path_core];
		tx_entry = rte_zmalloc(NULL,
			sizeof(struct pre_ld_direct_entry), 0);
		if (!tx_entry) {
			ret = -ENOMEM;
			goto fd_init_quit;
		}
		if (s_fd_rte_ring) {
			tx_entry->poll_type = TX_RING;
			sprintf(nm, "tx_ring_fd%d", sockfd);
			tx_entry->poll.tx_ring = rte_ring_create(nm,
				MEMPOOL_USR_SIZE, 0,
				RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (!tx_entry->poll.tx_ring) {
				ret = -ENOMEM;
				goto fd_init_quit;
			}
		} else {
			tx_entry->poll_type = PRE_LD_TX_RING;
			sprintf(nm, "pre_ld_tx_ring_fd%d", sockfd);
			tx_entry->poll.pre_ld_tx_ring = pre_ld_ring_create(nm,
				MEMPOOL_USR_SIZE);
			if (!tx_entry->poll.pre_ld_tx_ring) {
				ret = -ENOMEM;
				goto fd_init_quit;
			}
		}
		tx_entry->dest_type = HW_PORT;
		tx_entry->dest.dest_port = tx_port;
		tx_entry->entry_cb = pre_ld_entry_usr_tx_process;
		tx_entry->poll_prefix = rte_zmalloc(NULL, 1024, 0);
		if (tx_entry->poll_prefix)
			sprintf(tx_entry->poll_prefix, "Receive from %s", nm);
		tx_entry->action_prefix = rte_zmalloc(NULL, 1024, 0);
		if (tx_entry->action_prefix) {
			sprintf(tx_entry->action_prefix,
				"-> send to port%d", tx_port);
		}

		ret = pre_ld_update_dir_list_safe(tx_entry,
			INSERT_ENTRY_REQ);
		if (ret) {
			RTE_LOG(INFO, pre_ld,
				"Insert FD[%d]'s tx entry failed(%d)\n",
				sockfd, ret);
			goto fd_init_quit;
		}
		desc->dp_desc.entry_desc.tx_entry = tx_entry;

		rx_entry = rte_zmalloc(NULL,
			sizeof(struct pre_ld_direct_entry), 0);
		if (!rx_entry) {
			ret = -ENOMEM;
			goto fd_init_quit;
		}
		rx_entry->poll_type = RX_QUEUE;
		rx_entry->poll.rx_flow = rx_flow;
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
		rx_entry->entry_cb = pre_ld_entry_usr_rx_process;
		rx_entry->poll_prefix = rte_zmalloc(NULL, 1024, 0);
		if (rx_entry->poll_prefix) {
			sprintf(rx_entry->poll_prefix,
				"Receive from port%d/queue%d",
				rx_port, rx_flow->src->queue_id);
		}
		rx_entry->action_prefix = rte_zmalloc(NULL, 1024, 0);
		if (rx_entry->action_prefix) {
			sprintf(rx_entry->action_prefix,
				"-> send to %s", nm);
		}
		desc->dp_desc.entry_desc.rx_entry = rx_entry;
		/** Postpone insert entry untile socket connects.*/

		free_entry = rte_zmalloc(NULL,
			sizeof(struct pre_ld_direct_entry), 0);
		if (!free_entry) {
			ret = -ENOMEM;
			goto fd_init_quit;
		}
		if (s_fd_rte_ring) {
			free_entry->poll_type = MBUF_FREE_RING;
			sprintf(nm, "free_ring_fd%d", sockfd);
			free_entry->poll.free_ring = rte_ring_create(nm,
				MEMPOOL_USR_SIZE, 0,
				RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (!free_entry->poll.free_ring) {
				ret = -ENOMEM;
				goto fd_init_quit;
			}
		} else {
			free_entry->poll_type = PRE_LD_MBUF_FREE_RING;
			sprintf(nm, "pre_ld_free_ring_fd%d", sockfd);
			free_entry->poll.pre_ld_free_ring =
				pre_ld_ring_create(nm, MEMPOOL_USR_SIZE);
			if (!free_entry->poll.pre_ld_free_ring) {
				ret = -ENOMEM;
				goto fd_init_quit;
			}
		}
		free_entry->entry_cb = pre_ld_entry_free_mbufs;
		free_entry->poll_prefix = rte_zmalloc(NULL, 1024, 0);
		if (free_entry->poll_prefix) {
			sprintf(free_entry->poll_prefix,
				"Poll FD%d' RX mbuf to be freed", sockfd);
		}
		free_entry->action_prefix = rte_zmalloc(NULL, 1024, 0);
		if (free_entry->action_prefix) {
			sprintf(free_entry->action_prefix,
				"-> Free mbuf");
		}

		free_entry->dest_type = FREE_MBUF;
		ret = pre_ld_update_dir_list_safe(free_entry,
			INSERT_ENTRY_REQ);
		if (ret) {
			RTE_LOG(INFO, pre_ld,
				"Insert FD[%d]'s free buffer entry failed(%d)\n",
				sockfd, ret);
			goto fd_init_quit;
		}
		desc->dp_desc.entry_desc.free_entry = free_entry;

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
	if (s_fd_mbuf_malloc_direct ||
		!s_fd_mbuf_malloc_hw_pool) {
		sprintf(nm, "tx_pool_fd%d", sockfd);
		tx_pool = rte_pktmbuf_pool_create_by_ops(nm,
				MEMPOOL_USR_SIZE, s_mempool_cache_size,
				PRE_LD_MP_PRIV_SIZE, PRE_LD_MBUF_MAX_SIZE,
				rte_socket_id(), RTE_MBUF_DEFAULT_MEMPOOL_OPS);
		if (!tx_pool) {
			ret = -ENOMEM;
			RTE_LOG(ERR, pre_ld, "Create %s failed\n", nm);
			goto fd_init_quit;
		}
		rte_mempool_obj_iter(tx_pool, pre_ld_pktmbuf_init, NULL);
	}

	if (s_fd_mbuf_malloc_direct) {
		desc->tx_pool = tx_pool;
	} else {
		desc->tx_pool = NULL;
		if (desc->access_type != FD_THREAD_ACCESS) {
			ret = -EINVAL;
			RTE_LOG(ERR, pre_ld,
				"FD[%d] needs data path thread to malloc TX buffer\n",
				sockfd);
			goto fd_init_quit;
		}
		malloc_entry = rte_zmalloc(NULL,
			sizeof(struct pre_ld_direct_entry), 0);
		if (!malloc_entry) {
			ret = -ENOMEM;
			goto fd_init_quit;
		}
		malloc_entry->poll_type = MBUF_MALLOC_POOL;
		if (s_fd_mbuf_malloc_hw_pool)
			malloc_entry->poll.malloc_pool = s_pre_ld_rx_pool;
		else
			malloc_entry->poll.malloc_pool = tx_pool;

		if (s_fd_rte_ring) {
			malloc_entry->dest_type = MALLOC_RING;
			sprintf(nm, "malloc_ring_fd%d", sockfd);
			malloc_entry->dest.malloc_ring = rte_ring_create(nm,
				MEMPOOL_USR_SIZE, 0,
				RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (!malloc_entry->dest.malloc_ring) {
				ret = -ENOMEM;
				goto fd_init_quit;
			}
		} else {
			malloc_entry->dest_type = PRE_LD_MALLOC_RING;
			sprintf(nm, "pre_ld_malloc_ring_fd%d", sockfd);
			malloc_entry->dest.pre_ld_malloc_ring =
				pre_ld_ring_create(nm, MEMPOOL_USR_SIZE);
			if (!malloc_entry->dest.pre_ld_malloc_ring) {
				ret = -ENOMEM;
				goto fd_init_quit;
			}
		}
		malloc_entry->entry_cb = pre_ld_entry_malloc_mbufs;
		malloc_entry->poll_prefix = rte_zmalloc(NULL, 1024, 0);
		if (malloc_entry->poll_prefix) {
			sprintf(malloc_entry->poll_prefix,
				"Malloc from %s for TX of user FD%d",
				malloc_entry->poll.malloc_pool->name, sockfd);
		}
		malloc_entry->action_prefix = rte_zmalloc(NULL, 1024, 0);
		if (malloc_entry->action_prefix) {
			sprintf(malloc_entry->action_prefix,
				"-> put into %s", nm);
		}
		ret = pre_ld_update_dir_list_safe(malloc_entry,
			INSERT_ENTRY_REQ);
		if (ret) {
			RTE_LOG(INFO, pre_ld,
				"Insert FD[%d]'s malloc buffer entry failed(%d)\n",
				sockfd, ret);
			goto fd_init_quit;
		}
		desc->dp_desc.entry_desc.malloc_entry = malloc_entry;
	}

fd_init_quit:
	if (!ret) {
		desc->tx_enable = true;
		desc->rx_enable = true;
		pthread_mutex_unlock(&s_fd_mutex);

		return 0;
	}

	if (rx_flow)
		rte_ring_enqueue(s_port_flow_r[rx_port], rx_flow);

	if (tx_pool)
		rte_mempool_free(tx_pool);

	if (desc->rx_buffer.rx_bufs)
		rte_free(desc->rx_buffer.rx_bufs);

	if (!desc || desc->access_type != FD_THREAD_ACCESS) {
		pthread_mutex_unlock(&s_fd_mutex);

		return ret;
	}

	if (desc->dp_desc.entry_desc.tx_entry) {
		rm = desc->dp_desc.entry_desc.tx_entry;
		ret = pre_ld_update_dir_list_safe(rm, REMOVE_ENTRY_REQ);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: remove FD[%d]'s tx entry failed(%d)\n",
				__func__, sockfd, ret);
		}
	}
	if (desc->dp_desc.entry_desc.free_entry) {
		rm = desc->dp_desc.entry_desc.free_entry;
		ret = pre_ld_update_dir_list_safe(rm, REMOVE_ENTRY_REQ);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: remove FD[%d]'s free entry failed(%d)\n",
				__func__, sockfd, ret);
		}
	}
	if (desc->dp_desc.entry_desc.malloc_entry && list) {
		rm = desc->dp_desc.entry_desc.malloc_entry;
		ret = pre_ld_update_dir_list_safe(rm, REMOVE_ENTRY_REQ);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: remove FD[%d]'s malloc entry failed(%d)\n",
				__func__, sockfd, ret);
		}
	}

	if (tx_entry &&
		tx_entry->poll_type == TX_RING &&
		tx_entry->poll.tx_ring)
		rte_ring_free(tx_entry->poll.tx_ring);
	else if (tx_entry &&
		tx_entry->poll_type == PRE_LD_TX_RING &&
		tx_entry->poll.pre_ld_tx_ring)
		pre_ld_ring_free(tx_entry->poll.pre_ld_tx_ring);
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

	if (free_entry &&
		free_entry->poll_type == MBUF_FREE_RING &&
		free_entry->poll.free_ring)
		rte_ring_free(free_entry->poll.free_ring);
	else if (free_entry &&
		free_entry->poll_type ==
		PRE_LD_MBUF_FREE_RING &&
		free_entry->poll.pre_ld_free_ring)
		pre_ld_ring_free(free_entry->poll.pre_ld_free_ring);
	if (free_entry)
		rte_free(free_entry);

	if (malloc_entry &&
		malloc_entry->dest_type == MALLOC_RING &&
		free_entry->dest.malloc_ring)
		rte_ring_free(free_entry->dest.malloc_ring);
	else if (malloc_entry &&
		malloc_entry->dest_type == PRE_LD_MALLOC_RING &&
		free_entry->dest.pre_ld_malloc_ring)
		pre_ld_ring_free(free_entry->dest.pre_ld_malloc_ring);
	if (malloc_entry)
		rte_free(malloc_entry);

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
	struct pre_ld_port_rx_flow *rx_flow;
	struct pre_ld_direct_entry *rx_entry;
	int ret;

	pthread_mutex_lock(&s_fd_mutex);
	if (is_usr_socket_connected(sockfd)) {
		pthread_mutex_unlock(&s_fd_mutex);
		return 0;
	}
	if ((s_fd_desc[sockfd].hdr_init &
		(LOCAL_UDP_INIT | REMOTE_UDP_INIT)) !=
		(LOCAL_UDP_INIT | REMOTE_UDP_INIT)) {
		RTE_LOG(INFO, pre_ld,
			"%s: Socket(%d) UDP header not initialized.\n",
			__func__, sockfd);
		pthread_mutex_unlock(&s_fd_mutex);
		return -EINVAL;
	}

	if (s_fd_desc[sockfd].access_type == FD_HARDWARE_ACCESS) {
		rx_flow = s_fd_desc[sockfd].dp_desc.hw_desc.rx_flow;
	} else {
		rx_entry = s_fd_desc[sockfd].dp_desc.entry_desc.rx_entry;
		rx_flow = rx_entry->poll.rx_flow;
	}
	rx_flow->type[0] = RTE_FLOW_ITEM_TYPE_UDP;
	memset(&rx_flow->items[0], 0, sizeof(union pre_ld_flow_item));
	memset(&rx_flow->masks[0], 0, sizeof(union pre_ld_flow_item));
	rx_flow->items[0].udp_spec.hdr.src_port =
		s_fd_desc[sockfd].hdr.udp_hdr.dst_port;
	rx_flow->items[0].udp_spec.hdr.dst_port =
		s_fd_desc[sockfd].hdr.udp_hdr.src_port;
	rx_flow->masks[0].udp_spec.hdr.src_port = 0xffff;
	rx_flow->masks[0].udp_spec.hdr.dst_port = 0xffff;

	ret = eal_create_flow(sockfd);
	pthread_mutex_unlock(&s_fd_mutex);

	return ret;
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

	if (is_usr_socket(sockfd) && is_usr_socket_connected(sockfd))
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

	if (is_usr_socket(sockfd) && is_usr_socket_connected(sockfd))
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

static uint16_t
netwrap_filter_fd_set(const fd_set *fds,
	const fd_set *filterd_fds, fd_set *rest_fds, int fd[])
{
	uint16_t num = 0;
	const uint8_t *_f, *_t;
	uint8_t *_r;
	uint64_t i, j;

	_f = (const void *)filterd_fds;
	_t = (const void *)fds;
	_r = (void *)rest_fds;
	for (i = 0; i < sizeof(fd_set); i++) {
		_r[i] = _t[i] & (~_f[i]);
		if (!_r[i])
			continue;
		for (j = 0; j < 8; j++) {
			if ((1 << j) & _r[i] &&
				!is_usr_socket(j + 8 * i)) {
				fd[num] = j + 8 * i;
				num++;
			}
		}
	}

	return num;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout)
{
	int ret = 0, i, off, hit;
	fd_set usr_rfds;
	fd_set usr_wfds;
	int usr_r_fd_num = 0, usr_w_fd_num = 0, user_fd_num = 0;
	fd_set sys_rfds;
	fd_set sys_wfds;
	fd_set *rfds = NULL, *wfds = NULL;
	int sys_r_fd_num = 0, sys_w_fd_num = 0;
	char log_buf[1024];
	int usr_r_fd[sizeof(fd_set) * 8];
	int usr_w_fd[sizeof(fd_set) * 8];
	int sys_r_fd[sizeof(fd_set) * 8];
	int sys_w_fd[sizeof(fd_set) * 8];
	struct fd_desc *usr, *tusr;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: nfds:%d, libc_select:%p\n",
			__func__, nfds, libc_select);
		dump_usr_fd(__func__);
	}

	if (unlikely(!libc_select)) {
		LIBC_FUNCTION(select);
		if (!libc_select) {
			ret = -1;
			errno = EACCES;

			return ret;
		}
	}

	RTE_TAILQ_FOREACH_SAFE(usr, &s_fd_desc_list, next, tusr) {
		hit = 0;
		if (readfds && FD_ISSET(usr->fd, readfds) &&
			is_usr_socket_connected(usr->fd)) {
			usr_r_fd[usr_r_fd_num] = usr->fd;
			usr_r_fd_num++;
			hit++;
		}
		if (writefds && FD_ISSET(usr->fd, writefds)) {
			usr_w_fd[usr_w_fd_num] = usr->fd;
			usr_w_fd_num++;
			hit++;
		}
		if (hit)
			user_fd_num++;
	}

	if (!user_fd_num) {
		return (*libc_select)(nfds, readfds, writefds,
				exceptfds, timeout);
	}

	memset(&usr_rfds, 0, sizeof(fd_set));
	memset(&usr_wfds, 0, sizeof(fd_set));
	for (i = 0; i < usr_r_fd_num; i++)
		FD_SET(usr_r_fd[i], &usr_rfds);
	for (i = 0; i < usr_w_fd_num; i++)
		FD_SET(usr_w_fd[i], &usr_wfds);

	memset(&sys_rfds, 0, sizeof(fd_set));
	memset(&sys_wfds, 0, sizeof(fd_set));

	if (readfds) {
		sys_r_fd_num = netwrap_filter_fd_set(readfds,
			&usr_rfds, &sys_rfds, sys_r_fd);
	}
	if (writefds) {
		sys_w_fd_num = netwrap_filter_fd_set(writefds,
			&usr_wfds, &sys_wfds, sys_w_fd);
	}

	if (!s_select_dbg)
		goto select_fds;

	off = 0;
	if (sys_r_fd_num) {
		off += sprintf(&log_buf[off],
			"Sys read FD(s)(=%d): ", sys_r_fd_num);
		for (i = 0; i < sys_r_fd_num; i++)
			off += sprintf(&log_buf[off], "%d ", sys_r_fd[i]);
	}
	if (sys_w_fd_num) {
		off += sprintf(&log_buf[off],
			"/Sys write FD(s)(=%d): ", sys_w_fd_num);
		for (i = 0; i < sys_w_fd_num; i++)
			off += sprintf(&log_buf[off], "%d ", sys_w_fd[i]);
	}
	if (usr_r_fd_num) {
		off += sprintf(&log_buf[off],
			"/Usr read FD(s)(=%d): ", usr_r_fd_num);
		for (i = 0; i < usr_r_fd_num; i++)
			off += sprintf(&log_buf[off], "%d ", usr_r_fd[i]);
	}
	if (usr_w_fd_num) {
		off += sprintf(&log_buf[off],
			"/Usr write FD(s)(=%d): ", usr_w_fd_num);
		for (i = 0; i < usr_w_fd_num; i++)
			off += sprintf(&log_buf[off], "%d ", usr_w_fd[i]);
	}

	RTE_LOG(INFO, pre_ld, "%s: %s\n", __func__, log_buf);

select_fds:
	if ((readfds && !memcmp(&usr_rfds, readfds, sizeof(fd_set)) &&
		writefds && !memcmp(&usr_wfds, writefds, sizeof(fd_set))) ||
		(readfds && !writefds &&
		!memcmp(&usr_rfds, readfds, sizeof(fd_set))) ||
		(writefds && !readfds &&
		!memcmp(&usr_wfds, writefds, sizeof(fd_set)))) {
		/** TBD: User FD select only.*/
		ret = user_fd_num;
	} else {
		if (sys_r_fd_num)
			rfds = &sys_rfds;
		if (sys_w_fd_num)
			wfds = &sys_wfds;

		ret = (*libc_select)(nfds, rfds, wfds, exceptfds, timeout);
		if (readfds && rfds)
			rte_memcpy(readfds, rfds, sizeof(fd_set));
		if (writefds && wfds)
			rte_memcpy(writefds, wfds, sizeof(fd_set));
	}

	return ret;
}

__attribute__((destructor)) static void netwrap_main_dtor(void)
{
	if (!netwrap_is_usr_process())
		return;

	eal_quit();
	if (s_fd_desc)
		free(s_fd_desc);
	s_fd_desc = NULL;

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
	int i, j, ret;
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

	if (!getenv("DPAA2_TX_CONF_FD_OVERFLOW"))
		setenv("DPAA2_TX_CONF_FD_OVERFLOW", "64", 1);

	if (!getenv("PRE_LOAD_IPSEC_BUF_SWAP"))
		setenv("PRE_LOAD_IPSEC_BUF_SWAP", "1", 1);

	/* We have to set flow control, otherwise, traffic congests
	 * at other end to discard IKE frames to get failure of
	 * IPSec rekey.
	 */
	if (!getenv("PRE_LOAD_FLOW_CONTROL_ENABLE"))
		setenv("PRE_LOAD_FLOW_CONTROL_ENABLE", "1", 1);

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

	env = getenv("PRE_LOAD_SELECT_DEBUG");
	if (env)
		s_select_dbg = atoi(env);

	env = getenv("PRE_LOAD_USER_FD_MALLOC");
	if (env)
		s_fd_mbuf_malloc_direct = atoi(env);

	env = getenv("PRE_LOAD_USER_FD_MALLOC_HW_POOL");
	if (env)
		s_fd_mbuf_malloc_hw_pool = atoi(env);

	env = getenv("IPSEC_IB_FLOW_IP_ADDR_EXTRACT");
	if (env)
		s_ipsec_ib_flow_ip_addr_extract = atoi(env);

	env = getenv("PRE_LOAD_USER_FD_DATA_VERIFY");
	if (env)
		s_data_verify = atoi(env);

	env = getenv("PRE_LOAD_USER_FD_DATA_VERIFY_ERR_PANIC");
	if (env)
		s_data_verify_err_panic = atoi(env);

	env = getenv("PRE_LOAD_MEMPOOL_CACHE_SIZE");
	if (env) {
		s_mempool_cache_size = atoi(env);
		if (!RTE_IS_POWER_OF_2(s_mempool_cache_size) ||
			s_mempool_cache_size > MEMPOOL_CACHE_SIZE) {
			RTE_LOG(WARNING, pre_ld,
				"Invalid mempool cache size(%d), reset it as zero\n",
				s_mempool_cache_size);
			s_mempool_cache_size = 0;
		}
	}

	env = getenv("PRE_LOAD_PAUSE_TRAFFIC_FLOW_UPDATING");
	if (env)
		s_pause_traffic_flow_updating = atoi(env);

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

	for (i = 0; i < PRE_LD_MUX_MAX_NUM; i++) {
		for (j = 0; j < PRE_LD_MUX_MAX_IF_NUM; j++)
			s_mux_cfg[i].entry_id[j] = -1;
	}

	for (i = 0; i < PRE_LD_DIR_MAX_IF_NUM; i++) {
		s_dir_ports.pair[i].ul_id = -1;
		s_dir_ports.pair[i].dl_id = -1;
		s_dir_ports.recyc_pair[i].ul_id = -1;
		s_dir_ports.recyc_pair[i].dl_id = -1;
	}

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
