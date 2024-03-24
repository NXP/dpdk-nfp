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
#include <rte_pmd_dpaa2.h>
#include <nxp/rte_remote_direct_flow.h>

#include "netwrap.h"

#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif
#define INVALID_SOCKFD (-1)
static int s_socket_pre_set;
static int s_eal_inited;
static pthread_mutex_t s_eal_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_dp_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint16_t s_cpu_start = 1;
#define SYS_CORE_ID 0

static const char *s_dpdmux_ep_name;
static int s_dpdmux_id = -1;
static int s_dpdmux_ep_id;

static const char *s_eal_file_prefix;
static const char *s_uplink;
static const char *s_slow_if;
static const char *s_downlink;

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

struct fd_desc {
	int fd;
	int cpu;
	pthread_t thread;
	struct eth_ipv4_udp_hdr hdr;
	enum hdr_init_enum hdr_init;
	uint16_t rx_port;
	uint16_t *rxq_id;
	struct rte_ring *rx_ring;
	uint16_t tx_port;
	uint16_t *txq_id;
	struct rte_ring *tx_ring;
	void *flow;
	struct rte_mempool *tx_pool;
	struct pre_ld_rx_pool rx_buffer;

	uint64_t tx_count;
	uint64_t tx_pkts;
	uint64_t tx_oh_bytes;
	uint64_t tx_usr_bytes;

	uint64_t rx_count;
	uint64_t rx_pkts;
	uint64_t rx_oh_bytes;
	uint64_t rx_usr_bytes;
};

pthread_mutex_t s_fd_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct fd_desc *s_fd_desc;
static int s_fd_usr[MAX_USR_FD_NUM];
static int s_usr_fd_num;
static int s_max_usr_fd = INVALID_SOCKFD;

#define UDP_HDR_LEN sizeof(struct rte_udp_hdr)

#define IPv4_HDR_LEN \
	(sizeof(struct rte_ipv4_hdr) + UDP_HDR_LEN)

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
static uint16_t s_rxq_ids[RTE_MAX_ETHPORTS][MAX_QUEUES_PER_PORT];
static uint16_t s_txq_ids[RTE_MAX_ETHPORTS][MAX_QUEUES_PER_PORT];

static struct rte_eth_conf s_port_conf = {
	.rxmode = {0},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

static struct rte_mempool *s_pre_ld_rx_pool;
static int s_tx_from_rx_pool;

struct pre_ld_dir_traffic_cfg {
	int valid;
	uint16_t ext_id;
	uint16_t ul_id;
	uint16_t dl_id;
	uint16_t tap_id;
	uint16_t rxq_nb[RTE_MAX_ETHPORTS];
};

static struct pre_ld_dir_traffic_cfg s_dir_traffic_cfg;

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

struct pre_ld_rxq_port {
	uint16_t port_id;
	uint16_t queue_id;
};

enum pre_ld_poll_type {
	RX_QUEUE,
	TX_RING,
	SELF_GEN
};

struct pre_ld_poll_tx_ring {
	struct rte_ring **tx_ring;
	uint16_t tx_ring_num;
};

union pre_ld_poll {
	struct pre_ld_rxq_port poll_queue;
	struct pre_ld_poll_tx_ring tx_rings;
};

enum pre_ld_fwd_type {
	HW_PORT,
	RX_RING,
	DROP
};

union pre_ld_fwd {
	uint16_t fwd_port;
	struct rte_ring *rx_ring;
};

struct pre_ld_lcore_fwd {
	enum pre_ld_poll_type poll_type;
	union pre_ld_poll poll;
	enum pre_ld_fwd_type fwd_type;
	union pre_ld_fwd fwd_dest;
	uint64_t tx_count;
	uint64_t tx_pkts;
	uint64_t tx_oh_bytes;

	uint64_t rx_count;
	uint64_t rx_pkts;
	uint64_t rx_oh_bytes;
};

#define MAX_RX_POLLS_PER_LCORE 16

struct pre_ld_lcore_conf {
	uint16_t n_fwds;
	struct pre_ld_lcore_fwd fwd[MAX_RX_POLLS_PER_LCORE];
};
static struct pre_ld_lcore_conf s_pre_ld_lcore[RTE_MAX_LCORE];
static pthread_mutex_t s_lcore_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Single core support only now.*/
static int s_pre_ld_quit;

/** Single rx/tx ports pair support only now, default 0.*/
static uint16_t s_rx_port;
static uint16_t s_tx_port;

static int s_dpdmux_entry_index = -1;

#define MAX_DEFAULT_FLOW_NUM 8
static struct rte_flow *s_default_flow[MAX_DEFAULT_FLOW_NUM];
static uint16_t s_default_flow_num;

static int s_data_path_core = -1;

struct pre_ld_udp_desc {
	uint16_t offset;
	uint16_t length;
} __rte_packed;

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

static void eal_quit(void)
{
	uint16_t portid, drain, i;
	int ret;

	s_pre_ld_quit = 1;
	sleep(1);

	while (s_usr_fd_num) {
		for (i = 0; i < s_usr_fd_num; i++) {
			if (s_fd_desc[s_fd_usr[i]].fd !=
				INVALID_SOCKFD)
				close(s_fd_desc[s_fd_usr[i]].fd);
		}
	}

	ret = eal_destroy_dpaa2_mux_flow();
	if (ret) {
		RTE_LOG(INFO, pre_ld, "Destroy mux flow failed(%d)",
			ret);
	}
	RTE_ETH_FOREACH_DEV(portid) {
		if (portid == s_tx_port) {
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

	/* clean up the EAL */
	rte_eal_cleanup();
	RTE_LOG(INFO, pre_ld, "Bye...\n");
}

static int
eal_data_path_thread_register(struct fd_desc *desc)
{
	int ret, cpu, new_cpu, lcore;
	rte_cpuset_t cpuset;
	pthread_t thread = pthread_self();

	cpu = sched_getcpu();
	if (likely((desc->cpu == cpu &&
		thread == desc->thread) ||
		thread == s_main_td))
		return 0;

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
	desc->cpu = new_cpu;
	desc->thread = pthread_self();
	RTE_LOG(INFO, pre_ld,
		"Register thread(%ld) of FD(%d) from cpu(%d) to cpu(%d)\n",
		pthread_self(), desc->fd, cpu, desc->cpu);

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
			"UDP offset = %d, IPV6 or tunnel frame?\n",
			l4_offset);
	}

	udp_hdr = rte_pktmbuf_mtod_offset(mbuf, void *, l4_offset);
	if (unlikely(udp_hdr->src_port != flow_hdr->dst_port ||
		udp_hdr->dst_port != flow_hdr->src_port)) {
		RTE_LOG(WARNING, pre_ld,
			"UDP RX ERR(src %04x!=%04x, dst %04x!=%04x).\n",
			udp_hdr->src_port, flow_hdr->src_port,
			udp_hdr->dst_port, flow_hdr->dst_port);
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
	uint32_t nb_rx, i, total_bytes = 0, j;
	size_t length, remain = len;
	struct pre_ld_udp_desc *desc;
	uint16_t rxq_id;
	int ret;
	uint8_t *buf_u8 = buf, *pkt;
	struct pre_ld_rx_pool *rx_pool = &s_fd_desc[sockfd].rx_buffer;

	RTE_SET_USED(flags);

	ret = eal_data_path_thread_register(&s_fd_desc[sockfd]);
	if (ret)
		return ret;

	i = 0;
	while (rx_pool->head != rx_pool->tail &&
		total_bytes < len) {
		mbuf = rx_pool->rx_bufs[rx_pool->head];
		desc = rte_pktmbuf_mtod(mbuf, void *);
		length = desc->length;
		pkt = ((uint8_t *)desc + desc->offset);
		if (length <= remain) {
			rte_memcpy(&buf_u8[total_bytes], pkt, length);
			s_fd_desc[sockfd].rx_usr_bytes += length;
			remain -= length;
			total_bytes += length;
			free_burst[i] = mbuf;
			i++;
			rx_pool->rx_bufs[rx_pool->head] = NULL;
			rx_pool->head = (rx_pool->head + 1) &
				(rx_pool->max_num - 1);
		} else {
			rte_memcpy(&buf_u8[total_bytes], pkt, remain);
			s_fd_desc[sockfd].rx_usr_bytes += remain;
			remain = 0;
			total_bytes += remain;
			desc->offset += remain;
			desc->length -= remain;
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

	if (s_fd_desc[sockfd].rx_ring) {
		nb_rx = rte_ring_dequeue_burst(s_fd_desc[sockfd].rx_ring,
				(void **)pkts_burst, MAX_PKT_BURST, NULL);
	} else {
		if (unlikely(!s_fd_desc[sockfd].rxq_id)) {
			RTE_LOG(ERR, pre_ld,
				"Socket(%d): rxq not initialized!\n", sockfd);
			return -EIO;
		}
		rxq_id = *s_fd_desc[sockfd].rxq_id;
		nb_rx = rte_eth_rx_burst(s_fd_desc[sockfd].rx_port,
				rxq_id, pkts_burst, MAX_PKT_BURST);
	}
	for (i = 0; i < nb_rx; i++) {
		s_fd_desc[sockfd].rx_oh_bytes +=
			pkts_burst[i]->pkt_len +
			RTE_TM_ETH_FRAMING_OVERHEAD_FCS;
	}
	s_fd_desc[sockfd].rx_pkts += nb_rx;
	s_fd_desc[sockfd].rx_count++;
	if (!nb_rx)
		goto finsh_recv;
	j = 0;
	for (i = 0; i < nb_rx; i++) {
		ret = pre_ld_adjust_rx_l4_info(sockfd, pkts_burst[i]);
		if (unlikely(ret))
			break;
		desc = rte_pktmbuf_mtod(pkts_burst[i], void *);
		pkt = (uint8_t *)desc + desc->offset;
		length = desc->length;
		if (remain >= length) {
			rte_memcpy(&buf_u8[total_bytes], pkt, length);
			s_fd_desc[sockfd].rx_usr_bytes += length;
			remain -= length;
			total_bytes += length;
			free_burst[j] = pkts_burst[i];
			j++;
		} else {
			rte_memcpy(&buf_u8[total_bytes], pkt, remain);
			s_fd_desc[sockfd].rx_usr_bytes += remain;
			remain = 0;
			total_bytes += remain;
			desc->offset += remain;
			desc->length -= remain;
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
eal_send_fill_mbuf(const void *buf, size_t len, int fd,
	struct rte_mbuf *m)
{
	void *udp_data;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_udp_hdr *udp_hdr;

	/* Initialize the Ethernet header */
	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	rte_memcpy(eth_hdr, &s_fd_desc[fd].hdr,
		sizeof(struct eth_ipv4_udp_hdr));
	/* Set IP header length then calculate checksum.*/
	ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	ip_hdr->total_length = rte_cpu_to_be_16(len + IPv4_HDR_LEN);
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

	/* Set UDP header length only*/
	udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
	udp_hdr->dgram_len = rte_cpu_to_be_16(len + UDP_HDR_LEN);

	udp_data = (void *)(udp_hdr + 1);
	if (buf)
		rte_memcpy(udp_data, buf, len);
	m->data_off = RTE_PKTMBUF_HEADROOM;
	m->nb_segs = 1;
	m->next = NULL;
	m->data_len = len + sizeof(*eth_hdr) +
		sizeof(*ip_hdr) + sizeof(*udp_hdr);
	if (m->data_len < 60)
		m->data_len = 60;
	m->pkt_len = m->data_len;
}

static int
eal_send(int sockfd, const void *buf, size_t len, int flags)
{
	struct rte_mbuf *m = NULL;
	int sent, cnt, ret;
	uint16_t txq_id;
	uint32_t byte, byte_overhead;
	struct rte_mempool *pool = s_tx_from_rx_pool ?
		s_pre_ld_rx_pool : s_fd_desc[sockfd].tx_pool;

	RTE_SET_USED(sockfd);
	RTE_SET_USED(flags);

	ret = eal_data_path_thread_register(&s_fd_desc[sockfd]);
	if (ret)
		return ret;

	cnt = 0;
	m = rte_pktmbuf_alloc(pool);
	if (unlikely(!m)) {
		RTE_LOG(WARNING, pre_ld,
			"Alloc from TX pool %s failed\n", pool->name);
		return 0;
	}

	eal_send_fill_mbuf(buf, len, sockfd, m);
	byte = m->pkt_len;
	byte_overhead = byte + RTE_TM_ETH_FRAMING_OVERHEAD_FCS;

	if (s_fd_desc[sockfd].tx_ring) {
		cnt = 0;
eq_again:
		sent = rte_ring_enqueue(s_fd_desc[sockfd].tx_ring, m);
		if (!sent) {
			sent = 1;
		} else {
			if (cnt < 100) {
				cnt++;
				goto eq_again;
			}
		}
	} else {
		if (unlikely(!s_fd_desc[sockfd].txq_id)) {
			RTE_LOG(ERR, pre_ld,
				"%s: Socket(%d) txq not available\n",
				__func__, sockfd);
			goto send_err;
		}
		txq_id = *s_fd_desc[sockfd].txq_id;
		sent = rte_eth_tx_burst(s_fd_desc[sockfd].tx_port,
			txq_id, &m, 1);
	}
	if (likely(sent == 1)) {
		s_fd_desc[sockfd].tx_usr_bytes += len;
		s_fd_desc[sockfd].tx_oh_bytes += byte_overhead;
		s_fd_desc[sockfd].tx_pkts++;
		s_fd_desc[sockfd].tx_count++;

		return len;
	}

send_err:
	rte_pktmbuf_free(m);
	return 0;
}

static void
pre_ld_configure_direct_traffic(uint16_t ext_id,
	uint16_t ul_id, uint16_t dl_id,
	uint16_t tap_id, uint16_t rxq_nb[])
{
	uint16_t i, lcore_id;
	struct rte_flow *flow;
	uint32_t prio[2];
	struct pre_ld_lcore_conf *lcore;
	struct pre_ld_lcore_fwd *fwd;
	char dl_nm[RTE_ETH_NAME_MAX_LEN];
	char tap_nm[RTE_ETH_NAME_MAX_LEN];

	rte_eth_dev_get_name_by_port(dl_id, dl_nm);
	rte_eth_dev_get_name_by_port(tap_id, tap_nm);

	if (s_data_path_core < 0)
		rte_exit(EXIT_FAILURE, "No data path core available\n");
	lcore_id = s_data_path_core;

	s_def_dir_num = 2;
	strcpy(s_def_dir[0].from_name, dl_nm);
	strcpy(s_def_dir[0].to_name, tap_nm);
	/**Assume only single TC support and
	 * direct flow is lowest priority.
	 */
	prio[0] = rxq_nb[dl_id] - 1;
	strcpy(s_def_dir[1].from_name, tap_nm);
	strcpy(s_def_dir[1].to_name, dl_nm);
	prio[1] = rxq_nb[tap_id] - 1;

	for (i = 0; i < s_def_dir_num; i++) {
		flow = rte_remote_default_direct(s_def_dir[i].from_name,
				s_def_dir[i].to_name, NULL,
				DEFAULT_DIRECT_GROUP, prio[i]);
		if (!flow) {
			RTE_LOG(WARNING, pre_ld,
				"default flow (%s)->(%s) created failed\n",
				s_def_dir[i].from_name,
				s_def_dir[i].to_name);
		} else {
			s_default_flow[s_default_flow_num] = flow;
			s_default_flow_num++;
		}
	}

	lcore = &s_pre_ld_lcore[lcore_id];
	if (lcore->n_fwds >= MAX_RX_POLLS_PER_LCORE)
		rte_exit(EXIT_FAILURE, "Too many forwards\n");
	pthread_mutex_lock(&s_lcore_mutex);
	fwd = &lcore->fwd[lcore->n_fwds];
	fwd->poll_type = RX_QUEUE;
	fwd->poll.poll_queue.port_id = ext_id;
	fwd->poll.poll_queue.queue_id = 0;
	fwd->fwd_type = HW_PORT;
	fwd->fwd_dest.fwd_port = ul_id;
	rte_wmb();
	lcore->n_fwds++;

	fwd = &lcore->fwd[lcore->n_fwds];
	fwd->poll_type = RX_QUEUE;
	fwd->poll.poll_queue.port_id = ul_id;
	fwd->poll.poll_queue.queue_id = 0;
	fwd->fwd_type = HW_PORT;
	fwd->fwd_dest.fwd_port = ext_id;
	rte_wmb();
	lcore->n_fwds++;
	pthread_mutex_unlock(&s_lcore_mutex);
}

static void
pre_ld_configure_split_traffic(uint32_t portid)
{
	const char *ep_name;
	int ret, id = -1, ep_id = -1;

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

		return;
	}

	ret = rte_remote_parse_ep_name(ep_name,
			NULL, &ep_id);
	if (!ret) {
		if (s_downlink) {
			RTE_LOG(WARNING, pre_ld,
				"Multiple downlinks(%s)(%s) detected.\n",
				s_downlink, ep_name);
		}
		if (!s_uplink) {
			RTE_LOG(WARNING, pre_ld,
				"No uplink specified\n");
		}
		s_downlink = ep_name;
		RTE_LOG(INFO, pre_ld,
			"%s <-> %s is hijacked.\n",
			s_uplink, s_downlink);
	}
}

static int
pre_ld_main_loop(void *dummy)
{
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	uint32_t lcore_id;
	int i, nb_rx, j, fd;
	uint16_t nb_tx, portid, queueid, nb_txr_burst;
	struct pre_ld_lcore_conf *qconf;
	struct pre_ld_lcore_fwd *fwd;
	uint64_t bytes_overhead[MAX_PKT_BURST];
	struct rte_ring *txr;
	struct pre_ld_poll_tx_ring *tx_rings;
	struct rte_mempool *tx_pool = NULL;

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
	qconf = &s_pre_ld_lcore[lcore_id];
	s_data_path_core = lcore_id;

	pre_ld_configure_direct_traffic(s_dir_traffic_cfg.ext_id,
		s_dir_traffic_cfg.ul_id,
		s_dir_traffic_cfg.dl_id,
		s_dir_traffic_cfg.tap_id,
		s_dir_traffic_cfg.rxq_nb);
	pthread_mutex_unlock(&s_dp_init_mutex);

	RTE_LOG(INFO, pre_ld,
		"entering main loop %d fwds on lcore %u\n",
		qconf->n_fwds, lcore_id);

	tx_pool = rte_pktmbuf_pool_create_by_ops("tx_self_gen_pool",
		MEMPOOL_ELEM_SIZE, MEMPOOL_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id(),
		RTE_MBUF_DEFAULT_MEMPOOL_OPS);
	if (!tx_pool) {
		RTE_LOG(WARNING, pre_ld,
			"TX self gen pool created failed\n");
	}

for_ever_loop:
	if (s_pre_ld_quit)
		return 0;

	for (i = 0; i < qconf->n_fwds; i++) {
		fwd = &qconf->fwd[i];

		if (fwd->poll_type == RX_QUEUE) {
			portid = fwd->poll.poll_queue.port_id;
			queueid = fwd->poll.poll_queue.queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid,
					mbufs, MAX_PKT_BURST);
		} else if (fwd->poll_type == TX_RING) {
			tx_rings = &fwd->poll.tx_rings;
			if (!tx_rings->tx_ring_num)
				continue;
			nb_txr_burst = MAX_PKT_BURST / tx_rings->tx_ring_num;
			nb_rx = 0;
			for (j = 0; j < tx_rings->tx_ring_num; j++) {
				txr = tx_rings->tx_ring[j];
				nb_rx += rte_ring_dequeue_burst(txr,
					(void **)&mbufs[nb_rx], nb_txr_burst,
					NULL);
			}
		} else if (fwd->poll_type == SELF_GEN) {
			if (s_usr_fd_num <= 0) {
				nb_rx = 0;
				continue;
			}
			fd = s_fd_usr[s_usr_fd_num - 1];
			if (!tx_pool) {
				rte_exit(EXIT_FAILURE,
					"No TX pool fro self gen available\n");
			}
			if (!rte_pktmbuf_alloc_bulk(tx_pool, mbufs,
				MAX_PKT_BURST))
				nb_rx = MAX_PKT_BURST;
			else
				nb_rx = 0;
			for (j = 0; j < nb_rx; j++)
				eal_send_fill_mbuf(NULL, 64, fd, mbufs[j]);
		} else {
			nb_rx = 0;
		}

		if (!nb_rx)
			continue;

		for (j = 0; j < nb_rx; j++) {
			bytes_overhead[j] = mbufs[j]->pkt_len +
				RTE_TM_ETH_FRAMING_OVERHEAD_FCS;
			fwd->rx_oh_bytes += bytes_overhead[j];
		}
		fwd->rx_pkts += nb_rx;
		fwd->rx_count++;

		if (fwd->fwd_type == HW_PORT) {
			portid = fwd->fwd_dest.fwd_port;
			nb_tx = rte_eth_tx_burst(portid, 0, mbufs, nb_rx);
		} else if (fwd->fwd_type == RX_RING) {
			nb_tx = rte_ring_enqueue_burst(fwd->fwd_dest.rx_ring,
					(void * const *)mbufs, nb_rx, NULL);
		} else {
			nb_tx = 0;
		}
		for (j = 0; j < nb_tx; j++) {
			fwd->tx_oh_bytes += bytes_overhead[j];
		}
		fwd->tx_pkts += nb_tx;
		fwd->tx_count++;
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
		}
	}

	if (port_num == 1) {
		RTE_ETH_FOREACH_DEV(portid1) {
			if (rte_pmd_dpaa2_dev_is_dpaa2(portid1)) {
				port_type[portid1] = DOWN_LINK_TYPE;
				type_val = DOWN_LINK_TYPE;
			}
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

static void *
pre_ld_data_path_statistics(void *arg)
{
	uint16_t i, j;
	struct pre_ld_lcore_conf *qconf;
	struct pre_ld_poll_tx_ring *tx_rings;
	char poll_info[512], fwd_info[512];
	char rx_stat_info[512], tx_stat_info[512];
	const char *space = "        ";
	int offset, fd;
	uint64_t tx_old_count[MAX_RX_POLLS_PER_LCORE];
	uint64_t tx_old_pkts[MAX_RX_POLLS_PER_LCORE];
	uint64_t tx_old_oh_bytes[MAX_RX_POLLS_PER_LCORE];

	uint64_t rx_old_count[MAX_RX_POLLS_PER_LCORE];
	uint64_t rx_old_pkts[MAX_RX_POLLS_PER_LCORE];
	uint64_t rx_old_oh_bytes[MAX_RX_POLLS_PER_LCORE];

	uint64_t tx_old_fd_pkts[MAX_RX_POLLS_PER_LCORE];
	uint64_t tx_old_fd_oh_bytes[MAX_RX_POLLS_PER_LCORE];
	uint64_t tx_old_fd_usr_bytes[MAX_RX_POLLS_PER_LCORE];

	uint64_t rx_old_fd_pkts[MAX_RX_POLLS_PER_LCORE];
	uint64_t rx_old_fd_oh_bytes[MAX_RX_POLLS_PER_LCORE];
	uint64_t rx_old_fd_usr_bytes[MAX_RX_POLLS_PER_LCORE];

	uint64_t count_diff, pkt_diff, oh_diff;

	memset(tx_old_count, 0, sizeof(tx_old_count));
	memset(tx_old_pkts, 0, sizeof(tx_old_pkts));
	memset(tx_old_oh_bytes, 0, sizeof(tx_old_oh_bytes));

	memset(rx_old_count, 0, sizeof(rx_old_count));
	memset(rx_old_pkts, 0, sizeof(rx_old_pkts));
	memset(rx_old_oh_bytes, 0, sizeof(rx_old_oh_bytes));

	memset(tx_old_fd_pkts, 0, sizeof(tx_old_fd_pkts));
	memset(tx_old_fd_oh_bytes, 0, sizeof(tx_old_fd_oh_bytes));
	memset(tx_old_fd_usr_bytes, 0, sizeof(tx_old_fd_usr_bytes));

	memset(rx_old_fd_pkts, 0, sizeof(rx_old_fd_pkts));
	memset(rx_old_fd_oh_bytes, 0, sizeof(rx_old_fd_oh_bytes));
	memset(rx_old_fd_usr_bytes, 0, sizeof(rx_old_fd_usr_bytes));

statistics_loop:
	if (s_data_path_core < 0)
		goto usr_fd_statistics;

	qconf = &s_pre_ld_lcore[s_data_path_core];
	for (i = 0; i < qconf->n_fwds; i++) {
		if (qconf->fwd[i].poll_type == RX_QUEUE) {
			sprintf(poll_info, "Poll from port%d/queue%d",
				qconf->fwd[i].poll.poll_queue.port_id,
				qconf->fwd[i].poll.poll_queue.queue_id);
		} else if (qconf->fwd[i].poll_type == TX_RING) {
			tx_rings = &qconf->fwd[i].poll.tx_rings;
			offset = sprintf(poll_info, "Poll from tx rings:");
			for (j = 0; j < tx_rings->tx_ring_num; j++) {
				offset += sprintf(&poll_info[offset],
					" (%s)", tx_rings->tx_ring[j]->name);
			}
		} else if (qconf->fwd[i].poll_type == SELF_GEN) {
			sprintf(poll_info, "self gen tx frames");
		} else {
			sprintf(poll_info, "Err poll type(%d)",
				qconf->fwd[i].poll_type);
		}
		if (qconf->fwd[i].fwd_type == HW_PORT) {
			sprintf(fwd_info, "then forward to port%d",
				qconf->fwd[i].fwd_dest.fwd_port);
		} else if (qconf->fwd[i].fwd_type == RX_RING) {
			sprintf(fwd_info, "then forward to rx ring(%s)",
				qconf->fwd[i].fwd_dest.rx_ring->name);
		} else {
			sprintf(fwd_info, "then drop");
		}
		count_diff = qconf->fwd[i].tx_count - tx_old_count[i];
		pkt_diff = qconf->fwd[i].tx_pkts - tx_old_pkts[i];
		oh_diff = qconf->fwd[i].tx_oh_bytes -
			tx_old_oh_bytes[i];
		tx_old_count[i] = qconf->fwd[i].tx_count;
		tx_old_pkts[i] = qconf->fwd[i].tx_pkts;
		tx_old_oh_bytes[i] = qconf->fwd[i].tx_oh_bytes;

		if (count_diff > 0) {
			offset = sprintf(tx_stat_info,
				"Average tx burst(%.1f)(%ld/%ld) ",
				pkt_diff / (double)count_diff,
				pkt_diff, count_diff);
		} else {
			offset = 0;
		}
		offset += sprintf(&tx_stat_info[offset],
			"send line: %.2fGbps, %.2fMPPS",
			(double)oh_diff * 8 /
			(STATISTICS_DELAY_SEC *
			(double)(1000 * 1000 * 1000)),
			(double)pkt_diff * 8 /
			(STATISTICS_DELAY_SEC *
			(double)(1000 * 1000)));

		count_diff = qconf->fwd[i].rx_count - rx_old_count[i];
		pkt_diff = qconf->fwd[i].rx_pkts - rx_old_pkts[i];
		oh_diff = qconf->fwd[i].rx_oh_bytes -
			rx_old_oh_bytes[i];
		rx_old_count[i] = qconf->fwd[i].rx_count;
		rx_old_pkts[i] = qconf->fwd[i].rx_pkts;
		rx_old_oh_bytes[i] = qconf->fwd[i].rx_oh_bytes;
		if (count_diff > 0) {
			offset = sprintf(rx_stat_info,
				"Average rx burst(%.1f)(%ld/%ld) ",
				pkt_diff / (double)count_diff,
				pkt_diff, count_diff);
		} else {
			offset = 0;
		}

		sprintf(&rx_stat_info[offset],
			"recv line: %.2fGbps, %.2fMPPS",
			(double)oh_diff * 8 /
			(STATISTICS_DELAY_SEC *
			(double)(1000 * 1000 * 1000)),
			(double)pkt_diff * 8 /
			(STATISTICS_DELAY_SEC *
			(double)(1000 * 1000)));

		RTE_LOG(INFO, pre_ld,
			"FWD[%d] on core%d:\n%s%s %s\n%s%s\n%s%s\n\n",
			i, s_data_path_core,
			space, poll_info, fwd_info,
			space, rx_stat_info,
			space, tx_stat_info);
	}

usr_fd_statistics:
	if (s_usr_fd_num <= 0)
		goto statistics_continue;

	fd = s_fd_usr[s_usr_fd_num - 1];
	for (i = 0; i < s_usr_fd_num; i++) {
		fd = s_fd_usr[i];
		RTE_LOG(INFO, pre_ld,
			"FD(%d) send line: %.2fGbps, usr: %.2fGbps, %.2fMPPS\n",
			fd, (double)(s_fd_desc[fd].tx_oh_bytes -
			tx_old_fd_oh_bytes[i]) * 8 /
			(STATISTICS_DELAY_SEC *
			(double)(1000 * 1000 * 1000)),
			(double)(s_fd_desc[fd].tx_usr_bytes -
			tx_old_fd_usr_bytes[i]) * 8 /
			(STATISTICS_DELAY_SEC *
			(double)(1000 * 1000 * 1000)),
			(double)(s_fd_desc[fd].tx_pkts -
			tx_old_fd_pkts[i]) * 8 /
			(STATISTICS_DELAY_SEC *
			(double)(1000 * 1000)));
		tx_old_fd_oh_bytes[i] = s_fd_desc[fd].tx_oh_bytes;
		tx_old_fd_usr_bytes[i] = s_fd_desc[fd].tx_usr_bytes;
		tx_old_fd_pkts[i] = s_fd_desc[fd].tx_pkts;

		RTE_LOG(INFO, pre_ld,
			"FD(%d) recv line: %.2fGbps, usr: %.2fGbps, %.2fMPPS\n",
			fd, (double)(s_fd_desc[fd].rx_oh_bytes -
			rx_old_fd_oh_bytes[i]) * 8 /
			(STATISTICS_DELAY_SEC *
			(double)(1000 * 1000 * 1000)),
			(double)(s_fd_desc[fd].rx_usr_bytes -
			rx_old_fd_usr_bytes[i]) * 8 /
			(STATISTICS_DELAY_SEC *
			(double)(1000 * 1000 * 1000)),
			(double)(s_fd_desc[fd].rx_pkts -
			rx_old_fd_pkts[i]) * 8 /
			(STATISTICS_DELAY_SEC *
			(double)(1000 * 1000)));
		rx_old_fd_oh_bytes[i] = s_fd_desc[fd].rx_oh_bytes;
		rx_old_fd_usr_bytes[i] = s_fd_desc[fd].rx_usr_bytes;
		rx_old_fd_pkts[i] = s_fd_desc[fd].rx_pkts;
	}

statistics_continue:
	sleep(STATISTICS_DELAY_SEC);
	if (s_pre_ld_quit)
		return arg;
	goto statistics_loop;

	return arg;
}

static int eal_main(void)
{
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid, dpaa2_rxqs = 0;
	uint16_t rxq_num[RTE_MAX_ETHPORTS];
	uint16_t txq_num[RTE_MAX_ETHPORTS];
	struct rte_eth_conf port_conf[RTE_MAX_ETHPORTS];
	struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];
	enum pre_ld_port_type port_type[RTE_MAX_ETHPORTS], type_ret;
	size_t i, eal_argc = 0;
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
		MEMPOOL_ELEM_SIZE, MEMPOOL_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (!s_pre_ld_rx_pool)
		rte_exit(EXIT_FAILURE, "Cannot init rx pool\n");

	if (getenv("TX_FROM_RX_POOL")) {
		s_tx_from_rx_pool = 1;
		RTE_LOG(INFO, pre_ld,
			"Using single pool for TX/RX\n");
	}

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		rte_memcpy(&port_conf[i], &s_port_conf,
			sizeof(s_port_conf));
		memset(&dev_info[i], 0, sizeof(struct rte_eth_dev_info));
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
			s_tx_port = ext_id;
			rxq_num[portid] = 1;
			txq_num[portid] = 1;
		} else if (port_type[portid] == UP_LINK_TYPE) {
			ul_id = portid;
			rxq_num[portid] = 1;
			txq_num[portid] = 1;
		} else if (port_type[portid] == DOWN_LINK_TYPE) {
			dl_id = portid;
			s_rx_port = dl_id;
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
		rte_log(RTE_LOG_INFO, RTE_LOGTYPE_pre_ld, "done.\n");
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
		fc_conf.mode = RTE_ETH_FC_NONE;
		ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
		if (ret) {
			RTE_LOG(WARNING, pre_ld,
				"Flow control set not support on port%d\n",
				portid);
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
			MAX_USR_FD_NUM, 0,
			RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (!s_port_rxq_rings[portid])
			rte_exit(EXIT_FAILURE, "create %s failed\n", ring_nm);

		for (i = 0; i < dev_info[portid].max_rx_queues; i++) {
			s_rxq_ids[portid][i] = i;
			ret = rte_ring_enqueue(s_port_rxq_rings[portid],
				&s_rxq_ids[portid][i]);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"eq s_rxq_ids[%d][%d] to %s failed\n",
					portid, (int)i, ring_nm);
				return ret;
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
				RTE_LOG(ERR, pre_ld,
					"eq s_txq_ids[%d][%d] to %s failed\n",
					portid, (int)i, ring_nm);
				return ret;
			}
		}
	}

	if (type_ret == DOWN_LINK_TYPE) {
		pre_ld_configure_split_traffic(dl_id);
	} else if (type_ret == ALL_TYPE) {
		s_dir_traffic_cfg.valid = 1;
		s_dir_traffic_cfg.ext_id = ext_id;
		s_dir_traffic_cfg.ul_id = ul_id;
		s_dir_traffic_cfg.dl_id = dl_id;
		s_dir_traffic_cfg.tap_id = tap_id;
		rte_memcpy(s_dir_traffic_cfg.rxq_nb,
			rxq_num, sizeof(uint16_t) * RTE_MAX_ETHPORTS);
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
	int ret;
	uint16_t rxq_id, offset = 0;
	struct pre_ld_lcore_conf *lcore;
	struct pre_ld_lcore_fwd *fwd;
	char nm[RTE_MEMZONE_NAMESIZE];
	static int default_created;
	char fwd_info[512];
	const char *prot_name;

	if (!s_fd_desc[sockfd].rxq_id)
		return -EIO;

	rxq_id = *s_fd_desc[sockfd].rxq_id;

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

	sprintf(config_str,
		"(%s, %s, %s)", s_uplink, s_downlink, prot_name);

	ret = rte_remote_direct_parse_config(config_str, 1);
	if (ret)
		return ret;
	ret = rte_remote_direct_traffic(RTE_REMOTE_DIR_REQ);
	if (ret)
		return ret;

	default_created = 1;

create_local_flow:

	ret = eal_create_local_flow(sockfd, s_fd_desc[sockfd].rx_port,
		pattern, rxq_id);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Port(%d) flow create failed(%d)\n",
			s_fd_desc[sockfd].rx_port, ret);

		return ret;
	}

	if (s_data_path_core < 0)
		return 0;

	lcore = &s_pre_ld_lcore[s_data_path_core];
	if (lcore->n_fwds >= MAX_RX_POLLS_PER_LCORE)
		return -EINVAL;

	sprintf(nm, "rx_ring_%d", sockfd);
	s_fd_desc[sockfd].rx_ring = rte_ring_create(nm, 2048,
			0, RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (!s_fd_desc[sockfd].rx_ring) {
		RTE_LOG(ERR, pre_ld,
			"ring %s created failed.\n", nm);
		return -ENOMEM;
	}

	pthread_mutex_lock(&s_lcore_mutex);
	fwd = &lcore->fwd[lcore->n_fwds];
	fwd->poll_type = RX_QUEUE;
	fwd->poll.poll_queue.port_id = s_fd_desc[sockfd].rx_port;
	fwd->poll.poll_queue.queue_id = rxq_id;
	offset += sprintf(&fwd_info[offset],
		"FWD[%d]: RX from port%d, queue%d ",
		lcore->n_fwds, fwd->poll.poll_queue.port_id,
		fwd->poll.poll_queue.queue_id);
	fwd->fwd_type = RX_RING;
	fwd->fwd_dest.rx_ring = s_fd_desc[sockfd].rx_ring;
	offset += sprintf(&fwd_info[offset],
		"then forward to rx ring(%s)\r\n",
		fwd->fwd_dest.rx_ring->name);
	rte_wmb();
	RTE_LOG(INFO, pre_ld, "%s", fwd_info);
	lcore->n_fwds++;
	pthread_mutex_unlock(&s_lcore_mutex);

	return 0;
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

static int
usr_socket_fd_desc_init(int sockfd,
	uint16_t rx_port, uint16_t tx_port)
{
	int ret = 0, found = 0;
	struct pre_ld_lcore_conf *lcore;
	struct pre_ld_lcore_fwd *fwd;
	struct pre_ld_poll_tx_ring *tx_rings;
	uint16_t n_fwds;
	char nm[64];

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
	if (s_fd_desc[sockfd].fd >= 0) {
		RTE_LOG(ERR, pre_ld,
			"Duplicated FD[%d](%d)?\n",
			sockfd, s_fd_desc[sockfd].fd);

		ret = -EEXIST;
		goto fd_init_quit;
	}

	socket_hdr_init(&s_fd_desc[sockfd].hdr);

	s_fd_desc[sockfd].rx_buffer.head = 0;
	s_fd_desc[sockfd].rx_buffer.tail = 0;
	s_fd_desc[sockfd].rx_buffer.rx_bufs = rte_malloc(NULL,
		sizeof(void *) * MAX_PKT_BURST * 2,
		RTE_CACHE_LINE_SIZE);
	if (!s_fd_desc[sockfd].rx_buffer.rx_bufs) {
		RTE_LOG(ERR, pre_ld,
			"port%d: RX pool init failed for socket(%d)\n",
			rx_port, sockfd);

		goto fd_init_quit;
	}
	s_fd_desc[sockfd].rx_buffer.max_num = MAX_PKT_BURST * 2;

	ret = rte_ring_dequeue(s_port_rxq_rings[rx_port],
		(void **)&s_fd_desc[sockfd].rxq_id);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"port%d: No RXQ available for socket(%d)\n",
			rx_port, sockfd);

		goto fd_init_quit;
	}
	RTE_LOG(INFO, pre_ld,
		"port%d: RXQ[%d] allocated for socket(%d)\n",
		tx_port, *s_fd_desc[sockfd].rxq_id, sockfd);

	if (!s_dir_traffic_cfg.valid) {
		ret = rte_ring_dequeue(s_port_txq_rings[tx_port],
				(void **)&s_fd_desc[sockfd].txq_id);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"port%d: No TXQ available for socket(%d)\n",
				tx_port, sockfd);

			goto fd_init_quit;
		}
		RTE_LOG(INFO, pre_ld,
			"port%d: TXQ[%d] allocated for socket(%d)\n",
			tx_port, *s_fd_desc[sockfd].txq_id, sockfd);
	} else {
		s_fd_desc[sockfd].txq_id = NULL;
	}

	s_fd_desc[sockfd].rx_port = rx_port;
	s_fd_desc[sockfd].tx_port = tx_port;

	s_fd_desc[sockfd].hdr_init = HDR_INIT_NONE;

	s_fd_usr[s_usr_fd_num] = sockfd;
	s_usr_fd_num++;
	if (s_max_usr_fd < 0)
		s_max_usr_fd = sockfd;
	else if (sockfd > s_max_usr_fd)
		s_max_usr_fd = sockfd;

	s_fd_desc[sockfd].fd = sockfd;
	s_fd_desc[sockfd].cpu = -1;
	sprintf(nm, "tx_pool_fd%d", sockfd);
	s_fd_desc[sockfd].tx_pool = rte_pktmbuf_pool_create_by_ops(nm,
			MEMPOOL_ELEM_SIZE, MEMPOOL_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id(),
			RTE_MBUF_DEFAULT_MEMPOOL_OPS);
	if (!s_fd_desc[sockfd].tx_pool) {
		ret = -ENOMEM;
		RTE_LOG(ERR, pre_ld, "Create %s failed\n", nm);
	}

fd_init_quit:
	if (ret) {
		if (s_fd_desc[sockfd].rxq_id) {
			rte_ring_enqueue(s_port_rxq_rings[tx_port],
				s_fd_desc[sockfd].rxq_id);
			s_fd_desc[sockfd].rxq_id = NULL;
		}
		if (s_fd_desc[sockfd].txq_id) {
			rte_ring_enqueue(s_port_txq_rings[tx_port],
				s_fd_desc[sockfd].txq_id);
			s_fd_desc[sockfd].txq_id = NULL;
		}
	}
	pthread_mutex_unlock(&s_fd_mutex);

	if (ret)
		return ret;

	if (!s_dir_traffic_cfg.valid)
		return 0;

	lcore = &s_pre_ld_lcore[s_data_path_core];
	if (lcore->n_fwds >= MAX_RX_POLLS_PER_LCORE)
		return -EINVAL;

	sprintf(nm, "tx_ring_fd%d", sockfd);
	s_fd_desc[sockfd].tx_ring = rte_ring_create(nm,
			2048, 0, RING_F_SP_ENQ | RING_F_SC_DEQ);

	pthread_mutex_lock(&s_lcore_mutex);
	fwd = NULL;
	for (n_fwds = 0; n_fwds < lcore->n_fwds; n_fwds++) {
		fwd = &lcore->fwd[n_fwds];
		if (fwd->poll_type == TX_RING &&
			fwd->fwd_type == HW_PORT &&
			fwd->fwd_dest.fwd_port == tx_port) {
			found = 1;
			break;
		}
	}
	if (!found) {
		fwd = &lcore->fwd[lcore->n_fwds];
		fwd->poll.tx_rings.tx_ring = rte_malloc(NULL,
			sizeof(void *) * MAX_USR_FD_NUM, 0);
		if (!fwd->poll.tx_rings.tx_ring) {
			RTE_LOG(ERR, pre_ld,
				"Alloc tx rings failed\n");
			goto fwd_configure_quit;
		}
		fwd->poll_type = TX_RING;
		fwd->poll.tx_rings.tx_ring[0] = s_fd_desc[sockfd].tx_ring;
		fwd->fwd_type = HW_PORT;
		fwd->fwd_dest.fwd_port = s_fd_desc[sockfd].tx_port;
		rte_wmb();
		fwd->poll.tx_rings.tx_ring_num = 1;
		rte_wmb();
		lcore->n_fwds++;
	} else {
		tx_rings = &fwd->poll.tx_rings;
		tx_rings->tx_ring[tx_rings->tx_ring_num] =
			s_fd_desc[sockfd].tx_ring;
		rte_wmb();
		tx_rings->tx_ring_num++;
	}

fwd_configure_quit:
	pthread_mutex_unlock(&s_lcore_mutex);

	return 0;
}

static int
usr_socket_fd_release(int sockfd)
{
	int ret = 0, ret_tmp, i;
	uint16_t rx_port, tx_port;

	pthread_mutex_lock(&s_fd_mutex);
	rx_port = s_fd_desc[sockfd].rx_port;
	tx_port = s_fd_desc[sockfd].tx_port;

	if (s_fd_desc[sockfd].rxq_id &&
		s_port_rxq_rings[rx_port]) {
		ret_tmp = rte_ring_enqueue(s_port_rxq_rings[rx_port],
					s_fd_desc[sockfd].rxq_id);
		if (ret_tmp) {
			RTE_LOG(ERR, pre_ld,
				"%s release *s_fd_desc[%d].rxq_id(%d) failed(%d)\n",
				__func__, sockfd,
				*s_fd_desc[sockfd].rxq_id, ret_tmp);
			ret = ret_tmp;
		}
	}
	s_fd_desc[sockfd].rxq_id = NULL;

	if (s_fd_desc[sockfd].txq_id &&
		s_port_txq_rings[tx_port]) {
		ret_tmp = rte_ring_enqueue(s_port_txq_rings[tx_port],
					s_fd_desc[sockfd].txq_id);
		if (ret_tmp) {
			RTE_LOG(ERR, pre_ld,
				"%s release *s_fd_desc[%d].txq_id(%d) failed(%d)\n",
				__func__, sockfd,
				*s_fd_desc[sockfd].txq_id, ret_tmp);
			ret = ret_tmp;
		}
	}
	s_fd_desc[sockfd].txq_id = NULL;

	if (s_fd_desc[sockfd].flow) {
		ret_tmp = rte_flow_destroy(rx_port,
				s_fd_desc[sockfd].flow, NULL);
		if (ret_tmp) {
			RTE_LOG(ERR, pre_ld,
				"%s free s_fd_desc[%d].flow(%p) failed(%d)\n",
				__func__, sockfd,
				s_fd_desc[sockfd].flow, ret_tmp);
			ret = ret_tmp;
		}
		s_fd_desc[sockfd].flow = NULL;
	}
	memset(&s_fd_desc[sockfd], 0, sizeof(struct fd_desc));
	s_fd_desc[sockfd].fd = INVALID_SOCKFD;

	for (i = 0; i < s_usr_fd_num; i++) {
		if (s_fd_usr[i] == sockfd &&
			i != (s_usr_fd_num - 1)) {
			memmove(&s_fd_usr[i], &s_fd_usr[i + 1],
				sizeof(int) * (s_usr_fd_num - (i + 1)));
			break;
		} else if (s_fd_usr[i] == sockfd) {
			break;
		}
	}
	s_usr_fd_num--;
	if (s_max_usr_fd == sockfd) {
		s_max_usr_fd = INVALID_SOCKFD;
		for (i = 0; i < s_usr_fd_num; i++) {
			if (s_fd_usr[i] > s_max_usr_fd)
				s_max_usr_fd = s_fd_usr[i];
		}
	}
	pthread_mutex_unlock(&s_fd_mutex);

	return ret;
}

static void
dump_usr_fd(const char *s)
{
	char dump_str[4096];
	int i, off = 0;

	if (!s_usr_fd_num)
		return;

	for (i = 0; i < s_usr_fd_num; i++) {
		if (i != (s_usr_fd_num - 1)) {
			off += sprintf(&dump_str[off],
				"%d, ", s_fd_usr[i]);
		} else {
			off += sprintf(&dump_str[off],
				"%d", s_fd_usr[i]);
		}
	}
	RTE_LOG(INFO, pre_ld,
		"%s: total %d usr FD(s)(MAX=%d): %s\n",
		s, s_usr_fd_num, s_max_usr_fd, dump_str);
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
		ret = eal_init(domain, type);
		if (ret > 0 && (type & SOCK_TYPE_MASK) == SOCK_DGRAM) {
			ret = usr_socket_fd_desc_init(sockfd,
					s_rx_port, s_tx_port);
			if (ret < 0) {
				RTE_LOG(ERR, pre_ld,
					"Init FD desc failed(%d)\n", ret);
				exit(EXIT_FAILURE);
			}
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
		ret = eal_init(domain, type);
		if (ret > 0 && (type & SOCK_TYPE_MASK) == SOCK_DGRAM) {
			ret = usr_socket_fd_desc_init(sockfd,
					s_rx_port, s_tx_port);
			if (ret < 0) {
				RTE_LOG(ERR, pre_ld,
					"Init FD desc failed(%d)\n", ret);
				exit(EXIT_FAILURE);
			}
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

	if (IS_USECT_SOCKET(sockfd)) {
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

	if (IS_USECT_SOCKET(sockfd)) {
		RTE_LOG(INFO, pre_ld,
			"%s socket fd:%d, libc_close:%p\n", __func__,
			sockfd, libc_close);
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
	int ret, offset = 0, i, arp_s, close_ret;
	struct arpreq arpreq;
	char mac_addr[64];
	uint8_t addr_bytes[RTE_ETHER_ADDR_LEN];
	struct sockaddr_in ia;
	struct eth_ipv4_udp_hdr *hdr = &s_fd_desc[sockfd].hdr;

	if ((s_fd_desc[sockfd].hdr_init &
		(REMOTE_IP_INIT | REMOTE_UDP_INIT)) !=
		(REMOTE_IP_INIT | REMOTE_UDP_INIT)) {
		RTE_LOG(ERR, pre_ld,
			"%s: fd:%d, remote IP/UDP not initialized.\n",
			__func__, sockfd);
			return -EINVAL;
	}
	ia.sin_family = AF_INET;
	ia.sin_addr.s_addr = hdr->ip_hdr.dst_addr;
	ia.sin_port = hdr->udp_hdr.dst_port;

	memset(&arpreq, 0, sizeof(struct arpreq));
	memcpy(&arpreq.arp_pa, &ia, sizeof(struct sockaddr_in));
	strcpy(arpreq.arp_dev, s_slow_if);
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
	ret = ioctl(arp_s, SIOCGARP, &arpreq);
	if (ret) {
		RTE_LOG(INFO, pre_ld,
			"%s: Get arp table by socket(%d) failed(%d)\n",
			__func__, arp_s, ret);

		goto close_arp_socket;
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
		"%s: socket fd:%d, Remote Mac: %s\n",
		__func__, sockfd, mac_addr);

	s_fd_desc[sockfd].hdr_init |= REMOTE_ETH_INIT;

close_arp_socket:
	close_ret = (*libc_close)(arp_s);
	if (close_ret) {
		RTE_LOG(INFO, pre_ld,
			"%s: close arp socket(%d) failed(%d)\n",
			__func__, arp_s, close_ret);
	}

	return 0;
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

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, s_slow_if);

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
	int connect_value = 0, ret;
	const struct sockaddr_in *sa = (const void *)addr;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, libc_connect:%p\n",
			__func__, sockfd, libc_connect);
		dump_usr_fd(__func__);
	}

	if (IS_USECT_SOCKET(sockfd)) {
		RTE_LOG(INFO, pre_ld,
			"%s socket fd:%d with family(%d), len(%d)\n",
			__func__, sockfd, sa->sin_family, addrlen);
		if (sa->sin_family != AF_INET &&
			sa->sin_family != AF_INET6) {
			RTE_LOG(ERR, pre_ld,
				"%s: fd:%d, Invalid family(%d)\n",
				__func__, sockfd, sa->sin_family);
			return -EINVAL;
		}
		if (unlikely(!libc_connect)) {
			LIBC_FUNCTION(connect);
			if (!libc_connect)
				rte_panic("Get libc %s failed!\n", __func__);
		}
		connect_value = (*libc_connect)(sockfd, addr, addrlen);
		if (connect_value) {
			RTE_LOG(ERR, pre_ld,
				"User socket(%d) get connection failed(%d)\n",
				sockfd, connect_value);

			return connect_value;
		}

		ret = netwrap_collect_info(sockfd);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s fd:%d, collect info failed(%d)\n",
				__func__, sockfd, ret);
		}

		return socket_create_ingress_flow(sockfd);
	} else if (libc_connect) {
		connect_value = (*libc_connect)(sockfd, addr, addrlen);
	} else {
		LIBC_FUNCTION(connect);

		if (libc_connect)
			connect_value = (*libc_connect)(sockfd, addr, addrlen);
		else {
			connect_value = -EACCES;
			errno = EACCES;
		}
	}

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

	if (IS_USECT_SOCKET(sockfd)) {
		if (s_fd_desc[sockfd].flow)
			return eal_recv(sockfd, buf, len, 0);
	}

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

	if (IS_USECT_SOCKET(sockfd)) {
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

	if (likely(IS_USECT_SOCKET(sockfd))) {
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

	if (IS_USECT_SOCKET(sockfd)) {
		if (s_fd_desc[sockfd].flow)
			return eal_recv(sockfd, buf, len, flags);
	}

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

	if (IS_USECT_SOCKET(sockfd)) {
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

	if (likely(IS_USECT_SOCKET(sockfd))) {
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

static int usr_fd_set_num(const fd_set *fds,
	int nfds, int fd_set[], int check_flow)
{
	int i, num = 0;

	for (i = 0; i < nfds; i++) {
		if (FD_ISSET(s_fd_usr[i], fds)) {
			if (check_flow && s_fd_desc[s_fd_usr[i]].flow) {
				fd_set[num] = s_fd_usr[i];
				num++;
			} else if (!check_flow) {
				fd_set[num] = s_fd_usr[i];
				num++;
			}
		}
	}

	return num;
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
	int select_value = 0, usr_fd_num, sys_fd_num = 0;
	int ret, i, j, off;
	fd_set usr_readfds;
	fd_set sys_readfds;
	uint8_t *_usr, *_sys;
	const uint8_t *_fds;
	char usr_fd_buf[128];
	char sys_fd_buf[128];
	char sel_fd_buf[128];
	int usr_fd[s_max_usr_fd];
	int sys_fd[sizeof(fd_set) * 8];

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: nfds:%d, libc_select:%p\n",
			__func__, nfds, libc_select);
		dump_usr_fd(__func__);
	}

	if (s_max_usr_fd >= 0 && readfds) {
		if (unlikely(!libc_select)) {
			LIBC_FUNCTION(select);
			if (!libc_select) {
				select_value = -1;
				errno = EACCES;

				return select_value;
			}
		}

		usr_fd_num = usr_fd_set_num(readfds, nfds, usr_fd, 1);
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
	eal_quit();
	if (s_fd_desc)
		free(s_fd_desc);
	s_fd_desc = NULL;
}

__attribute__((constructor(65535))) static void setup_wrappers(void)
{
	char *env;
	int i;

	s_uplink = getenv("uplink_name");
	s_eal_file_prefix = getenv("file_prefix");
	s_slow_if = getenv("eth_name");
	if (!s_slow_if) {
		rte_exit(EXIT_FAILURE,
			"slow interface(kernel) not specified!\n");
	}

	if (getenv("PRE_LOAD_WRAP_LOG"))
		s_socket_dbg = 1;

	if (getenv("PRE_LOAD_STATISTIC_PRINT"))
		s_statistic_print = 1;

	env = getenv("PRE_LOAD_WRAP_CPU_START");
	if (env)
		s_cpu_start = atoi(env);

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
	for (i = 0; i < MAX_USR_FD_NUM; i++) {
		s_fd_desc[i].fd = INVALID_SOCKFD;
		s_fd_desc[i].rxq_id = NULL;
		s_fd_desc[i].txq_id = NULL;
		s_fd_desc[i].flow = NULL;
	}

	if (!getenv("PRE_LOAD_WAPPERS"))
		return;

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
}
