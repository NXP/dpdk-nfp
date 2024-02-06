/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

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
#include <rte_pmd_dpaa2.h>
#include <nxp/rte_remote_direct_flow.h>

#include "netwrap.h"

#define INVALID_SOCKFD (-1)
static int s_socket_pre_set;
static int s_eal_inited;
static int s_usect_sockfd = INVALID_SOCKFD;

static const char *s_dpdmux_ep_name;
static int s_dpdmux_id;
static int s_dpdmux_ep_id;

static char *s_eal_params;
static const char *s_uplink;
static const char *s_slow_if;
static const char *s_downlink;

static struct packet_info pinfo = {0};

static int (*libc_socket)(int, int, int);
static int (*libc_shutdown)(int, int);
static int (*libc_close)(int);
static int (*libc_bind)(int, const struct sockaddr *, socklen_t);
static int (*libc_accept)(int, struct sockaddr *, socklen_t *);
static int (*libc_connect)(int, const struct sockaddr *, socklen_t);
static int (*libc_getsockname)(int, struct sockaddr *, socklen_t *);
static int (*libc_getpeername)(int, struct sockaddr *, socklen_t *);
static ssize_t (*libc_read)(int, void *, size_t);
static ssize_t (*libc_write)(int, const void *, size_t);
static ssize_t (*libc_recv)(int, void *, size_t, int);
static ssize_t (*libc_send)(int, const void *, size_t, int);
static int (*libc_ioctl)(int, unsigned long, ...);
static int (*libc_select)(int, fd_set *, fd_set *, fd_set *,
	struct timeval *);

static int s_socket_dbg;

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define MEMPOOL_ELEM_SIZE 8192

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

static struct rte_eth_dev_tx_buffer *pre_tx_buf[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.rxmode = {0},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

struct rte_mempool *s_pre_ld_pktmbuf_pool;

/* Per-port statistics struct */
struct pre_ld_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct pre_ld_port_statistics s_pre_ld_stat[RTE_MAX_ETHPORTS];

#define IP_DEFTTL       64
#define IP_VERSION      0x40
#define IP_HDRLEN       0x05
#define IP_VHL_DEF      (IP_VERSION | IP_HDRLEN)

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

static void eal_quit(void)
{
	uint16_t portid;
	int ret;

	RTE_ETH_FOREACH_DEV(portid) {
		RTE_LOG(INFO, pre_ld, "Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"rte_eth_dev_stop: err=%d, port=%d\n",
				ret, portid);
		}
		rte_eth_dev_close(portid);
		RTE_LOG(INFO, pre_ld, " Done\n");
	}

	/* clean up the EAL */
	rte_eal_cleanup();
	RTE_LOG(INFO, pre_ld, "Bye...\n");
	exit(0);
}

static int
eal_recv(int sockfd, void *buf, size_t len, int flags)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint32_t portid, nb_rx, i, total_bytes = 0;
	size_t length, offset;
	char *pkt, *pdata;
	struct rte_udp_hdr *udp_hdr;

	RTE_SET_USED(sockfd);
	RTE_SET_USED(flags);
	portid = 0;

	/* Workaround for rte_lcore_id return -1 due to changed pid. */
	RTE_PER_LCORE(_lcore_id) = 0;

	offset = sizeof(struct rte_ether_hdr) +
		sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
	nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);
	for (i = 0, pdata = buf, total_bytes = 0; i < nb_rx; i++) {
		pkt = rte_pktmbuf_mtod(pkts_burst[i], char *);
		udp_hdr = (struct rte_udp_hdr *)(pkt
			+ sizeof(struct rte_ether_hdr)
			+ sizeof(struct rte_ipv4_hdr));
		length = rte_be_to_cpu_16(udp_hdr->dgram_len)
				- sizeof(struct rte_udp_hdr);

		if (len >= length) {
			rte_memcpy(pdata, pkt + offset, length);
			pdata += length;
			len -= length;
			total_bytes += length;
		}
		s_pre_ld_stat[portid].rx++;

		/* rte_pktmbuf_free(pkts_burst[i]); */
	}
	rte_pktmbuf_free_bulk(pkts_burst, nb_rx);

	return total_bytes;
}

static int
eal_send(int sockfd, const void *buf, size_t len, int flags)
{
	struct rte_mbuf *m;
	int sent, cnt;
	unsigned int portid = 0;
	void *udp_data;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_udp_hdr *udp_hdr;

	RTE_SET_USED(sockfd);
	RTE_SET_USED(flags);

#define ALLOC_RETRY_COUNT 10
	for (cnt = 0; cnt < ALLOC_RETRY_COUNT; cnt++) {
		m = rte_pktmbuf_alloc(s_pre_ld_pktmbuf_pool);
		if (m)
			break;
	}
	if (cnt == ALLOC_RETRY_COUNT) {
		RTE_LOG(ERR, pre_ld,
			"Sendto failed to allocate mbuf, cnt=%d\n", cnt);
		return -1;
	}

	/* Initialize the Ethernet header */
	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	memcpy(eth_hdr->src_addr.addr_bytes, pinfo.src_mac,
		sizeof(pinfo.src_mac));
	memcpy(eth_hdr->dst_addr.addr_bytes, pinfo.dst_mac,
		sizeof(pinfo.dst_mac));
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	/* Initialize the IP header*/
	ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	memset(ip_hdr, 0, sizeof(*ip_hdr));
	ip_hdr->version_ihl = IP_VHL_DEF;
	ip_hdr->type_of_service = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->src_addr = pinfo.src_ip;
	ip_hdr->dst_addr = pinfo.dst_ip;
	ip_hdr->total_length = rte_cpu_to_be_16(
			len + sizeof(*ip_hdr) + sizeof(*udp_hdr));
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

	/* Initialize the UDP header */
	udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
	udp_hdr->src_port = pinfo.src_port;
	udp_hdr->dst_port = pinfo.dst_port;
	/* UDP checksum is optional */
	udp_hdr->dgram_cksum = 0;
	udp_hdr->dgram_len = rte_cpu_to_be_16(len + sizeof(*udp_hdr));

	udp_data = (void *)(udp_hdr + 1);
	rte_memcpy(udp_data, buf, len);
	m->data_off = RTE_PKTMBUF_HEADROOM;
	m->nb_segs = 1;
	m->next = NULL;
	m->data_len = len + sizeof(*eth_hdr) +
		sizeof(*ip_hdr) + sizeof(*udp_hdr);
	if (m->data_len < 60)
		m->data_len = 60;
	m->pkt_len = m->data_len;

	sent = rte_eth_tx_burst(portid, 0, &m, 1);
	if (likely(sent == 1)) {
		s_pre_ld_stat[portid].tx++;
		return len;
	}

	rte_pktmbuf_free(m);
	return -1;
}

#define MAX_ARGV_NUM 32

static int main_ctor(void)
{
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid;
	size_t i, eal_argc;
	char *eal_argv[MAX_ARGV_NUM];
	const char *ep_name;

	RTE_LOG(INFO, pre_ld, "%s: Start!\n", __func__);

	for (i = 0, eal_argc = 1; i < strlen(s_eal_params); ++i) {
		if (isspace(s_eal_params[i]))
			++eal_argc;
	}

	if (eal_argc >= MAX_ARGV_NUM) {
		RTE_LOG(INFO, pre_ld, "Too many args(%ld)\n", eal_argc);

		exit(EXIT_FAILURE);
	}

	eal_argc = rte_strsplit(s_eal_params, strlen(s_eal_params),
				eal_argv, eal_argc, ' ');

	for (i = 0; i < eal_argc; ++i)
		RTE_LOG(INFO, pre_ld, "arg[%ld]: %s\n", i, eal_argv[i]);

	/* init EAL */
	ret = rte_eal_init(eal_argc, eal_argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	nb_ports = rte_eth_dev_count_avail();
	if (!nb_ports)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	RTE_LOG(INFO, pre_ld, "%d Ethernet ports found.", nb_ports);

	/* create the mbuf pool */
	s_pre_ld_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
		MEMPOOL_ELEM_SIZE, MEMPOOL_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (!s_pre_ld_pktmbuf_pool)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		nb_ports_available++;

		/* init port */
		RTE_LOG(INFO, pre_ld,
			"Initializing port %u... ", portid);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));
		}

		if (dev_info.tx_offload_capa &
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
			local_port_conf.txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		}
		ret = rte_eth_dev_configure(portid, 1, 1,
			&local_port_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Cannot configure device: err=%d, port=%u\n",
				ret, portid);
		}

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
				&nb_txd);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				 "Adjust descriptors: err=%d, port=%u\n",
				 ret, portid);
		}

		/* init one RX queue */
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
				rte_eth_dev_socket_id(portid),
				&rxq_conf,
				s_pre_ld_pktmbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"rte_eth_rx_queue_setup:err=%d, port=%u\n",
				ret, portid);
		}

		/* init one TX queue on each port */
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);
		}

		/* Initialize TX buffers */
		pre_tx_buf[portid] = rte_zmalloc_socket("pre_tx_buf",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (!pre_tx_buf[portid]) {
			rte_exit(EXIT_FAILURE,
				"Cannot allocate buffer for tx on port %u\n",
				portid);
		}

		rte_eth_tx_buffer_init(pre_tx_buf[portid], 1);

		ret = rte_eth_tx_buffer_set_err_callback(pre_tx_buf[portid],
				rte_eth_tx_buffer_count_callback,
				&s_pre_ld_stat[portid].dropped);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Set error callback for tx buffer on port %u\n",
				 portid);
		}

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL,
					     0);
		if (ret < 0) {
			RTE_LOG(ERR, pre_ld,
				"Port %u, Failed to disable Ptype parsing\n",
				portid);
		}
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start:err=%d, port=%u\n",
				ret, portid);
		}

		RTE_LOG(INFO, pre_ld, "done:\n");

		ret = rte_eth_promiscuous_enable(portid);
		if (ret) {
			rte_exit(EXIT_FAILURE,
				 "rte_eth_promiscuous_enable:err=%s, port=%u\n",
				 rte_strerror(-ret), portid);
		}

		/* initialize port stats */
		memset(&s_pre_ld_stat, 0, sizeof(s_pre_ld_stat));

		ep_name = rte_pmd_dpaa2_ep_name(portid);
		if (ep_name) {
			int id = -1, ep_id = -1;

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

				continue;
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
				RTE_LOG(WARNING, pre_ld,
					"%s <-> %s is hijacked.\n",
					s_uplink, s_downlink);
			}
		}
	}

	if (!s_downlink && !s_dpdmux_ep_name) {
		rte_exit(EXIT_FAILURE,
			"No split port specified!\n");
	}
	if (s_downlink && s_dpdmux_ep_name) {
		RTE_LOG(WARNING, pre_ld,
			"Chose %s to split than %s\n",
			s_dpdmux_ep_name, s_downlink);
		s_downlink = NULL;
	}

	if (!nb_ports_available)
		rte_exit(EXIT_FAILURE, "no port available\n");

	return 0;
}

static int
eal_create_dpaa2_mux_flow(int dpdmux_id,
	int dpdmux_ep_id, const char *prot,
	const char *field, uint64_t key)
{
	int ret;
	uint16_t key_16;
	uint32_t key_32;
	struct rte_flow_item pattern[2];
	struct rte_flow_action actions[1];
	struct rte_flow_action_vf vf;

	struct rte_flow_item_udp udp_item;
	struct rte_flow_item_gtp gtp_item;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item_gtp gtp_mask;

	memset(pattern, 0, sizeof(pattern));
	memset(actions, 0, sizeof(actions));
	memset(&vf, 0, sizeof(vf));
	memset(&udp_item, 0, sizeof(udp_item));
	memset(&gtp_item, 0, sizeof(gtp_item));
	memset(&udp_mask, 0, sizeof(udp_mask));
	memset(&gtp_mask, 0, sizeof(gtp_mask));

	vf.id = dpdmux_ep_id;

	if (prot && !strcmp(prot, "udp")) {
		pattern[0].type = RTE_FLOW_ITEM_TYPE_UDP;
		if (field && !strcmp(field, "dst")) {
			pattern[0].spec = &udp_item;
			pattern[0].mask = &udp_mask;
			key_16 = key;
			udp_item.hdr.dst_port =
				rte_cpu_to_be_16(key_16);
			udp_mask.hdr.dst_port = 0xffff;
		} else if (field) {
			RTE_LOG(WARNING, pre_ld,
				"MUX UDP field(%s) not support\n",
				field);
			return -ENOTSUP;
		}
	} else if (prot && !strcmp(prot, "gtp")) {
		pattern[0].type = RTE_FLOW_ITEM_TYPE_GTP;
		if (field && strcmp(field, "teid")) {
			pattern[0].spec = &gtp_item;
			pattern[0].mask = &gtp_mask;
			key_32 = key;
			gtp_item.teid =
				rte_cpu_to_be_32(key_32);
			gtp_mask.teid = 0xffffffff;
		} else if (field) {
			RTE_LOG(WARNING, pre_ld,
				"MUX GTP field(%s) not support\n",
				field);
			return -ENOTSUP;
		}
	} else if (prot && !strcmp(prot, "eth")) {
		pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
		/**To DO.*/
		if (field) {
			RTE_LOG(WARNING, pre_ld,
				"MUX ETH field(%s) not support\n",
				field);
			return -ENOTSUP;
		}
	} else if (prot && !strcmp(prot, "ecpri")) {
		pattern[0].type = RTE_FLOW_ITEM_TYPE_ECPRI;
		/**To DO.*/
		if (field) {
			RTE_LOG(WARNING, pre_ld,
				"MUX eCPRI field(%s) not support\n",
				field);
			return -ENOTSUP;
		}
	} else if (prot) {
		RTE_LOG(WARNING, pre_ld,
			"MUX protocol(%s) not support\n", prot);
		return -ENOTSUP;
	} else {
		RTE_LOG(WARNING, pre_ld,
			"MUX NO protocol specified\n");
		return -ENOTSUP;
	}

	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	actions[0].type = RTE_FLOW_ACTION_TYPE_VF;
	actions[0].conf = &vf;

	ret = rte_pmd_dpaa2_mux_flow_create(dpdmux_id,
			pattern, actions);
	if (ret < 0) {
		RTE_LOG(ERR, pre_ld,
			"%s: MUX flow create failed(%d)\n",
			__func__, ret);
	}

	return ret >= 0 ? 0 : ret;
}

static int
eal_create_flow(const char *prot,
	const char *field, uint64_t key)
{
	char config_str[256];
	int ret;
	static int created;

	if (created) {
		RTE_LOG(WARNING, pre_ld,
			"Split traffic flow created!\n");

		return 0;
	}

	if (s_dpdmux_ep_name) {
		return eal_create_dpaa2_mux_flow(s_dpdmux_id,
				s_dpdmux_ep_id, prot, field, key);
	}

	if (!s_uplink) {
		RTE_LOG(ERR, pre_ld,
			"No uplink interface specified!\n");

		return -EINVAL;
	}
	if (!s_downlink) {
		RTE_LOG(ERR, pre_ld,
			"No downlink interface detected!\n");

		return -EINVAL;
	}

	sprintf(config_str,
		"(%s, %s, %s, %s, 0x%lx)",
		s_uplink, s_downlink, prot, field, key);

	ret = rte_remote_direct_parse_config(config_str, 1);
	if (ret)
		return ret;
	ret = rte_remote_direct_traffic(RTE_REMOTE_DIR_REQ);
	if (!ret)
		created = 1;

	return ret;
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
			"%s starts: wrappers:%d, libc_socket:%p, s_usect_sockfd:%d\n",
			__func__, s_socket_pre_set,
			libc_socket, s_usect_sockfd);
	}

	if (s_socket_pre_set) {
		if (unlikely(!libc_socket)) {
			rte_panic("line %d\tassert \"%s\" failed\n",
				__LINE__, __func__);
		}
		if (!((domain == AF_INET) && (type == SOCK_DGRAM))) {
			sockfd = (*libc_socket)(domain, type, protocol);
			RTE_LOG(INFO, pre_ld,
				"libc_socket domain = 0x%x, type = 0x%x, proto = 0x%04x, sockfd = %d\n",
				domain, type, ntohs(protocol), sockfd);
		} else {
			RTE_LOG(INFO, pre_ld,
				"%s: pre set eal domain = 0x%x, type = 0x%x, proto = 0x%04x, sockfd = %d\n",
				__func__, domain, type,
				ntohs(protocol), sockfd);
			RTE_LOG(INFO, pre_ld,
				"%s: pre set eal s_eal_inited = %d, s_usect_sockfd:%d\n",
				__func__, s_eal_inited, s_usect_sockfd);
			if (!s_eal_inited) {
				ret = main_ctor();
				if (!ret)
					s_eal_inited = 1;
			}
			if (s_usect_sockfd < 0) {
				sockfd = (*libc_socket)(domain, type, protocol);
				s_usect_sockfd = sockfd;
			} else {
				RTE_LOG(ERR, pre_ld,
					"Single Socket support only\n");
				exit(EXIT_FAILURE);
			}
			RTE_LOG(INFO, pre_ld,
				"Socket domain = 0x%x, type = 0x%x, proto = 0x%04x, sockfd = %d\n",
				domain, type, ntohs(protocol), s_usect_sockfd);
		}
	} else { /* pre init*/
		LIBC_FUNCTION(socket);

		RTE_LOG(INFO, pre_ld,
			"libc_socket(%p) domain(0x%x), type(0x%x), proto(0x%04x), sockfd(%d)\n",
			libc_socket, domain, type, ntohs(protocol), sockfd);

		if (libc_socket) {
			sockfd = (*libc_socket)(domain, type, protocol);
			RTE_LOG(INFO, pre_ld,
				"%s: domain = 0x%x, type = 0x%x, proto = 0x%04x, sockfd = %d\n",
				__func__, domain, type,
				ntohs(protocol), sockfd);
			RTE_LOG(INFO, pre_ld,
				"%s: s_eal_inited = %d, s_usect_sockfd:%d\n",
				__func__, s_eal_inited, s_usect_sockfd);
			if (domain == AF_INET && type == SOCK_DGRAM) {
				if (!s_eal_inited) {
					ret = main_ctor();
					if (!ret) {
						s_eal_inited = 1;
					} else {
						RTE_LOG(ERR, pre_ld,
							"eal constructor failed(%d)\n",
							ret);
						exit(EXIT_FAILURE);
					}
				}
				s_usect_sockfd = sockfd;
			}
		} else {
			sockfd = INVALID_SOCKFD;
			RTE_LOG(ERR, pre_ld,
				"%s: libc not exist!\n", __func__);
			exit(EXIT_FAILURE);
			errno = EACCES;
		}
	}

	return sockfd;
}

int
shutdown(int sockfd, int how)
{
	int shutdown_value = 0;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, s_usect_sockfd:%d, libc_shutdown:%p\n",
			__func__, sockfd, s_usect_sockfd, libc_shutdown);
		RTE_LOG(INFO, pre_ld,
			"%s starts: wrappers:%d, libc_socket:%p, s_usect_sockfd:%d\n",
			__func__, s_socket_pre_set,
			libc_socket, s_usect_sockfd);
	}

	if (IS_USECT_SOCKET(sockfd)) {
		if (libc_shutdown)
			shutdown_value = (*libc_shutdown)(sockfd, how);
		s_usect_sockfd = INVALID_SOCKFD;
		RTE_LOG(INFO, pre_ld,
			"%s socket fd:%d\n", __func__, sockfd);
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
	int close_value = 0;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, s_usect_sockfd:%d, libc_close:%p\n",
			__func__, sockfd, s_usect_sockfd, libc_close);
	}

	if (IS_USECT_SOCKET(sockfd)) {
		RTE_LOG(INFO, pre_ld,
			"%s socket fd:%d\n", __func__, sockfd);
		if (libc_close)
			close_value = (*libc_close)(sockfd);
		s_usect_sockfd = INVALID_SOCKFD;
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

static int
netwrap_get_local_ip(int sockfd)
{
	struct sockaddr_in ia;
	socklen_t addrlen;
	int ret, cnt = 0;
	uint8_t ipaddr[64];
	char ipaddr_str[64];

	if (!libc_getsockname) {
		LIBC_FUNCTION(getsockname);
		if (!libc_getsockname) {
			RTE_LOG(ERR, pre_ld,
				"libc_getsockname is NULL\n");
			return -ENOTSUP;
		}
	}

	cnt = 0;
	ia.sin_family = AF_INET;
	ia.sin_addr.s_addr = htonl(INADDR_ANY);
	ia.sin_port = 0;
	addrlen = sizeof(ia);

#define RETRY_COUNT 5
	for (cnt = 0; cnt < RETRY_COUNT; cnt++) {
		ret = (*libc_getsockname)(sockfd,
			(struct sockaddr *)(&ia), &addrlen);
		if (!ret)
			break;
	}
	if (cnt == RETRY_COUNT) {
		RTE_LOG(ERR, pre_ld,
			"%s: failed(%d) to get socket name by fd(%d)\n",
			__func__, ret, sockfd);
		return -ENOTSUP;
	}

	if (ia.sin_family == AF_INET) {
		ret = convert_ip_addr_to_str(ipaddr_str,
			&ia.sin_addr.s_addr, 4);
		if (ret)
			return ret;

		RTE_LOG(INFO, pre_ld,
			"%s fd:%d, local family=%d, port=%x, IP addr=%s\n",
			__func__, sockfd, ia.sin_family,
			ntohs(ia.sin_port), ipaddr_str);
		pinfo.src_ip = ia.sin_addr.s_addr;
		pinfo.src_port = ia.sin_port;
	} else {
		RTE_LOG(ERR, pre_ld,
			"%s: fd:%d, Invalid family(%d) != AF_INET(%d)\n",
			__func__, sockfd, ia.sin_family, AF_INET);

		return -EINVAL;
	}

	return 0;
}

static int
netwrap_get_remote_hw(int sockfd, struct sockaddr_in *ia)
{
	int ret, offset = 0, i;
	struct arpreq arpreq;
	char mac_addr[64];

	memset(&arpreq, 0, sizeof(struct arpreq));
	memcpy(&arpreq.arp_pa, ia, sizeof(struct sockaddr_in));
	strcpy(arpreq.arp_dev, s_slow_if);
	arpreq.arp_pa.sa_family = AF_INET;
	arpreq.arp_ha.sa_family = AF_UNSPEC;

	if (!libc_ioctl) {
		RTE_LOG(ERR, pre_ld, "libc_ioctl is NULL\n");
		return -EIO;
	}

	ret = (*libc_ioctl)(sockfd, SIOCGARP, &arpreq);
	if (ret < 0) {
		RTE_LOG(ERR, pre_ld,
			"ioctl SIOCGARP error: %d\n", ret);
		return ret;
	}

	rte_memcpy(&pinfo.dst_mac, &arpreq.arp_ha.sa_data,
		sizeof(pinfo.dst_mac));
	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
		if (i != (RTE_ETHER_ADDR_LEN - 1)) {
			offset += sprintf(&mac_addr[offset],
				"%02x:", pinfo.dst_mac[i]);
		} else {
			offset += sprintf(&mac_addr[offset],
				"%02x", pinfo.dst_mac[i]);
		}
	}
	RTE_LOG(INFO, pre_ld,
		"%s: socket fd:%d, Remote Mac: %s\n",
		__func__, sockfd, mac_addr);

	return 0;
}

static int
netwrap_get_remote_info(int sockfd)
{
	int ret;
	struct sockaddr_in ia;
	socklen_t addrlen;
	char ipaddr_str[64];

	if (!libc_getpeername) {
		LIBC_FUNCTION(getpeername);
		if (!libc_getpeername) {
			RTE_LOG(ERR, pre_ld,
				"libc_getpeername is NULL\n");
			return -ENOTSUP;
		}
	}

	ret = (*libc_getpeername)(sockfd, (struct sockaddr *)&ia,
		&addrlen);
	if (ret < 0) {
		RTE_LOG(ERR, pre_ld, "libc_getpeername error:%d\n", ret);
		return ret;
	}

	if (ia.sin_family != AF_INET) {
		RTE_LOG(ERR, pre_ld,
			"%s: fd:%d, Invalid family(%d) != AF_INET(%d)\n",
			__func__, sockfd, ia.sin_family, AF_INET);
		return -EINVAL;
	}

	ret = convert_ip_addr_to_str(ipaddr_str,
		&ia.sin_addr.s_addr, 4);
	if (ret)
		return ret;

	RTE_LOG(INFO, pre_ld,
		"%s fd:%d, remote family=%d, port=%x, IP addr=%s\n",
		__func__, sockfd, ia.sin_family,
		ntohs(ia.sin_port), ipaddr_str);

	pinfo.dst_ip = ia.sin_addr.s_addr;
	pinfo.dst_port = ia.sin_port;

	ret = netwrap_get_remote_hw(sockfd, &ia);

	return ret;
}

static int
netwrap_get_local_hw(int sockfd)
{
	int ret, offset = 0, i;
	struct ifreq ifr;
	char mac_addr[64];

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, s_slow_if);

	if (!libc_ioctl) {
		RTE_LOG(INFO, pre_ld, "libc_ioctl is NULL\n");
		return -EIO;
	}

	ret = (*libc_ioctl)(sockfd, SIOCGIFHWADDR, &ifr);
	if (ret < 0) {
		RTE_LOG(ERR, pre_ld,
			"ioctl SIOCGIFHWADDR error:%d\n", ret);
		return ret;
	}

	rte_memcpy(&pinfo.src_mac, &ifr.ifr_hwaddr.sa_data,
		sizeof(pinfo.src_mac));
	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
		if (i != (RTE_ETHER_ADDR_LEN - 1)) {
			offset += sprintf(&mac_addr[offset],
				"%02x:", pinfo.src_mac[i]);
		} else {
			offset += sprintf(&mac_addr[offset],
				"%02x", pinfo.src_mac[i]);
		}
	}
	RTE_LOG(INFO, pre_ld,
		"%s: socket fd:%d, Local Mac: %s\n",
		__func__, sockfd, mac_addr);

	return 0;
}

static void
netwrap_collect_info(int sockfd)
{
	netwrap_get_local_ip(sockfd);
	netwrap_get_local_hw(sockfd);
	netwrap_get_remote_info(sockfd);
}

int
bind(int sockfd, const struct sockaddr *addr,
	socklen_t addrlen)
{
	int bind_value = 0, ret;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, s_usect_sockfd:%d, libc_bind:%p\n",
			__func__, sockfd, s_usect_sockfd, libc_bind);
	}

	if (IS_USECT_SOCKET(sockfd)) {
		if (libc_bind)
			bind_value = (*libc_bind)(sockfd, addr, addrlen);
		if (!bind_value) {
			const struct sockaddr_in *sa = (const void *)addr;
			char ipaddr_str[64];

			if (sa->sin_family != AF_INET) {
				RTE_LOG(ERR, pre_ld,
					"%s: fd:%d, Invalid family(%d) != AF_INET(%d)\n",
					__func__, sockfd, sa->sin_family,
					AF_INET);
				return -EINVAL;
			}

			ret = convert_ip_addr_to_str(ipaddr_str,
					&sa->sin_addr.s_addr, 4);
			if (ret)
				return ret;

			RTE_LOG(INFO, pre_ld,
				"%s fd:%d, family=%d, port=%x, IP addr==%s\n",
				__func__, sockfd, sa->sin_family,
				ntohs(sa->sin_port), ipaddr_str);

			netwrap_collect_info(sockfd);
			bind_value = eal_create_flow("udp", "dst",
				ntohs(sa->sin_port));
		}
	} else if (libc_bind) {
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
			"%s starts: sockfd:%d, s_usect_sockfd:%d, libc_bind:%p\n",
			__func__, sockfd, s_usect_sockfd, libc_accept);
	}

	if (IS_USECT_SOCKET(sockfd)) {
		RTE_LOG(INFO, pre_ld,
			"%s socket fd:%d\n", __func__, sockfd);
		if (libc_accept)
			accept_value = (*libc_accept)(sockfd, addr, addrlen);
	} else if (libc_accept) {
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

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, s_usect_sockfd:%d, libc_connect:%p\n",
			__func__, sockfd, s_usect_sockfd, libc_connect);
	}

	if (IS_USECT_SOCKET(sockfd)) {
		RTE_LOG(INFO, pre_ld,
			"%s socket fd:%d\n", __func__, sockfd);
		if (libc_connect)
			connect_value = (*libc_connect)(sockfd, addr, addrlen);
		if (!connect_value) {
			const struct sockaddr_in *sa = (const void *)addr;
			char ipaddr_str[64];

			if (sa->sin_family != AF_INET) {
				RTE_LOG(ERR, pre_ld,
					"%s: fd:%d, Invalid family(%d) != AF_INET(%d)\n",
					__func__, sockfd, sa->sin_family,
					AF_INET);
				return -EINVAL;
			}

			ret = convert_ip_addr_to_str(ipaddr_str,
					&sa->sin_addr.s_addr, 4);
			if (ret)
				return ret;

			RTE_LOG(INFO, pre_ld,
				"%s fd:%d, family=%d, port=%x, IP addr==%s\n",
				__func__, sockfd, sa->sin_family,
				ntohs(sa->sin_port), ipaddr_str);

			netwrap_collect_info(sockfd);
			connect_value = eal_create_flow("udp", "dst",
				ntohs(sa->sin_port));
		}
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

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, s_usect_sockfd:%d, libc_read:%p\n",
			__func__, sockfd, s_usect_sockfd, libc_read);
	}

	if (IS_USECT_SOCKET(sockfd)) {
		read_value = eal_recv(sockfd, buf, len, 0);
		errno = 0;
	} else if (libc_read) {
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

	return read_value;
}

ssize_t
write(int sockfd, const void *buf, size_t len)
{
	ssize_t write_value;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, s_usect_sockfd:%d, libc_write:%p\n",
			__func__, sockfd, s_usect_sockfd, libc_write);
	}

	if (IS_USECT_SOCKET(sockfd)) {
		write_value = eal_send(sockfd, buf, len, 0);
		errno = 0;
	} else if (libc_write) {
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

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, s_usect_sockfd:%d, libc_recv:%p\n",
			__func__, sockfd, s_usect_sockfd, libc_recv);
	}

	if (IS_USECT_SOCKET(sockfd)) {
		recv_value = eal_recv(sockfd, buf, len, flags);
		errno = 0;
	} else if (libc_recv) {
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

	return recv_value;
}

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
	ssize_t send_value;

	if (s_socket_dbg) {
		RTE_LOG(INFO, pre_ld,
			"%s starts: sockfd:%d, s_usect_sockfd:%d, libc_send:%p\n",
			__func__, sockfd, s_usect_sockfd, libc_send);
	}

	if (IS_USECT_SOCKET(sockfd)) {
		send_value = eal_send(sockfd, buf, len, flags);
		errno = 0;
	} else if (libc_send) {
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

int
ioctl(int fd, unsigned long request, ...)
{
	int ioctl_value;
	va_list ap;
	void *data;

	va_start(ap, request);
	data = va_arg(ap, void *);
	va_end(ap);

	if (IS_USECT_SOCKET(fd) && libc_ioctl) {
		RTE_LOG(INFO, pre_ld,
			"IOCTL fd = %d, request = 0x%lx\n",
			fd, request);
		ioctl_value = (*libc_ioctl)(fd, request, data);
	} else if (libc_ioctl) {
		RTE_LOG(INFO, pre_ld,
			"libc_ioctl fd = %d, request = 0x%lx\n",
			fd, request);
		ioctl_value = (*libc_ioctl)(fd, request, data);
	} else {
		LIBC_FUNCTION(ioctl);
		RTE_LOG(INFO, pre_ld,
			"libc_ioctl fd = %d, request = 0x%lx\n",
			fd, request);
		if (libc_ioctl)
			ioctl_value = (*libc_ioctl)(fd, request, data);
		else {
			ioctl_value = -1;
			errno = EACCES;
		}
	}

	return ioctl_value;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout)
{
	int select_value;

	if ((s_usect_sockfd >= 0 && s_usect_sockfd < nfds) &&
		readfds && FD_ISSET(s_usect_sockfd, readfds)) {
		if (!libc_select) {
			LIBC_FUNCTION(select);
			if (!libc_select) {
				select_value = -1;
				errno = EACCES;

				return select_value;
			}
		}
		select_value = (*libc_select)(nfds, readfds, writefds,
			exceptfds, timeout);
		if (select_value > 0) {
			FD_SET(s_usect_sockfd, readfds);

			return select_value;
		}
		if (readfds)
			FD_SET(s_usect_sockfd, readfds);
		/* Here assume there is always data arriving. */
		select_value = 1;
	} else if (libc_select)
		select_value = (*libc_select)(nfds, readfds, writefds,
			exceptfds, timeout);
	else {
		LIBC_FUNCTION(select);

		if (libc_select) {
			select_value = (*libc_select)(nfds, readfds, writefds,
				exceptfds, timeout);
		} else {
			select_value = -1;
			errno = EACCES;
		}
	}

	return select_value;
}

__attribute__((destructor)) static void netwrap_main_dtor(void)
{
	eal_quit();
}

__attribute__((constructor(65535))) static void setup_wrappers(void)
{
	char *pre_ld_env = getenv("PRE_LOAD_WAPPERS");
	char *log_env = getenv("NET_WRAP_LOG");
	int ret;

	s_uplink = getenv("uplink_name");
	s_slow_if = getenv("eth_name");
	if (!s_slow_if) {
		RTE_LOG(ERR, pre_ld,
			"slow interface(kernel) not specified!\n");

		exit(EXIT_FAILURE);
	}
	s_eal_params = getenv("eal_params");
	if (!s_eal_params) {
		RTE_LOG(ERR, pre_ld, "eal_params not set\n");

		exit(EXIT_FAILURE);
	}

	RTE_LOG(INFO, pre_ld, "%s: pre_ld_env:%p\n",
		__func__, pre_ld_env);

	if (log_env)
		s_socket_dbg = 1;

	if (!pre_ld_env)
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
	LIBC_FUNCTION(getsockname);
	LIBC_FUNCTION(getpeername);
	LIBC_FUNCTION(ioctl);
	LIBC_FUNCTION(select);
	s_socket_pre_set = 1;
}
