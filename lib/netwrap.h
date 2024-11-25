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

#include "usr_sec.h"

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

enum pre_ld_cmp_offset {
	PRE_LD_NO_CMP,
	PRE_LD_CMP_L2_OFFSET,
	PRE_LD_CMP_L3_OFFSET,
	PRE_LD_CMP_L4_OFFSET,
	PRE_LD_CMP_L5_OFFSET
};

#define PRE_LD_FLOW_MAX_ITEM 4

union pre_ld_flow_item {
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item_ipv6 ipv6_spec;
	struct rte_flow_item_esp esp_spec;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_gtp gtp_spec;
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_ecpri ecpri_spec;
};

struct pre_ld_port_rx_source {
	uint16_t port_id;
	uint8_t tc_id;
	uint16_t flow_id;
	uint16_t queue_id;
};

struct pre_ld_port_rx_flow {
	const struct pre_ld_port_rx_source *src;
	struct rte_flow *flow;
	enum rte_flow_item_type type[PRE_LD_FLOW_MAX_ITEM];
	union pre_ld_flow_item items[PRE_LD_FLOW_MAX_ITEM];
	union pre_ld_flow_item masks[PRE_LD_FLOW_MAX_ITEM];
	enum pre_ld_cmp_offset cmp_offset_type;
	uint8_t cmp_offset;
	uint8_t cmp_size;
	uint8_t cmp_data[64];
};

struct pre_ld_sp_node;

struct pre_ld_sec_desc {
	uint16_t sec_id;
	uint16_t *queue_id;
	struct pre_ld_sp_node *sp_list;
};

struct pre_ld_ring {
	char name[RTE_MEMZONE_NAMESIZE];
	uint16_t pre_ld_head;
	uint16_t pre_ld_tail;
	uint16_t pre_ld_size;
	void **pre_ld_elems;
};

enum pre_ld_dir_poll_type {
	RX_QUEUE,
	PRE_LD_TX_RING,
	TX_RING,
	SEC_IN_COMPLETE,
	SEC_EG_COMPLETE,
	PRE_LD_MBUF_FREE_RING,
	MBUF_FREE_RING,
	MBUF_MALLOC_POOL
};

union pre_ld_dir_poll {
	struct pre_ld_port_rx_flow *rx_flow;
	struct pre_ld_sec_desc poll_sec;
	struct rte_ring *tx_ring;
	struct pre_ld_ring *pre_ld_tx_ring;
	struct rte_ring *free_ring;
	struct pre_ld_ring *pre_ld_free_ring;
	struct rte_mempool *malloc_pool;
};

enum pre_ld_dir_dest_type {
	HW_PORT,
	PRE_LD_RX_RING,
	RX_RING,
	SEC_INGRESS,
	SEC_EGRESS,
	FREE_MBUF,
	PRE_LD_MALLOC_RING,
	MALLOC_RING,
	DROP
};

#define INVALID_ESP_SPI 0

union pre_ld_dir_dest {
	uint16_t dest_port;
	struct pre_ld_ring *pre_ld_rx_ring;
	struct rte_ring *rx_ring;
	struct pre_ld_sec_desc dest_sec;
	struct pre_ld_ring *pre_ld_malloc_ring;
	struct rte_ring *malloc_ring;
};

struct pre_ld_dir_statistic {
	uint64_t count;
	uint64_t pkts;
	union {
		uint64_t oh_bytes;
		uint64_t sec_bytes;
	};
};

struct pre_ld_direct_entry {
	TAILQ_ENTRY(pre_ld_direct_entry) next;
	enum pre_ld_dir_poll_type poll_type;
	union pre_ld_dir_poll poll;
	enum pre_ld_dir_dest_type dest_type;
	union pre_ld_dir_dest dest;
	struct pre_ld_dir_statistic tx_stat;
	struct pre_ld_dir_statistic rx_stat;
	char *poll_prefix;
	char *action_prefix;
	void (*entry_cb)(struct pre_ld_direct_entry *entry, int drain);

	/** Update by statistic function only.*/
	struct pre_ld_dir_statistic tx_old_stat;
	struct pre_ld_dir_statistic rx_old_stat;
};

struct pre_ld_crypt_param {
	uint8_t crypt_dev;
	struct rte_mempool *sess_pool;
	struct rte_mempool *sess_priv_pool;
};

struct pre_ld_ipsec_sa_entry {
	LIST_ENTRY(pre_ld_ipsec_sa_entry) next;
	struct rte_ipsec_session session;
	uint64_t created_cyc;
	uint64_t seq;
	enum pre_ld_ipsec_sa_flag sa_flags;
	uint16_t family;
	xfrm_address_t src;
	xfrm_address_t dst;
	uint8_t cipher_key[MAX_SEC_KEY_SIZE];
	uint16_t cipher_key_len;
	uint8_t auth_key[MAX_SEC_KEY_SIZE];
	uint16_t auth_key_len;
	uint16_t portid;
	int sec_id;
	struct pre_ld_ipsec_sp_entry *sp;

	struct rte_crypto_sym_xform auth_xform;
	struct rte_crypto_sym_xform ciph_xform;
	struct rte_security_session_conf sess_conf;
};

struct pre_ld_ipsec_sp_entry {
	LIST_ENTRY(pre_ld_ipsec_sp_entry) next;
	xfrm_address_t src;
	xfrm_address_t dst;
	xfrm_address_t sel_src;
	xfrm_address_t sel_dst;
	uint16_t family;
	uint32_t priority;
	uint32_t index;
	uint8_t dir;

	struct rte_flow *flow;
	uint8_t crypt_id;
	struct pre_ld_direct_entry *entry_to_sec;
	struct pre_ld_direct_entry *entry_from_sec;

	struct pre_ld_ipsec_sa_entry *sa;
	struct pre_ld_ipsec_sp_head *head;
};

struct pre_ld_sp_node {
	struct pre_ld_ipsec_sp_entry *sp;
	struct pre_ld_sp_node *next;
};

struct pre_ld_ipsec_sa_head {
	struct pre_ld_ipsec_sa_entry *lh_first;
};

struct pre_ld_ipsec_sp_head {
	struct pre_ld_ipsec_sp_entry *lh_first;
};

struct pre_ld_ipsec_cntx {
	struct pre_ld_ipsec_sa_head sa_list;
	struct pre_ld_ipsec_sp_head sp_ipv4_in_list;
	struct pre_ld_ipsec_sp_head sp_ipv6_in_list;
	struct pre_ld_ipsec_sp_head sp_ipv4_out_list;
	struct pre_ld_ipsec_sp_head sp_ipv6_out_list;
};

#define PRE_LD_FLOW_DESTROY_TRY_TIMES 10

#define dcbf(p) { asm volatile("dc cvac, %0" : : "r"(p) : "memory"); }
#define dccivac(p) { asm volatile("dc civac, %0" : : "r"(p) : "memory"); }

static inline int
_pre_ld_log(char *buf, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vsprintf(buf, format, ap);
	va_end(ap);

	return ret;
}

void
pre_ld_log(uint32_t level, uint32_t logtype, const char *format, ...);

#define PRE_LD_LOG(l, ...) \
	pre_ld_log(RTE_LOG_##l, RTE_LOGTYPE_pre_ld, __VA_ARGS__)

int
pre_ld_configure_sec_path(struct pre_ld_ipsec_sp_entry *sp,
	rte_be32_t spi);
void
pre_ld_deconfigure_sec_path(struct pre_ld_ipsec_sp_entry *sp);
int
pre_ld_attach_sec_path(struct pre_ld_ipsec_sp_entry *sp);
int
pre_ld_detach_sec_path(struct pre_ld_ipsec_sp_entry *sp);
double
pre_ld_get_cycs_per_us(void);

extern void
eal_lcore_non_eal_release(uint32_t lcore_id);

#endif /* __NETWRAP_COMMON_H__ */
