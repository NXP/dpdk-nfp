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

struct pre_ld_port_desc {
	uint16_t port_id;
	uint16_t *queue_id;
	void *flow;
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
	TX_RING,
	SEC_IN_COMPLETE,
	SEC_EG_COMPLETE,
	PRE_LD_MBUF_FREE_RING,
	MBUF_FREE_RING
};

union pre_ld_dir_poll {
	struct pre_ld_port_desc poll_port;
	struct pre_ld_sec_desc poll_sec;
	struct rte_ring *tx_ring;
	struct rte_ring *free_ring;
	struct pre_ld_ring *pre_ld_free_ring;
};

enum pre_ld_dir_dest_type {
	HW_PORT,
	PRE_LD_RX_RING,
	RX_RING,
	SEC_INGRESS,
	SEC_EGRESS,
	FREE_MBUF,
	DROP
};

#define INVALID_ESP_SPI 0

union pre_ld_dir_dest {
	uint16_t dest_port;
	struct pre_ld_ring *pre_ld_rx_ring;
	struct rte_ring *rx_ring;
	struct pre_ld_sec_desc dest_sec;
};

struct pre_ld_dir_statistic {
	uint64_t count;
	uint64_t pkts;
	union {
		uint64_t oh_bytes;
		uint64_t sec_bytes;
	};
};

enum pre_ld_dir_entry_state {
	PRE_LD_DIR_ENTRY_RUNNING = 1,
	PRE_LD_DIR_ENTRY_STOPPING = 2,
	PRE_LD_DIR_ENTRY_STOPPED = 3
};

struct pre_ld_direct_entry {
	TAILQ_ENTRY(pre_ld_direct_entry) next;
	enum pre_ld_dir_entry_state state;
	enum pre_ld_dir_poll_type poll_type;
	union pre_ld_dir_poll poll;
	enum pre_ld_dir_dest_type dest_type;
	union pre_ld_dir_dest dest;
	struct pre_ld_dir_statistic tx_stat;
	struct pre_ld_dir_statistic rx_stat;

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

	struct rte_flow_action action[2];
	struct rte_flow_attr attr;
	struct rte_flow_action_queue ingress_queue;
	struct rte_flow_item flow_item[3];
	union {
		struct rte_flow_item_ipv4 ipv4_spec;
		struct rte_flow_item_ipv6 ipv6_spec;
	};
	union {
		struct rte_flow_item_ipv4 ipv4_mask;
		struct rte_flow_item_ipv6 ipv6_mask;
	};
	struct rte_flow_item_esp esp_spec;
	struct rte_flow_item_esp esp_mask;
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

int
pre_ld_configure_sec_path(struct pre_ld_ipsec_sp_entry *sp);
void
pre_ld_deconfigure_sec_path(struct pre_ld_ipsec_sp_entry *sp);
int
pre_ld_attach_sec_path(struct pre_ld_ipsec_sp_entry *sp);
int
pre_ld_detach_sec_path(struct pre_ld_ipsec_sp_entry *sp);

extern void
eal_lcore_non_eal_release(uint32_t lcore_id);

#endif /* __NETWRAP_COMMON_H__ */
