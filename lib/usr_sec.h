/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
 * Copyright 2023-2024 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _USR_SEC_H
#define _USR_SEC_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <linux/pfkeyv2.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_debug.h>
#include <rte_string_fns.h>
#include <rte_tm.h>
#include <rte_ipsec.h>
#include <rte_flow.h>

#include "netwrap.h"

#ifndef bool
#define bool int
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif /* unlikely */

#define INVALID_QUEUEID 0xffff
#define INVALID_PORTID 0xffff

#define MAX_SEC_KEY_SIZE 36

#define PRE_LD_INVALID_SPI (0)

#define PRE_LD_IPSEC_SP_MAX_ENTRY_MASK 0xff
#define PRE_LD_IPSEC_SP_MAX_ENTRIES \
	(PRE_LD_IPSEC_SP_MAX_ENTRY_MASK + 1)

enum pre_ld_ipsec_sa_flag {
	IP4_TUNNEL = (1 << 0),
	IP6_TUNNEL = (1 << 1),
	TRANSPORT = (1 << 2),
	IP4_TRANSPORT = (1 << 3),
	IP6_TRANSPORT = (1 << 4)
};

union pre_ld_ipsec_addr {
	uint8_t ip4[sizeof(rte_be32_t)];
	uint8_t ip6[16];
};

struct pre_ld_ipsec_sa_entry {
	LIST_ENTRY(pre_ld_ipsec_sa_entry) next;
	struct rte_ipsec_session session;
	uint64_t seq;
	enum pre_ld_ipsec_sa_flag sa_flags;
	uint16_t family;
	union pre_ld_ipsec_addr src;
	union pre_ld_ipsec_addr dst;
	uint8_t cipher_key[MAX_SEC_KEY_SIZE];
	uint16_t cipher_key_len;
	uint8_t auth_key[MAX_SEC_KEY_SIZE];
	uint16_t auth_key_len;
	uint16_t portid;

	struct rte_crypto_sym_xform auth_xform;
	struct rte_crypto_sym_xform ciph_xform;
	struct rte_security_session_conf sess_conf;
};

struct pre_ld_ipsec_sp_entry {
	LIST_ENTRY(pre_ld_ipsec_sp_entry) next;
	union pre_ld_ipsec_addr src;
	union pre_ld_ipsec_addr dst;
	rte_be32_t spi;
	uint16_t family;
	uint32_t priority;
	uint32_t index;

	struct rte_flow_action action;
	struct rte_flow_attr attr;
	union {
		struct rte_flow_item_ipv4 ipv4_spec;
		struct rte_flow_item_ipv6 ipv6_spec;
	};
	struct rte_flow_item_esp esp_spec;
	struct rte_flow *flow;
	uint32_t flow_idx;

	struct pre_ld_ipsec_sa_entry *sa;
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

	struct pre_ld_ipsec_sp_entry *sp_in;
};

struct pre_ld_ipsec_priv {
	struct pre_ld_ipsec_sa_entry *sa;
	struct rte_crypto_op cop;
	struct rte_crypto_sym_op sym_cop;
	uint8_t cntx[32];
} __rte_cache_aligned;

enum {
	XFRMA_AUTH_PRESENT = 1,
	XFRMA_AUTH_TRUNC_PRESENT = 2
};

struct xfrm_algo_param {
	char alg_name[64];
	uint32_t alg_key_len; /* in bytes */
	uint8_t alg_key[MAX_SEC_KEY_SIZE];
};

struct xfrm_algo_trunc_param {
	char alg_name[64];
	uint32_t alg_key_len; /* in bytes */
	uint32_t alg_trunc_len; /* icv trunc in bytes */
	uint8_t alg_key[MAX_SEC_KEY_SIZE];
};

union xfrm_auth_algo_param {
	struct xfrm_algo_param alg;
	struct xfrm_algo_trunc_param alg_trunc;
};

struct xfm_ipsec_sa_params {
	int auth_present;
	int ciph_present;
	int encp_present;
	struct xfrm_algo_param ciph_alg;
	union xfrm_auth_algo_param auth_alg;
	struct xfrm_encap_tmpl encp;
};

int
xfm_crypto_init(uint8_t crypt_dev, uint16_t qp_nb,
	uint16_t sec_port, uint16_t sec_port_flow);

struct pre_ld_ipsec_cntx *xfm_get_cntx(void);

int
do_spdget(int spid, xfrm_address_t *saddr,
	xfrm_address_t *daddr, int *sa_af);

int
do_spddel(int spid);

int
do_saddel(int spi);

int
pfkey_align(struct sadb_msg *msg, caddr_t *mhp);

int pfkey_recv_sadbmsg(int so, u_int msg_type, u_int32_t seq_num,
	struct sadb_msg **newmsg);

void kdebug_sadb(struct sadb_msg *base);

int pfkey_open(void);

void pfkey_close(int so);

int pfkey_send(int so, struct sadb_msg *msg, int len);

#endif
