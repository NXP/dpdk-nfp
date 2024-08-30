/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
 * Copyright 2023-2024 NXP
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <linux/pfkeyv2.h>
#include <net/if.h>
#include <assert.h>
#include <linux/rtnetlink.h>
#include <sys/msg.h>
#include <sys/queue.h>

#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cryptodev.h>
#include <rte_security.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_ring.h>
#include <rte_common.h>
#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_log.h>
#include <rte_thread.h>
#include <rte_launch.h>
#include <rte_tailq.h>

#include "netwrap.h"

static char s_dump_prefix[sizeof("PRE_LD_IPSEC: ") - 1];
#define DUMP_PREFIX s_dump_prefix
#define DUMP_BUF_SIZE 2048

#define NLA_DATA(na) ((void *)((char *)(na) + NLA_HDRLEN))
#define NLA_NEXT(na, len) \
	((len) -= NLA_ALIGN((na)->nla_len), \
		(struct nlattr *)((char *)(na) \
		+ NLA_ALIGN((na)->nla_len)))
#define NLA_OK(na, len) \
	((len) >= (int)sizeof(struct nlattr) && \
		(na)->nla_len >= sizeof(struct nlattr) && \
		(na)->nla_len <= (len))

struct xfm_ciph_support {
	const char *name;
	enum rte_crypto_cipher_algorithm algo;
};

struct xfm_auth_support {
	const char *name;
	enum rte_crypto_auth_algorithm algo;
};

static const struct xfm_ciph_support s_xfm_cipher[] = {
	{
		.name = "ecb(cipher_null)",
		.algo = RTE_CRYPTO_CIPHER_NULL,
	},
	{
		.name = "cbc(aes)",
		.algo = RTE_CRYPTO_CIPHER_AES_CBC,
	},
	{
		.name = "ctr(aes)",
		.algo = RTE_CRYPTO_CIPHER_AES_CTR,
	},
	{
		.name = "cbc(3des)",
		.algo = RTE_CRYPTO_CIPHER_3DES_CBC,
	},
	{
		.name = "cbc(des)",
		.algo = RTE_CRYPTO_CIPHER_DES_CBC,
	}
};

static const struct xfm_auth_support s_auth_xfm[] = {
	{
		.name = "digest_null",
		.algo = RTE_CRYPTO_AUTH_NULL,
	},
	{
		.name = "hmac(sha1)",
		.algo = RTE_CRYPTO_AUTH_SHA1_HMAC,
	},
	{
		.name = "hmac(sha256)",
		.algo = RTE_CRYPTO_AUTH_SHA256_HMAC,
	},
	{
		.name = "xcbc(aes)",
		.algo = RTE_CRYPTO_AUTH_AES_XCBC_MAC,
	},
};

static int s_ipsec_ib_flow_ip_addr_extract;

static struct pre_ld_ipsec_cntx s_pre_ld_ipsec_cntx;

static int s_kernel_sp_sa_clear;

static double s_xfm_cycs_per_us;

struct pre_ld_xfm_flow {
	TAILQ_ENTRY(pre_ld_xfm_flow) next;
	struct rte_flow *flow;
	int flow_ref;
};

TAILQ_HEAD(pre_ld_xfm_flow_list, pre_ld_xfm_flow);
static struct pre_ld_xfm_flow_list s_xfm_flow_list =
	TAILQ_HEAD_INITIALIZER(s_xfm_flow_list);

struct pre_ld_ipsec_cntx *xfm_get_cntx(void)
{
	return &s_pre_ld_ipsec_cntx;
}

static const struct xfm_ciph_support *
xfm_ciph_support_by_nm(const char *nm)
{
	uint32_t i;

	for (i = 0; i < RTE_DIM(s_xfm_cipher); i++) {
		if (!strcmp(nm, s_xfm_cipher[i].name))
			return &s_xfm_cipher[i];
	}

	return NULL;
}

static const struct xfm_auth_support *
xfm_auth_support_by_nm(const char *nm)
{
	uint32_t i;

	for (i = 0; i < RTE_DIM(s_auth_xfm); i++) {
		if (!strcmp(nm, s_auth_xfm[i].name))
			return &s_auth_xfm[i];
	}

	return NULL;
}

static int create_nl_socket(int protocol, int groups)
{
	int fd, ret;
	struct sockaddr_nl local;

	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0)
		return fd;

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = groups;
	ret = bind(fd, (struct sockaddr *)&local, sizeof(local));
	if (ret < 0) {
		close(fd);
		return ret;
	}

	return fd;
}

static int
add_dump_selector_info(char *pol_dump,
	int max_len, int offset,
	const struct xfrm_selector *sel,
	const char *prefix)
{
	uint8_t src[sizeof(rte_be32_t) * 4];
	uint8_t dst[sizeof(rte_be32_t) * 4];
	uint8_t sport[sizeof(rte_be16_t)], sport_mask[sizeof(rte_be16_t)];
	uint8_t dport[sizeof(rte_be16_t)], dport_mask[sizeof(rte_be16_t)];

	offset += sprintf(&pol_dump[offset],
		"%ssel(family(%d))", prefix, sel->family);
	if (sel->family == AF_INET) {
		rte_memcpy(src, &sel->saddr.a4, sizeof(rte_be32_t));
		rte_memcpy(dst, &sel->daddr.a4, sizeof(rte_be32_t));
		offset += sprintf(&pol_dump[offset], ": src(%d.%d.%d.%d) ",
			src[0], src[1], src[2], src[3]);
		offset += sprintf(&pol_dump[offset], "dst(%d.%d.%d.%d)\n",
			dst[0], dst[1], dst[2], dst[3]);
	} else if (sel->family == AF_INET6) {
		rte_memcpy(src, &sel->saddr.a6,
			sizeof(rte_be32_t) * 4);
		rte_memcpy(dst, &sel->daddr.a6,
			sizeof(rte_be32_t) * 4);
		offset += sprintf(&pol_dump[offset],
			": src(%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			src[0], src[1], src[2], src[3],
			src[4], src[5], src[6], src[7]);
		offset += sprintf(&pol_dump[offset],
			":%02x%02x:%02x%02x:%02x%02x:%02x%02x)\n",
			src[8], src[9], src[10], src[11],
			src[12], src[13], src[14], src[15]);
		offset += sprintf(&pol_dump[offset],
			"%sdst(%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			prefix, dst[0], dst[1], dst[2], dst[3],
			dst[4], dst[5], dst[6], dst[7]);
		offset += sprintf(&pol_dump[offset],
			":%02x%02x:%02x%02x:%02x%02x:%02x%02x)\n",
			dst[8], dst[9], dst[10], dst[11],
			dst[12], dst[13], dst[14], dst[15]);
	} else {
		offset += sprintf(&pol_dump[offset], "\n");
	}
	RTE_VERIFY(offset < max_len);

	if (sel->family != AF_INET && sel->family != AF_INET6)
		return offset;

	offset += sprintf(&pol_dump[offset],
		"%snext prot(%d)", prefix,
		sel->proto);
	if (sel->proto != IPPROTO_UDP && sel->proto != IPPROTO_TCP) {
		offset += sprintf(&pol_dump[offset], "\n");
		return offset;
	}

	rte_memcpy(sport, &sel->sport, sizeof(rte_be16_t));
	rte_memcpy(sport_mask, &sel->sport_mask,
		sizeof(rte_be16_t));
	rte_memcpy(dport, &sel->dport, sizeof(rte_be16_t));
	rte_memcpy(dport_mask, &sel->dport_mask,
		sizeof(rte_be16_t));

	offset += sprintf(&pol_dump[offset],
		": sport:(%02x%02x, %02x%02x) ",
		sport[0], sport[1], sport_mask[0], sport_mask[1]);
	offset += sprintf(&pol_dump[offset],
		"dport:(%02x%02x, %02x%02x)\n",
		dport[0], dport[1], dport_mask[0], dport_mask[1]);
	RTE_VERIFY(offset < max_len);

	return offset;
}

static void
dump_sa_from_xfrm(const struct xfrm_usersa_info *sa_info)
{
	char pol_dump[DUMP_BUF_SIZE];
	int offset = 0;
	uint8_t src[sizeof(rte_be32_t) * 4];
	uint8_t dst[sizeof(rte_be32_t) * 4];

	offset += sprintf(&pol_dump[offset],
		"New SA.ID spi(%08x) ",
		rte_be_to_cpu_32(sa_info->id.spi));

	if (sa_info->family == AF_INET) {
		offset += sprintf(&pol_dump[offset], "IPv4 ");
	} else if (sa_info->family == AF_INET6) {
		offset += sprintf(&pol_dump[offset], "IPv6 ");
	} else {
		offset += sprintf(&pol_dump[offset],
			"Invalid family(%d) ",
			sa_info->family);
	}

	if (sa_info->id.proto == IPPROTO_ESP) {
		offset += sprintf(&pol_dump[offset], "ESP ");
	} else if (sa_info->id.proto == IPPROTO_AH) {
		offset += sprintf(&pol_dump[offset], "AH ");
	} else if (sa_info->id.proto == IPPROTO_COMP) {
		offset += sprintf(&pol_dump[offset], "COMP ");
	} else if (sa_info->id.proto == IPPROTO_DSTOPTS) {
		offset += sprintf(&pol_dump[offset], "IPv6 dest ");
	} else if (sa_info->id.proto == IPPROTO_ROUTING) {
		offset += sprintf(&pol_dump[offset], "IPv6 rout ");
	} else {
		offset += sprintf(&pol_dump[offset],
			"Unsupport proto(%d) ", sa_info->id.proto);
	}

	if (sa_info->mode == XFRM_MODE_ROUTEOPTIMIZATION) {
		offset += sprintf(&pol_dump[offset], "route ");
	} else if (sa_info->mode == XFRM_MODE_TUNNEL) {
		offset += sprintf(&pol_dump[offset], "tunnel ");
	} else if (sa_info->mode == XFRM_MODE_TRANSPORT) {
		offset += sprintf(&pol_dump[offset], "trans ");
	} else if (sa_info->mode == XFRM_MODE_IN_TRIGGER) {
		offset += sprintf(&pol_dump[offset], "trigger ");
	} else if (sa_info->mode == XFRM_MODE_BEET) {
		offset += sprintf(&pol_dump[offset], "beet ");
	} else {
		offset += sprintf(&pol_dump[offset],
			"Unsupport mode(%d) ", sa_info->mode);
	}

	offset += sprintf(&pol_dump[offset],
		"flags(%02x) replay win(%d)\n",
		sa_info->flags, sa_info->replay_window);

	RTE_VERIFY(offset < DUMP_BUF_SIZE);
	if (sa_info->family == AF_INET) {
		rte_memcpy(src, &sa_info->saddr.a4, sizeof(rte_be32_t));
		rte_memcpy(dst, &sa_info->id.daddr.a4, sizeof(rte_be32_t));
		offset += sprintf(&pol_dump[offset],
			"%ssrc:%d.%d.%d.%d", DUMP_PREFIX,
			src[0], src[1], src[2], src[3]);
		offset += sprintf(&pol_dump[offset],
			" dst:%d.%d.%d.%d\n",
			dst[0], dst[1], dst[2], dst[3]);
	} else if (sa_info->family == AF_INET6) {
		rte_memcpy(src, sa_info->saddr.a6,
			sizeof(rte_be32_t) * 4);
		rte_memcpy(dst, sa_info->id.daddr.a6,
			sizeof(rte_be32_t) * 4);
		offset += sprintf(&pol_dump[offset],
			"%ssrc:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			DUMP_PREFIX,
			src[0], src[1], src[2], src[3],
			src[4], src[5], src[6], src[7]);
		offset += sprintf(&pol_dump[offset],
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
			src[8], src[9], src[10], src[11],
			src[12], src[13], src[14], src[15]);
		offset += sprintf(&pol_dump[offset],
			"%sdst:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			DUMP_PREFIX,
			dst[0], dst[1], dst[2], dst[3],
			dst[4], dst[5], dst[6], dst[7]);
		offset += sprintf(&pol_dump[offset],
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
			dst[8], dst[9], dst[10], dst[11],
			dst[12], dst[13], dst[14], dst[15]);
	}

	offset += add_dump_selector_info(&pol_dump[offset],
		DUMP_BUF_SIZE - offset, 0, &sa_info->sel,
		DUMP_PREFIX);
	RTE_VERIFY(offset < DUMP_BUF_SIZE);

	RTE_LOG(INFO, pre_ld, "%s", pol_dump);
}

static int nl_parse_attrs(struct nlattr *na, int len,
		struct xfm_ipsec_sa_params *sa_params)
{
	struct xfrm_algo *cipher_alg = NULL;
	struct xfrm_algo *auth_alg = NULL;
	struct xfrm_encap_tmpl *encp = NULL;
	struct xfrm_algo_auth *auth_trunc_alg = NULL;

	while (NLA_OK(na, len)) {
		switch (na->nla_type) {
		case XFRMA_ALG_AUTH:
			if (sa_params->auth_present >= XFRMA_AUTH_PRESENT)
				break;
			auth_alg = NLA_DATA(na);
			sa_params->auth_present = XFRMA_AUTH_PRESENT;
			rte_memcpy(sa_params->auth_alg.alg.alg_name,
				auth_alg->alg_name, 64);
			sa_params->auth_alg.alg.alg_key_len =
				auth_alg->alg_key_len / 8;
			rte_memcpy(sa_params->auth_alg.alg.alg_key,
				auth_alg->alg_key,
				sa_params->auth_alg.alg.alg_key_len);
			RTE_LOG(INFO, pre_ld, "%s: parse auth alog(%s)\n",
				__func__, auth_alg->alg_name);
			break;
		case XFRMA_ALG_CRYPT:
			cipher_alg = NLA_DATA(na);
			sa_params->ciph_present = 1;
			rte_memcpy(&sa_params->ciph_alg.alg_name,
				cipher_alg->alg_name, 64);
			sa_params->ciph_alg.alg_key_len =
				cipher_alg->alg_key_len / 8;
			rte_memcpy(sa_params->ciph_alg.alg_key,
				cipher_alg->alg_key,
				sa_params->ciph_alg.alg_key_len);
			RTE_LOG(INFO, pre_ld, "%s: parse crypt alog(%s)\n",
				__func__, cipher_alg->alg_name);
			break;
		case XFRMA_ENCAP:
			RTE_LOG(INFO, pre_ld, "%s: parse encap\n",
				__func__);
			encp = NLA_DATA(na);
			sa_params->encp_present = 1;
			rte_memcpy(&sa_params->encp, encp,
				sizeof(struct xfrm_encap_tmpl));
			break;
		case XFRMA_ALG_AUTH_TRUNC:
			RTE_LOG(INFO, pre_ld, "%s: parse auth trunc(%s)\n",
				__func__, auth_alg->alg_name);
			auth_trunc_alg = NLA_DATA(na);
			sa_params->auth_present = XFRMA_AUTH_TRUNC_PRESENT;
			rte_memcpy(sa_params->auth_alg.alg_trunc.alg_name,
				auth_trunc_alg->alg_name, 64);
			sa_params->auth_alg.alg_trunc.alg_key_len =
				auth_trunc_alg->alg_key_len / 8;
			sa_params->auth_alg.alg_trunc.alg_trunc_len =
				auth_trunc_alg->alg_trunc_len / 8;
			rte_memcpy(sa_params->auth_alg.alg_trunc.alg_key,
				auth_trunc_alg->alg_key,
				sa_params->auth_alg.alg_trunc.alg_key_len);
			break;
		default:
			RTE_LOG(ERR, pre_ld,
				"%s: XFRM netlink type(%d) not support\n",
				__func__, na->nla_type);
			break;
		}

		na = NLA_NEXT(na, len);
	}

	return 0;
}

static int
xfm_sp_flow_hw_create(struct pre_ld_ipsec_sp_entry *sp)
{
	struct rte_flow_error error;
	struct pre_ld_xfm_flow *xfm_flow;
	uint16_t port_id;
	int ret, times = PRE_LD_FLOW_DESTROY_TRY_TIMES;

	if (sp->flow) {
		RTE_LOG(WARNING, pre_ld,
			"%s: Policy flow (index=%d) has been created!\n",
			__func__, sp->ingress_queue.index);

		return -EEXIST;
	}

	port_id = sp->entry_to_sec->poll.poll_port.port_id;

	sp->flow = rte_flow_create(port_id, &sp->attr,
			sp->flow_item, sp->action, &error);
	if (sp->flow) {
		xfm_flow = rte_zmalloc(NULL,
			sizeof(struct pre_ld_xfm_flow), 0);
		if (!xfm_flow) {
again:
			ret = rte_flow_destroy(port_id, sp->flow, &error);
			if (ret) {
				RTE_LOG(INFO, pre_ld,
					"%s: destroy flow failed(%d), times=%d\n",
					__func__, ret, times);
			}
			if (ret == -EAGAIN && times > 0) {
				times--;
				goto again;
			}
			sp->flow = NULL;

			return -ENOMEM;
		}
		xfm_flow->flow = sp->flow;
		xfm_flow->flow_ref = 1;
		sp->entry_to_sec->poll.poll_port.flow = sp->flow;
		RTE_LOG(INFO, pre_ld,
			"%s: Policy flow (index=%d) create successfully\n",
			__func__, sp->ingress_queue.index);

		RTE_LOG(INFO, pre_ld,
			"%s: Steer %s flow from port%d flow%d to port%d\n",
			__func__, sp->dir == XFRM_POLICY_IN ?
			"Ingress" : "Egress",
			port_id,
			*sp->entry_to_sec->poll.poll_port.queue_id,
			sp->entry_from_sec->dest.dest_port);

		TAILQ_INSERT_TAIL(&s_xfm_flow_list, xfm_flow, next);

		return 0;
	}

	RTE_LOG(ERR, pre_ld,
		"%s: Policy flow (index=%d) create failed(%s)\n",
		__func__, sp->ingress_queue.index, error.message);

	return -EIO;
}

static int
process_del_policy_entry(struct pre_ld_ipsec_sp_entry *sp)
{
	int ret = 0, times = PRE_LD_FLOW_DESTROY_TRY_TIMES;
	struct rte_flow_error error;
	uint16_t port_id = sp->entry_to_sec->poll.poll_port.port_id;
	struct pre_ld_xfm_flow *xfm_flow = NULL, *txfm_flow;
	struct pre_ld_xfm_flow_list *flow_list = &s_xfm_flow_list;

	LIST_REMOVE(sp, next);

	RTE_TAILQ_FOREACH_SAFE(xfm_flow, flow_list, next, txfm_flow) {
		if (xfm_flow->flow == sp->flow) {
			xfm_flow->flow_ref--;
			break;
		}
	}
	if (!xfm_flow)
		return -ENODATA;

	if (!xfm_flow->flow_ref) {
again:
		ret = rte_flow_destroy(port_id, sp->flow, &error);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: Policy flow destroy failed(%s)(%d), times=%d\n",
				__func__, error.message, ret, times);
		}
		if (ret == -EAGAIN && times > 0) {
			times--;
			goto again;
		}

		pre_ld_deconfigure_sec_path(sp);
		TAILQ_REMOVE(flow_list, xfm_flow, next);
		rte_free(xfm_flow);
	} else {
		ret = pre_ld_detach_sec_path(sp);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: detach sp failed(%d)\n",
				__func__, ret);
		}
	}

	rte_free(sp);

	return ret;
}

static int
xfm_find_sa_by_addrs(const xfrm_address_t *src,
	const xfrm_address_t *dst, uint16_t family,
	struct pre_ld_ipsec_sa_entry *sa[], int max)
{
	struct rte_security_ipsec_xform *ipsec;
	struct pre_ld_ipsec_cntx *cntx = xfm_get_cntx();
	struct pre_ld_ipsec_sa_entry *curr = LIST_FIRST(&cntx->sa_list);
	uint16_t size = 0;
	int num = 0, i, inserted;

	if (family == AF_INET)
		size = sizeof(rte_be32_t);
	else if (family == AF_INET6)
		size = 16;
	else
		return -EINVAL;

	if (!src && !dst)
		return -EINVAL;

	while (curr) {
		ipsec = &curr->sess_conf.ipsec;
		if (ipsec->spi == PRE_LD_INVALID_SPI) {
			curr = LIST_NEXT(curr, next);
			continue;
		}
		if (family != curr->family) {
			curr = LIST_NEXT(curr, next);
			continue;
		}
		if (src && memcmp(src, &curr->src, size))
			goto continue_next;
		if (dst && memcmp(dst, &curr->dst, size))
			goto continue_next;
		if (curr->sp)
			goto continue_next;

		if (num >= max)
			return num;
		inserted = 0;
		for (i = 0; i < num; i++) {
			if (curr->created_cyc < sa[i]->created_cyc) {
				memmove(&sa[i + 1], &sa[i],
					sizeof(void *) * (num - i));
				sa[i] = curr;
				inserted = 1;
				num++;
				break;
			}
		}
		if (!inserted)	{
			sa[num] = curr;
			num++;
		}
continue_next:
		curr = LIST_NEXT(curr, next);
	}

	return num;
}

int
xfm_find_sa_addrs_by_sp_addrs(const xfrm_address_t *src,
	const xfrm_address_t *dst, uint16_t family, int dir,
	xfrm_address_t *sa_src, xfrm_address_t *sa_dst)
{
	struct pre_ld_ipsec_cntx *cntx = xfm_get_cntx();
	struct pre_ld_ipsec_sp_head *head;
	struct pre_ld_ipsec_sp_entry *curr;
	uint16_t size = 0;

	if (family == AF_INET &&
		dir == XFRM_POLICY_IN) {
		head = &cntx->sp_ipv4_in_list;
		size = sizeof(rte_be32_t);
	} else if (family == AF_INET &&
		dir == XFRM_POLICY_OUT) {
		head = &cntx->sp_ipv4_out_list;
		size = sizeof(rte_be32_t);
	} else if (family == AF_INET6 &&
		dir == XFRM_POLICY_IN) {
		head = &cntx->sp_ipv6_in_list;
		size = 16;
	} else if (family == AF_INET6 &&
		dir == XFRM_POLICY_OUT) {
		head = &cntx->sp_ipv6_out_list;
		size = 16;
	} else {
		/* we handle only in/out policies */
		RTE_LOG(ERR, pre_ld,
			"Policy dir(%d)/family(%d) unsupport\n",
			dir, family);
		return -EINVAL;
	}

	curr = LIST_FIRST(head);

	while (curr) {
		if (src && !dst && !memcmp(src, &curr->src, size))
			break;
		if (dst && !src && !memcmp(dst, &curr->dst, size))
			break;
		if (src && dst && !memcmp(src, &curr->src, size) &&
			!memcmp(dst, &curr->dst, size))
			break;
		curr = LIST_NEXT(curr, next);
	}

	if (curr) {
		if (sa_src) {
			if (!curr->sa)
				return -ENODATA;
			rte_memcpy(sa_src, &curr->sa->src,
				sizeof(xfrm_address_t));
		}
		if (sa_dst) {
			if (!curr->sa)
				return -ENODATA;
			rte_memcpy(sa_dst, &curr->sa->dst,
				sizeof(xfrm_address_t));
		}

		return 0;
	}

	return -ENODATA;
}

static int
xfm_to_sa_entry(const struct xfm_ipsec_sa_params *sa_param,
	const struct xfrm_usersa_info *sa_info, int update)
{
	struct pre_ld_ipsec_sa_entry *sa_entry = NULL;
	const struct xfm_auth_support *auth_entry;
	const struct xfm_ciph_support *ciph_entry;
	struct rte_security_ipsec_tunnel_param *tunnel_param;
	const struct xfrm_algo_param *ciph = NULL;
	const struct xfrm_algo_param *auth = NULL;
	const struct xfrm_algo_trunc_param *auth_trunc = NULL;
	int new_sa = 0, ret = 0;
	uint32_t spi = rte_be_to_cpu_32(sa_info->id.spi);
	struct pre_ld_ipsec_cntx *cntx = xfm_get_cntx();
	struct pre_ld_ipsec_sa_entry *curr = LIST_FIRST(&cntx->sa_list);

	if (update) {
		while (curr) {
			if (curr->sess_conf.ipsec.spi == spi) {
				sa_entry = curr;
				goto update_sa;
			}
			curr = LIST_NEXT(curr, next);
		}
	}

	sa_entry = rte_zmalloc(NULL, sizeof(struct pre_ld_ipsec_sa_entry),
		RTE_CACHE_LINE_SIZE);
	if (!sa_entry) {
		RTE_LOG(ERR, pre_ld,
			"New SA entry malloc failed\n");
		return -ENOMEM;
	}
	new_sa = 1;

update_sa:
	if (sa_param->auth_present == XFRMA_AUTH_PRESENT)
		auth = &sa_param->auth_alg.alg;
	else if (sa_param->auth_present == XFRMA_AUTH_TRUNC_PRESENT)
		auth_trunc = &sa_param->auth_alg.alg_trunc;

	if (sa_param->ciph_present)
		ciph = &sa_param->ciph_alg;

	if (!ciph || (!auth && !auth_trunc) || !sa_info) {
		ret = -ENOTSUP;
		goto quit;
	}

	if (auth) {
		auth_entry = xfm_auth_support_by_nm(auth->alg_name);
		if (!auth_entry) {
			ret = -ENOTSUP;
			goto quit;
		}
	} else {
		auth_entry = xfm_auth_support_by_nm(auth_trunc->alg_name);
		if (!auth_entry) {
			ret = -ENOTSUP;
			goto quit;
		}
	}

	ciph_entry = xfm_ciph_support_by_nm(ciph->alg_name);
	if (!ciph_entry) {
		ret = -ENOTSUP;
		goto quit;
	}

	sa_entry->seq = 0;
	sa_entry->cipher_key_len = ciph->alg_key_len;
	rte_memcpy(sa_entry->cipher_key, ciph->alg_key,
		sa_entry->cipher_key_len);

	if (auth) {
		sa_entry->auth_key_len = auth->alg_key_len;
		rte_memcpy(sa_entry->auth_key, auth->alg_key,
			sa_entry->auth_key_len);
	} else {
		sa_entry->auth_key_len = auth_trunc->alg_key_len;
		rte_memcpy(sa_entry->auth_key, auth_trunc->alg_key,
			sa_entry->auth_key_len);
	}

	rte_memcpy(&sa_entry->src, &sa_info->saddr,
		sizeof(xfrm_address_t));
	rte_memcpy(&sa_entry->dst, &sa_info->id.daddr,
		sizeof(xfrm_address_t));
	if (sa_info->family == AF_INET) {
		if (sa_info->mode == XFRM_MODE_TRANSPORT) {
			sa_entry->sa_flags = IP4_TRANSPORT;
		} else if (sa_info->mode == XFRM_MODE_TUNNEL) {
			sa_entry->sa_flags = IP4_TUNNEL;
		} else {
			RTE_LOG(ERR, pre_ld,
				"unsupported xfrm mode(%d)\n",
				sa_info->mode);
			ret = -ENOTSUP;
			goto quit;
		}
	} else if (sa_info->family == AF_INET6) {
		if (sa_info->mode == XFRM_MODE_TRANSPORT) {
			sa_entry->sa_flags = IP6_TRANSPORT;
		} else if (sa_info->mode == XFRM_MODE_TUNNEL) {
			sa_entry->sa_flags = IP6_TUNNEL;
		} else {
			RTE_LOG(ERR, pre_ld,
				"unsupported xfrm mode(%d)\n",
				sa_info->mode);
			ret = -ENOTSUP;
			goto quit;
		}
	} else {
		RTE_LOG(ERR, pre_ld,
			"unsupported xfrm family(%d)\n",
			sa_info->family);
		ret = -ENOTSUP;
		goto quit;
	}
	sa_entry->family = sa_info->family;

	sa_entry->sess_conf.action_type =
		RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL;
	sa_entry->sess_conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
	sa_entry->sess_conf.ipsec.spi = spi;
	sa_entry->sess_conf.ipsec.salt = (uint32_t)rte_rand();
	if (sa_entry->seq)
		sa_entry->sess_conf.ipsec.options.esn = 1;
	sa_entry->sess_conf.ipsec.options.udp_encap = 0;
	sa_entry->sess_conf.ipsec.options.copy_dscp = 1;
	if (sa_info->mode == XFRM_MODE_TUNNEL)
		sa_entry->sess_conf.ipsec.options.ecn = 1;

	sa_entry->sess_conf.ipsec.direction =
		RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
	sa_entry->sess_conf.ipsec.proto =
		RTE_SECURITY_IPSEC_SA_PROTO_ESP;
	if (sa_info->mode == XFRM_MODE_TUNNEL) {
		sa_entry->sess_conf.ipsec.mode =
			RTE_SECURITY_IPSEC_SA_MODE_TUNNEL;
	} else if (sa_info->mode == XFRM_MODE_TRANSPORT) {
		sa_entry->sess_conf.ipsec.mode =
			RTE_SECURITY_IPSEC_SA_MODE_TRANSPORT;
	} else {
		RTE_LOG(ERR, pre_ld,
			"unsupported xfrm mode(%d)\n",
			sa_info->mode);
		ret = -ENOTSUP;
		goto quit;
	}

	if (sa_info->mode == XFRM_MODE_TUNNEL) {
		tunnel_param = &sa_entry->sess_conf.ipsec.tunnel;
		if (sa_info->family == AF_INET) {
			tunnel_param->type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
			rte_memcpy(&tunnel_param->ipv4.src_ip,
				&sa_info->saddr.a4, 4);
			rte_memcpy(&tunnel_param->ipv4.dst_ip,
				&sa_info->id.daddr.a4, 4);
			tunnel_param->ipv4.dscp = 0;
			tunnel_param->ipv4.df = 0;
			tunnel_param->ipv4.ttl = IPDEFTTL;
		} else if (sa_info->family == AF_INET6) {
			tunnel_param->type = RTE_SECURITY_IPSEC_TUNNEL_IPV6;
			rte_memcpy(&tunnel_param->ipv6.src_addr,
				&sa_info->saddr.a6, 16);
			rte_memcpy(&tunnel_param->ipv6.dst_addr,
				&sa_info->id.daddr.a6, 16);
			tunnel_param->ipv6.dscp = 0;
			tunnel_param->ipv6.flabel = 0;
			tunnel_param->ipv6.hlimit = IPDEFTTL;
		} else {
			RTE_LOG(ERR, pre_ld,
				"unsupported xfrm family(%d)\n",
				sa_info->family);
			ret = -ENOTSUP;
			goto quit;
		}
	}
	sa_entry->sess_conf.ipsec.replay_win_sz = sa_info->replay_window;

	sa_entry->auth_xform.next = NULL;
	sa_entry->auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	sa_entry->auth_xform.auth.algo = auth_entry->algo;
	sa_entry->auth_xform.auth.key.data = sa_entry->auth_key;
	sa_entry->auth_xform.auth.key.length = sa_entry->auth_key_len;
	/**Digest len is identified by IPSec protocal offload engine.*/
	if (auth_entry->algo == RTE_CRYPTO_AUTH_SHA256_HMAC)
		sa_entry->auth_xform.auth.digest_length = 16;
	else
		sa_entry->auth_xform.auth.digest_length = 0;

	sa_entry->ciph_xform.next = NULL;
	sa_entry->ciph_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	sa_entry->ciph_xform.cipher.algo = ciph_entry->algo;
	sa_entry->ciph_xform.cipher.key.data = sa_entry->cipher_key;
	sa_entry->ciph_xform.cipher.key.length = sa_entry->cipher_key_len;
	/**IV is identified by IPSec protocal offload engine/frames.*/
	sa_entry->ciph_xform.cipher.iv.offset = 0;
	sa_entry->ciph_xform.cipher.iv.length = 0;

	sa_entry->session.type = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL;

	sa_entry->created_cyc = rte_get_timer_cycles();

quit:
	if (ret) {
		if (new_sa)
			rte_free(sa_entry);
		return ret;
	}

	if (!new_sa)
		return 0;

	if (!LIST_FIRST(&cntx->sa_list)) {
		LIST_INSERT_HEAD(&cntx->sa_list, sa_entry, next);
	} else {
		curr = LIST_FIRST(&cntx->sa_list);
		while (LIST_NEXT(curr, next))
			curr = LIST_NEXT(curr, next);
		LIST_INSERT_AFTER(curr, sa_entry, next);
	}
	sa_entry->sec_id = -1;

	return 0;
}

static void
xfm_sa_entry_dir_config(struct pre_ld_ipsec_sa_entry *sa_entry,
	int is_inbound)
{
	sa_entry->sess_conf.ipsec.direction = is_inbound ?
		RTE_SECURITY_IPSEC_SA_DIR_INGRESS :
		RTE_SECURITY_IPSEC_SA_DIR_EGRESS;

	if (is_inbound) {
		sa_entry->sess_conf.crypto_xform = &sa_entry->auth_xform;
		sa_entry->auth_xform.next = &sa_entry->ciph_xform;

		sa_entry->auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;

		sa_entry->ciph_xform.next = NULL;
		sa_entry->ciph_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
	} else {
		sa_entry->sess_conf.crypto_xform = &sa_entry->ciph_xform;
		sa_entry->ciph_xform.next = &sa_entry->auth_xform;

		sa_entry->ciph_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;

		sa_entry->auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
	}
}

static int
process_notif_sa(const struct nlmsghdr *nh, int len,
	int update)
{
	struct xfrm_usersa_info *sa_info;
	struct xfm_ipsec_sa_params sa_params;
	struct nlattr *na;
	int msg_len = 0;
	int ret = 0;

	RTE_LOG(INFO, pre_ld, "XFRM notification type(%d)\n",
		nh->nlmsg_type);

	memset(&sa_params, 0, sizeof(struct xfm_ipsec_sa_params));

	sa_info = (void *)NLMSG_DATA(nh);

	dump_sa_from_xfrm(sa_info);
	na = (void *)((uint8_t *)NLMSG_DATA(nh) +
		NLMSG_ALIGN(sizeof(*sa_info)));

	memset(&sa_params, 0, sizeof(sa_params));

	/* get SA */
	/* attributes total length in the nh buffer */
	msg_len = (uint64_t)nh - (uint64_t)na + len;
	ret = nl_parse_attrs(na, msg_len, &sa_params);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"XFRM netlink parse attrs err(%d)\n",
			ret);
		return ret;
	}

	ret = xfm_to_sa_entry(&sa_params, sa_info, update);
	/** We can't apply SA to HW now until SA is associated to SP
	 * to get direction.
	 */

	return ret;
}

static int
process_del_sa_entry(struct pre_ld_ipsec_sa_entry *sa)
{
	int ret = 0;
	void *ctx;

	LIST_REMOVE(sa, next);
	if (sa->sec_id >= 0) {
		ctx = rte_cryptodev_get_sec_ctx(sa->sec_id);
		ret = rte_security_session_destroy(ctx,
				sa->session.security.ses);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"%s: destroy session failed(%d)\n",
				__func__, ret);
		}
	}
	RTE_LOG(INFO, pre_ld,
		"Delete SA %s spi(%08x), lifetime(%.2f s)\n",
		sa->sess_conf.ipsec.direction ==
		RTE_SECURITY_IPSEC_SA_DIR_INGRESS ?
		"IN" : "OUT", sa->sess_conf.ipsec.spi,
		(rte_get_timer_cycles() - sa->created_cyc) /
		(s_xfm_cycs_per_us * 1000 * 1000));
	rte_free(sa);

	return ret;
}

static int process_del_sa(const struct nlmsghdr *nh)
{
	struct xfrm_usersa_id *usersa_id;
	struct pre_ld_ipsec_cntx *cntx = xfm_get_cntx();
	struct pre_ld_ipsec_sa_entry *curr;
	uint8_t addr[16];
	char addr_info[128];
	uint16_t info_offset = 0, size = 0;
	uint32_t cpu_spi;
	int ret;

	usersa_id = NLMSG_DATA(nh);

	if (usersa_id->family == AF_INET)
		size = sizeof(rte_be32_t);
	else if (usersa_id->family == AF_INET6)
		size = 16;

	cpu_spi = rte_be_to_cpu_32(usersa_id->spi);

	curr = LIST_FIRST(&cntx->sa_list);

	while (curr) {
		if (usersa_id->family == curr->family &&
			!memcmp(&usersa_id->daddr, &curr->dst, size) &&
			cpu_spi == curr->sess_conf.ipsec.spi)
			break;

		curr = LIST_NEXT(curr, next);
	}

	if (curr) {
		if (curr->sp) {
			ret = process_del_policy_entry(curr->sp);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"%s: Delete policy entry failed(%d)\n",
					__func__, ret);
			}
		}

		return process_del_sa_entry(curr);
	}

	rte_memcpy(addr, &usersa_id->daddr, size);
	if (usersa_id->family == AF_INET) {
		sprintf(addr_info, "IPV4 dst: %d.%d.%d.%d",
			addr[0], addr[1], addr[2], addr[3]);
	} else {
		info_offset += sprintf(addr_info, "IPV6 dst: ");
		info_offset += sprintf(&addr_info[info_offset],
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			addr[0], addr[1], addr[2], addr[3],
			addr[4], addr[5], addr[6], addr[7]);
		info_offset += sprintf(&addr_info[info_offset],
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			addr[8], addr[9], addr[10], addr[11],
			addr[12], addr[13], addr[14], addr[15]);
	}

	RTE_LOG(INFO, pre_ld,
		"XFRM delete spi(0x%08x), %s failed\n",
		rte_be_to_cpu_32(usersa_id->spi), addr_info);

	return -ENODATA;
}

static void
dump_new_policy(const struct xfrm_userpolicy_info *pol_info)
{
	char pol_dump[DUMP_BUF_SIZE];
	static const char * const p_dir[] = {
		"IN",
		"OUT",
		"FWD",
		"MASK"
	};
	int offset = 0;

	if (pol_info->dir > XFRM_POLICY_MAX) {
		RTE_LOG(ERR, pre_ld, "Invalid policy direction(%d)\n",
			pol_info->dir);
		return;
	}

	offset += sprintf(&pol_dump[offset],
		"New %s policy[%d] action(%d) flags(%d):\n",
		p_dir[pol_info->dir], pol_info->index,
		pol_info->action, pol_info->flags);
	RTE_VERIFY(offset < DUMP_BUF_SIZE);

	offset += add_dump_selector_info(&pol_dump[offset],
		DUMP_BUF_SIZE - offset, 0, &pol_info->sel,
		DUMP_PREFIX);
	RTE_VERIFY(offset < DUMP_BUF_SIZE);

	RTE_LOG(INFO, pre_ld, "%s", pol_dump);
}

static int
xfm_steer_sp_flow(struct pre_ld_ipsec_sp_entry *sp,
	rte_be32_t spi, struct rte_flow *flow)
{
	int ret, idx = 0;
	struct pre_ld_xfm_flow *xfm_flow, *txfm_flow;
	struct pre_ld_xfm_flow_list *flow_list = &s_xfm_flow_list;

	if (sp->family == AF_INET &&
		(sp->dir == XFRM_POLICY_OUT ||
		s_ipsec_ib_flow_ip_addr_extract)) {
		sp->flow_item[idx].type = RTE_FLOW_ITEM_TYPE_IPV4;
		rte_memcpy(&sp->ipv4_spec.hdr.src_addr, &sp->src,
			sizeof(rte_be32_t));
		rte_memcpy(&sp->ipv4_spec.hdr.dst_addr, &sp->dst,
			sizeof(rte_be32_t));
		sp->ipv4_mask.hdr.src_addr = 0xffffffff;
		sp->ipv4_mask.hdr.dst_addr = 0xffffffff;
		sp->flow_item[idx].spec = &sp->ipv4_spec;
		sp->flow_item[idx].mask = &sp->ipv4_mask;
		idx++;
	} else if (sp->family == AF_INET6 &&
		(sp->dir == XFRM_POLICY_OUT ||
		s_ipsec_ib_flow_ip_addr_extract)) {
		sp->flow_item[idx].type = RTE_FLOW_ITEM_TYPE_IPV6;
		rte_memcpy(sp->ipv6_spec.hdr.src_addr, &sp->src, 16);
		rte_memcpy(sp->ipv6_spec.hdr.dst_addr, &sp->dst, 16);
		memset(sp->ipv6_mask.hdr.src_addr, 0xff, 16);
		memset(sp->ipv6_mask.hdr.dst_addr, 0xff, 16);
		sp->flow_item[idx].spec = &sp->ipv6_spec;
		sp->flow_item[idx].mask = &sp->ipv6_mask;
		idx++;
	}

	if (sp->dir == XFRM_POLICY_IN) {
		sp->flow_item[idx].type = RTE_FLOW_ITEM_TYPE_ESP;
		sp->esp_spec.hdr.spi = spi;
		sp->esp_mask.hdr.spi = 0xffffffff;
		sp->flow_item[idx].spec = &sp->esp_spec;
		sp->flow_item[idx].mask = &sp->esp_mask;
		idx++;
	}
	if (!idx) {
		RTE_LOG(ERR, pre_ld,
			"%s: Invalid IP family(%d) or direction(%d)\n",
			__func__, sp->family, sp->dir);
		return -EINVAL;
	}

	sp->flow_item[idx].type = RTE_FLOW_ITEM_TYPE_END;

	sp->action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	sp->action[0].conf = &sp->ingress_queue;
	sp->action[1].type = RTE_FLOW_ACTION_TYPE_END;

	sp->flow = flow;

	if (!sp->flow) {
		ret = pre_ld_configure_sec_path(sp);
		if (ret)
			return ret;
		ret = xfm_sp_flow_hw_create(sp);
	} else {
		ret = pre_ld_attach_sec_path(sp);
		if (ret)
			return ret;
		RTE_TAILQ_FOREACH_SAFE(xfm_flow, flow_list, next, txfm_flow) {
			if (xfm_flow->flow == sp->flow) {
				xfm_flow->flow_ref++;
				break;
			}
		}
	}

	return ret;
}

static int
xfm_create_session_by_sa(struct pre_ld_ipsec_sa_entry *sa,
	uint8_t dev_id, struct rte_mempool *mp)
{
	struct rte_security_ctx *ctx;
	struct rte_ipsec_session *ips = &sa->session;

	if (ips->type != RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL)
		return -ENOTSUP;

	ctx = rte_cryptodev_get_sec_ctx(dev_id);

	ips->security.ses = rte_security_session_create(ctx,
		&sa->sess_conf, mp);
	if (!ips->security.ses) {
		RTE_LOG(ERR, pre_ld, "Lookaside Session init failed\n");
		return -EINVAL;
	}
	sa->sec_id = dev_id;

	return 0;
}

static int
xfm_apply_sa(struct pre_ld_ipsec_sa_entry *sa,
	const struct xfrm_userpolicy_info *pol_info,
	uint8_t sec_dev_id, struct rte_mempool *mp)
{
	xfm_sa_entry_dir_config(sa,
		pol_info->dir == XFRM_POLICY_IN ? 1 : 0);
	return xfm_create_session_by_sa(sa, sec_dev_id, mp);
}

static int
xfm_sa_sp_associate(struct pre_ld_ipsec_sp_entry *sp,
	struct pre_ld_ipsec_sa_entry *sa, struct rte_flow *flow)
{
	int ret;

	ret = xfm_steer_sp_flow(sp,
		rte_cpu_to_be_32(sa->sess_conf.ipsec.spi), flow);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Steer policy by HW failed(%d)\n", ret);
		return ret;
	}

	sp->sa = sa;
	sa->sp = sp;

	return 0;
}

static void
xfm_insert_new_policy(struct pre_ld_ipsec_sp_entry *sp,
	const struct xfrm_userpolicy_info *pol_info,
	const xfrm_address_t *saddr, const xfrm_address_t *daddr,
	int af)
{
	struct pre_ld_ipsec_sp_entry *curr;
	struct pre_ld_ipsec_cntx *cntx = xfm_get_cntx();
	struct pre_ld_ipsec_sp_head *head;
	const uint8_t *src_ip4, *dst_ip4;
	const rte_be16_t *src_ip6, *dst_ip6;
	char add_str[1024];
	int offset;

	if (pol_info->dir == XFRM_POLICY_OUT) {
		if (af == AF_INET)
			head = &cntx->sp_ipv4_out_list;
		else
			head = &cntx->sp_ipv6_out_list;
	} else {
		if (af == AF_INET)
			head = &cntx->sp_ipv4_in_list;
		else
			head = &cntx->sp_ipv6_in_list;
	}
	curr = LIST_FIRST(head);

	rte_memcpy(&sp->src, saddr, sizeof(xfrm_address_t));
	rte_memcpy(&sp->dst, daddr, sizeof(xfrm_address_t));
	src_ip4 = (const void *)saddr;
	dst_ip4 = (const void *)daddr;
	src_ip6 = (const void *)saddr;
	dst_ip6 = (const void *)daddr;
	if (af == AF_INET) {
		offset = sprintf(add_str, "%s", "IPv4 src/dst: ");
		offset = sprintf(&add_str[offset],
			"%d.%d.%d.%d/%d.%d.%d.%d",
			src_ip4[0], src_ip4[1],
			src_ip4[2], src_ip4[3],
			dst_ip4[0], dst_ip4[1],
			dst_ip4[2], dst_ip4[3]);
	} else {
		offset = sprintf(add_str, "%s", "IPv6 src/dst: ");
		offset = sprintf(&add_str[offset],
			"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x/",
			src_ip6[0], src_ip6[1],
			src_ip6[2], src_ip6[3],
			src_ip6[4], src_ip6[5],
			src_ip6[6], src_ip6[7]);
		offset = sprintf(&add_str[offset],
			"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
			dst_ip6[0], dst_ip6[1],
			dst_ip6[2], dst_ip6[3],
			dst_ip6[4], dst_ip6[5],
			dst_ip6[6], dst_ip6[7]);
	}
	RTE_LOG(INFO, pre_ld, "New %s %s\n",
		pol_info->dir == XFRM_POLICY_OUT ?
		"Outbound policy" : "Inbound policy",
		add_str);
	sp->priority = pol_info->priority;
	sp->index = pol_info->index;
	sp->family = af;
	sp->sa = NULL;
	sp->dir = pol_info->dir;

	if (!curr) {
		LIST_INSERT_HEAD(head, sp, next);
	} else {
		while (LIST_NEXT(curr, next))
			curr = LIST_NEXT(curr, next);
		LIST_INSERT_AFTER(curr, sp, next);
	}
	sp->head = head;
}

static struct rte_flow *
xfm_find_policy_flow_by_rule(uint32_t spi,
	xfrm_address_t *src, xfrm_address_t *dst, int af)
{
	struct pre_ld_ipsec_sp_entry *curr;
	struct pre_ld_ipsec_cntx *cntx = xfm_get_cntx();
	struct pre_ld_ipsec_sp_head *head;

	if (spi == INVALID_ESP_SPI) {
		if (af == AF_INET)
			head = &cntx->sp_ipv4_out_list;
		else
			head = &cntx->sp_ipv6_out_list;
	} else {
		if (af == AF_INET)
			head = &cntx->sp_ipv4_in_list;
		else
			head = &cntx->sp_ipv6_in_list;
	}
	curr = LIST_FIRST(head);

	while (curr) {
		if (memcmp(&curr->src, src, sizeof(xfrm_address_t)))
			goto continue_next;
		if (memcmp(&curr->dst, dst, sizeof(xfrm_address_t)))
			goto continue_next;
		if (spi == INVALID_ESP_SPI)
			break;
		if (curr->sa &&
			curr->sa->sess_conf.ipsec.spi == spi)
			break;
continue_next:
		curr = LIST_NEXT(curr, next);
	}

	if (curr)
		return curr->flow;

	return NULL;
}

static int
process_new_policy(const struct nlmsghdr *nh,
	uint8_t sec_id, struct rte_mempool *mp)
{
#define MAX_SA_NUM 10
	struct xfrm_userpolicy_info *pol_info;
	struct rte_flow *flow;
	int ret = 0, af, offset = 0, num, i;
	xfrm_address_t saddr, daddr;
	uint32_t spi;
	struct pre_ld_ipsec_sa_entry *sas[MAX_SA_NUM], *sa = NULL;
	struct pre_ld_ipsec_sp_entry *sp;
	char addr_info[1024];

	pol_info = NLMSG_DATA(nh);

	if (pol_info->dir != XFRM_POLICY_IN &&
		pol_info->dir != XFRM_POLICY_OUT) {
		RTE_LOG(DEBUG, pre_ld,
			"Don't configure policy (dir=%d)\n",
			pol_info->dir);
		return 0;
	}

	dump_new_policy(pol_info);

	ret = do_spdget(pol_info->index, &saddr, &daddr, &af);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"Policy doesn't exist in kernel SPDB(%d)\n",
			ret);
		return ret;
	}

	if (af == AF_INET) {
		uint8_t *src4, *dst4;

		src4 = (void *)&saddr;
		dst4 = (void *)&daddr;
		offset = sprintf(addr_info, "src(%d.%d.%d.%d)/",
			src4[0], src4[1], src4[2], src4[3]);
		offset += sprintf(&addr_info[offset],
			"dst(%d.%d.%d.%d)",
			dst4[0], dst4[1], dst4[2], dst4[3]);
	} else if (af == AF_INET6) {
		uint16_t *src6, *dst6;

		src6 = (void *)&saddr;
		dst6 = (void *)&daddr;
		offset = sprintf(addr_info,
			"src(%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x)/",
			src6[0], src6[1], src6[2], src6[3],
			src6[4], src6[5], src6[6], src6[7]);
		offset += sprintf(&addr_info[offset],
			"dst(%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x)",
			dst6[0], dst6[1], dst6[2], dst6[3],
			dst6[4], dst6[5], dst6[6], dst6[7]);
	} else {
		RTE_LOG(ERR, pre_ld, "Invalid AF(%d) got by SPD\n", af);
		return -EINVAL;
	}

	num = xfm_find_sa_by_addrs(&saddr, &daddr, af, sas, MAX_SA_NUM);
	if (num <= 0) {
		/** TO DO: Add SP to pending list.*/
		RTE_LOG(ERR, pre_ld, "No SA found by %s\n", addr_info);
		return -ENOTSUP;
	}
	for (i = 0; i < num; i++) {
		if (!sas[i]->sp) {
			sa = sas[i];
			break;
		}
	}
	if (!sa) {
		RTE_LOG(ERR, pre_ld,
			"%d SA(s) have been associated to SP\n", num);
		return -EINVAL;
	}

	sprintf(&addr_info[offset], "/spi(%08x)",
		sa->sess_conf.ipsec.spi);
	RTE_LOG(INFO, pre_ld, "Found SA: %s\n", addr_info);

	if (pol_info->dir == XFRM_POLICY_IN) {
		spi = sa->sess_conf.ipsec.spi;
	} else {
		spi = INVALID_ESP_SPI;
		/** Use selector addresses as rule of policy out.*/
		rte_memcpy(&saddr, &pol_info->sel.saddr,
			sizeof(xfrm_address_t));
		rte_memcpy(&daddr, &pol_info->sel.daddr,
			sizeof(xfrm_address_t));
	}
	flow = xfm_find_policy_flow_by_rule(spi, &saddr, &daddr, af);

	sp = rte_zmalloc(NULL, sizeof(struct pre_ld_ipsec_sp_entry),
		RTE_CACHE_LINE_SIZE);
	if (!sp) {
		RTE_LOG(ERR, pre_ld, "Malloc sp failed.\n");
		return -ENOMEM;
	}

	xfm_insert_new_policy(sp, pol_info, &saddr, &daddr, af);

	rte_memcpy(&sp->sel_src, &pol_info->sel.saddr,
		sizeof(xfrm_address_t));
	rte_memcpy(&sp->sel_dst, &pol_info->sel.daddr,
		sizeof(xfrm_address_t));

	sp->crypt_id = sec_id;

	ret = 0;
	if (!sa->session.security.ses) {
		ret = xfm_apply_sa(sa, pol_info, sec_id, mp);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"Create session failed(%d)\n", ret);
		} else if (!sa->session.security.ses) {
			RTE_LOG(ERR, pre_ld,
				"Security session not allocated\n");
			ret = -ENOBUFS;
		}
	}

	if (!ret) {
		ret = xfm_sa_sp_associate(sp, sa, flow);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"SA/SP associate failed!\n");

			return ret;
		}
		if (s_kernel_sp_sa_clear) {
			ret = do_spddel(pol_info->index);
			if (ret) {
				RTE_LOG(ERR, pre_ld,
					"Delete policy[%d] in kernel failed(%d)\n",
					pol_info->index, ret);
			} else {
				RTE_LOG(INFO, pre_ld,
					"Delete policy[%d] in kernel successfully\n",
					pol_info->index);
			}
			if (sp->sa) {
				spi = sp->sa->sess_conf.ipsec.spi;
				ret = do_saddel(spi);
				if (ret) {
					RTE_LOG(ERR, pre_ld,
						"Delete SA(spi=%08x) in kernel failed(%d)\n",
						spi, ret);
				} else {
					RTE_LOG(INFO, pre_ld,
						"Delete SA(spi=%08x) in kernel successfully\n",
						spi);
				}
			}
		}
	}

	return ret;
}

static int process_del_policy(const struct nlmsghdr *nh)
{
	struct xfrm_userpolicy_id *pol_id;
	struct pre_ld_ipsec_cntx *cntx = xfm_get_cntx();
	struct pre_ld_ipsec_sp_head *head;
	struct pre_ld_ipsec_sp_entry *curr;
	void *src, *dst;
	uint64_t size, offset = 0;
	char addr_info[256], src_info[16], dst_info[16];

	pol_id = NLMSG_DATA(nh);

	RTE_LOG(INFO, pre_ld, "XFRM del policy dir:%d\n",
		pol_id->dir);

	/* we handle only in/out policies */
	if (pol_id->dir != XFRM_POLICY_OUT &&
		pol_id->dir != XFRM_POLICY_IN)
		return -EBADMSG;

	if (pol_id->sel.family == AF_INET &&
		pol_id->dir == XFRM_POLICY_IN) {
		head = &cntx->sp_ipv4_in_list;
		size = sizeof(rte_be32_t);
	} else if (pol_id->sel.family == AF_INET &&
		pol_id->dir == XFRM_POLICY_OUT) {
		head = &cntx->sp_ipv4_out_list;
		size = sizeof(rte_be32_t);
	} else if (pol_id->sel.family == AF_INET6 &&
		pol_id->dir == XFRM_POLICY_IN) {
		head = &cntx->sp_ipv6_in_list;
		size = 16;
	} else if (pol_id->sel.family == AF_INET6 &&
		pol_id->dir == XFRM_POLICY_OUT) {
		head = &cntx->sp_ipv6_out_list;
		size = 16;
	} else {
		/* we handle only in/out policies */
		RTE_LOG(ERR, pre_ld,
			"XFRM del policy dir(%d)/family(%d) unsupport\n",
			pol_id->dir, pol_id->sel.family);
		return -EINVAL;
	}

	curr = LIST_FIRST(head);

	while (curr) {
		src = &curr->sel_src;
		dst = &curr->sel_dst;
		if (!memcmp(src, &pol_id->sel.saddr, size) &&
			!memcmp(dst, &pol_id->sel.daddr, size) &&
			curr->index == pol_id->index)
			break;
		curr = LIST_NEXT(curr, next);
	}

	if (curr)
		return process_del_policy_entry(curr);

	rte_memcpy(src_info, &pol_id->sel.saddr, size);
	rte_memcpy(dst_info, &pol_id->sel.daddr, size);

	if (pol_id->sel.family == AF_INET) {
		sprintf(addr_info,
			"src/dst:%d.%d.%d.%d/%d.%d.%d.%d",
			src_info[0], src_info[1], src_info[2], src_info[3],
			dst_info[0], dst_info[1], dst_info[2], dst_info[3]);
	} else {
		offset += sprintf(&addr_info[offset],
			"src:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			src_info[0], src_info[1], src_info[2], src_info[3],
			src_info[4], src_info[5], src_info[6], src_info[7]);
		offset += sprintf(&addr_info[offset],
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x ",
			src_info[8], src_info[9], src_info[10], src_info[11],
			src_info[12], src_info[13], src_info[14], src_info[15]);
		offset += sprintf(&addr_info[offset],
			"dst:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			dst_info[0], dst_info[1], dst_info[2], dst_info[3],
			dst_info[4], dst_info[5], dst_info[6], dst_info[7]);
		offset += sprintf(&addr_info[offset],
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
			dst_info[8], dst_info[9], dst_info[10], dst_info[11],
			dst_info[12], dst_info[13], dst_info[14], dst_info[15]);
	}

	RTE_LOG(ERR, pre_ld,
		"XFRM del policy not found dir(%d)/family(%d) %s\n",
		pol_id->dir, pol_id->sel.family,
		addr_info);

	return -ENODATA;
}

static int process_flush_policy(void)
{
	return 0;
}

static int
resolve_xfrm_notif(const struct nlmsghdr *nh, int len,
	uint16_t sec_id, struct rte_mempool *mp)
{
	int ret = 0;
	struct xfrm_usersa_info *xsinfo = NULL;
	struct xfrm_user_expire *xexp = NULL;
	struct xfrm_userpolicy_info	*xpol = NULL;
	struct xfrm_user_polexpire *xpexp = NULL;
	uint8_t *src, *dst;
	uint16_t *src16, *dst16;
	char src_addr[128], dst_addr[128];

	switch (nh->nlmsg_type) {
	case XFRM_MSG_UPDSA:
		RTE_LOG(INFO, pre_ld, "XFRM update SA start\n");
		ret = process_notif_sa(nh, len, 1);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"XFRM update SA failed(%d)\n\n", ret);
		} else {
			RTE_LOG(INFO, pre_ld, "XFRM update SA done\n\n");
		}
		break;
	case XFRM_MSG_NEWSA:
		RTE_LOG(INFO, pre_ld, "XFRM new SA start\n");
		ret = process_notif_sa(nh, len, 0);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"XFRM new SA failed(%d)\n\n", ret);
		} else {
			RTE_LOG(INFO, pre_ld, "XFRM new SA done\n\n");
		}
		break;
	case XFRM_MSG_DELSA:
		RTE_LOG(INFO, pre_ld, "XFRM delete SA start\n");
		ret = process_del_sa(nh);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"XFRM delete SA failed(%d)\n\n", ret);
		} else {
			RTE_LOG(INFO, pre_ld, "XFRM delete SA done\n\n");
		}
		break;
	case XFRM_MSG_FLUSHSA:
		RTE_LOG(INFO, pre_ld, "XFRM flush SA start\n");
		ret = 0;
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"XFRM flush SA failed(%d)\n\n", ret);
		} else {
			RTE_LOG(INFO, pre_ld, "XFRM flush SA done\n\n");
		}
		break;
	case XFRM_MSG_UPDPOLICY:
		RTE_LOG(INFO, pre_ld, "XFRM update policy start\n");
		ret = process_new_policy(nh, sec_id, mp);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"XFRM update policy failed(%d)\n\n", ret);
		} else {
			RTE_LOG(INFO, pre_ld, "XFRM update policy done\n\n");
		}
		break;
	case XFRM_MSG_NEWPOLICY:
		RTE_LOG(INFO, pre_ld, "XFRM new policy start\n");
		ret = process_new_policy(nh, sec_id, mp);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"XFRM new policy failed(%d)\n\n", ret);
		} else {
			RTE_LOG(INFO, pre_ld, "XFRM new policy done\n\n");
		}
		break;
	case XFRM_MSG_DELPOLICY:
		RTE_LOG(INFO, pre_ld, "XFRM delete policy start\n");
		ret = process_del_policy(nh);
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"XFRM delete policy failed(%d)\n\n", ret);
		} else {
			RTE_LOG(INFO, pre_ld, "XFRM delete policy done\n\n");
		}
		break;
	case XFRM_MSG_GETPOLICY:
		RTE_LOG(INFO, pre_ld, "XFRM get policy start\n");
		ret = 0;
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"XFRM get policy failed(%d)\n\n", ret);
		} else {
			RTE_LOG(INFO, pre_ld, "XFRM get policy done\n\n");
		}
		break;
	case XFRM_MSG_POLEXPIRE:
		xpexp = NLMSG_DATA(nh);
		xpol = &xpexp->pol;
		if (xpol->sel.family == AF_INET) {
			src = (void *)&xpol->sel.saddr;
			dst = (void *)&xpol->sel.daddr;
			sprintf(src_addr, "%d.%d.%d.%d",
				src[0], src[1], src[2], src[3]);
			sprintf(dst_addr, "%d.%d.%d.%d",
				dst[0], dst[1], dst[2], dst[3]);
		} else if (xpol->sel.family == AF_INET6) {
			src16 = (void *)&xpol->sel.saddr;
			dst16 = (void *)&xpol->sel.daddr;
			sprintf(src_addr,
				"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
				src16[0], src16[1], src16[2], src16[3],
				src16[4], src16[5], src16[6], src16[7]);
			sprintf(dst_addr,
				"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
				dst16[0], dst16[1], dst16[2], dst16[3],
				dst16[4], dst16[5], dst16[6], dst16[7]);
		} else {
			sprintf(src_addr, "Invalid family(%d)",
				xpol->sel.family);
			sprintf(dst_addr, "Invalid family(%d)",
				xpol->sel.family);
		}
		RTE_LOG(INFO, pre_ld,
			"XFRM %s SP(src=%s/dst=%s) expire\n",
			xpol->dir == XFRM_POLICY_IN ? "in" : "out",
			src_addr, dst_addr);
		break;
	case XFRM_MSG_FLUSHPOLICY:
		RTE_LOG(INFO, pre_ld, "XFRM flush policy start\n");
		ret = process_flush_policy();
		if (ret) {
			RTE_LOG(ERR, pre_ld,
				"XFRM flush policy failed(%d)\n\n", ret);
		} else {
			RTE_LOG(INFO, pre_ld, "XFRM flush policy done\n\n");
		}
		break;
	case XFRM_MSG_EXPIRE:
		xexp = NLMSG_DATA(nh);
		xsinfo = &xexp->state;
		if (xsinfo->family == AF_INET) {
			src = (void *)&xsinfo->saddr;
			dst = (void *)&xsinfo->id.daddr;
			sprintf(src_addr, "%d.%d.%d.%d",
				src[0], src[1], src[2], src[3]);
			sprintf(dst_addr, "%d.%d.%d.%d",
				dst[0], dst[1], dst[2], dst[3]);
		} else if (xsinfo->family == AF_INET6) {
			src16 = (void *)&xsinfo->saddr;
			dst16 = (void *)&xsinfo->id.daddr;
			sprintf(src_addr,
				"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
				src16[0], src16[1], src16[2], src16[3],
				src16[4], src16[5], src16[6], src16[7]);
			sprintf(dst_addr,
				"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
				dst16[0], dst16[1], dst16[2], dst16[3],
				dst16[4], dst16[5], dst16[6], dst16[7]);
		} else {
			sprintf(src_addr, "Invalid family(%d)", xsinfo->family);
			sprintf(dst_addr, "Invalid family(%d)", xsinfo->family);
		}
		RTE_LOG(INFO, pre_ld,
			"XFRM SA(src=%s/dst=%s/spi=0x%08x) expire\n",
			src_addr, dst_addr, rte_be_to_cpu_32(xsinfo->id.spi));
		break;
	default:
		RTE_LOG(INFO, pre_ld,
			"\nXFRM msg type(%d) not support\n\n",
			nh->nlmsg_type);
		ret = 0;
	}

	return ret;
}

static void
xfm_calculate_cycles_per_us(void)
{
	uint64_t start_cycles, end_cycles;

	start_cycles = rte_get_timer_cycles();
	rte_delay_ms(1000);
	end_cycles = rte_get_timer_cycles();
	s_xfm_cycs_per_us = (end_cycles - start_cycles) / (1000 * 1000);
	RTE_LOG(INFO, pre_ld,
		"Cycles per us is: %ld\n",
		(unsigned long)s_xfm_cycs_per_us);
}

static void *xfrm_msg_loop(void *data)
{
	int xfrm_sd;
	int ret;
	int len = 0;
	char buf[4096];	/* XFRM messages receive buf */
	struct iovec iov = { buf, sizeof(buf) };
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct nlmsghdr *nh;
	cpu_set_t cpuset;
	const struct pre_ld_crypt_param *param = data;
	uint8_t sec_id = param->crypt_dev;
	struct rte_mempool *mp = param->sess_priv_pool;
	char *env;

	/* Set this cpu-affinity to CPU 0 */
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	ret = pthread_setaffinity_np(pthread_self(),
		sizeof(cpuset), &cpuset);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"XFRM thread set affinity failed(%d)\n",
			ret);
		pthread_exit(NULL);
	}

	memset(s_dump_prefix, ' ', sizeof(s_dump_prefix));

	xfrm_sd = create_nl_socket(NETLINK_XFRM, XFRMGRP_ACQUIRE |
				XFRMGRP_EXPIRE |
				XFRMGRP_SA |
				XFRMGRP_POLICY |
				XFRMGRP_REPORT);
	if (xfrm_sd < 0) {
		RTE_LOG(ERR, pre_ld, "XFRM open netlink failed(%d)\n",
			errno);
		pthread_exit(NULL);
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	xfm_calculate_cycles_per_us();

	env = getenv("IPSEC_IB_FLOW_IP_ADDR_EXTRACT");
	if (env)
		s_ipsec_ib_flow_ip_addr_extract = atoi(env);

	/* XFRM notification loop */
	while (1) {
		len = recvmsg(xfrm_sd, &msg, 0);
		if (len < 0 && errno != EINTR) {
			RTE_LOG(ERR, pre_ld,
				"XFRM receive socket(%d)\n",
				errno);
			break;
		} else if (errno == EINTR) {
			break;
		}

		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_type == NLMSG_ERROR) {
				RTE_LOG(ERR, pre_ld,
					"XFRM netlink message err(%d)\n",
					errno);
				break;
			}
			if (nh->nlmsg_flags & NLM_F_MULTI ||
				nh->nlmsg_type == NLMSG_DONE) {
				RTE_LOG(ERR, pre_ld,
					"XFRM multi-part messages not supported\n");
				break;
			}

			ret = resolve_xfrm_notif(nh, len, sec_id, mp);
			if (ret && ret != -EBADMSG)
				break;
		}
	}

	close(xfrm_sd);
	pthread_exit(NULL);

	return data;
}

int
xfrm_setup_msgloop(void *param)
{
	int ret;
	pthread_t tid;

	ret = pthread_create(&tid, NULL, xfrm_msg_loop, param);
	if (ret) {
		RTE_LOG(ERR, pre_ld,
			"XFRM message thread create failed(%d)\n",
			ret);
	}
	return ret;
}
