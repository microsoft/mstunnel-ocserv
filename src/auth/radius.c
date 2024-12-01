/*
 * Copyright (C) 2014-2016 Red Hat, Inc.
 * Copyright (C) 2016-2018 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vpn.h>
#include <ctype.h>
#include <arpa/inet.h> /* inet_ntop */
#include "radius.h"
#include "auth/common.h"
#include "str.h"
#include <ccan/hash/hash.h>

#ifdef HAVE_RADIUS

#include "common-config.h"

#ifdef LEGACY_RADIUS
#include <freeradius-client.h>
#else
#include <radcli/radcli.h>
#endif

#ifndef VENDOR_BIT_SIZE
#define VENDOR_BIT_SIZE 16
#define VENDOR_MASK 0xffff
#else
#define VENDOR_MASK 0xffffffff
#endif

#define VATTRID_SET(a, v) \
	((a) | ((uint64_t)((v) & VENDOR_MASK)) << VENDOR_BIT_SIZE)

#define RAD_GROUP_NAME PW_CLASS
/* Microsoft - RFC 2548 */
#define MS_PRIMARY_DNS_SERVER VATTRID_SET(28, 311)
#define MS_SECONDARY_DNS_SERVER VATTRID_SET(29, 311)
/* Roaring Penguin */
#define RP_UPSTREAM_SPEED_LIMIT VATTRID_SET(1, 10055)
#define RP_DOWNSTREAM_SPEED_LIMIT VATTRID_SET(2, 10055)

#if defined(LEGACY_RADIUS)
#ifndef PW_DELEGATED_IPV6_PREFIX
#define PW_DELEGATED_IPV6_PREFIX 123
#endif
#ifndef PW_ACCT_INTERIM_INTERVAL
#define PW_ACCT_INTERIM_INTERVAL 85
#endif
#endif

#if RADCLI_VERSION_NUMBER < 0x010207
#define CHALLENGE_RC 3
#endif

#define MAX_CHALLENGES 16

static void radius_vhost_init(void **_vctx, void *pool, void *additional)
{
	radius_cfg_st *config = additional;
	struct radius_vhost_ctx *vctx;

	if (config == NULL)
		goto fail;

	vctx = talloc_zero(pool, struct radius_vhost_ctx);
	if (vctx == NULL)
		goto fail;

	vctx->rh = rc_read_config(config->config);
	if (vctx->rh == NULL) {
		goto fail;
	}

	if (config->nas_identifier) {
		strlcpy(vctx->nas_identifier, config->nas_identifier,
			sizeof(vctx->nas_identifier));
	} else {
		vctx->nas_identifier[0] = 0;
	}

	if (rc_read_dictionary(vctx->rh, rc_conf_str(vctx->rh, "dictionary")) !=
	    0) {
		fprintf(stderr, "error reading the radius dictionary\n");
		exit(EXIT_FAILURE);
	}
	*_vctx = vctx;

	return;
fail:
	fprintf(stderr, "radius initialization error\n");
	exit(EXIT_FAILURE);
}

static void radius_vhost_deinit(void *_vctx)
{
	struct radius_vhost_ctx *vctx = _vctx;

	if (vctx->rh != NULL)
		rc_destroy(vctx->rh);
}

static int radius_auth_init(void **ctx, void *pool, void *_vctx,
			    const common_auth_init_st *info)
{
	struct radius_ctx_st *pctx;
	char *default_realm;
	struct radius_vhost_ctx *vctx = _vctx;

	if (info->username == NULL || info->username[0] == 0) {
		oc_syslog(LOG_NOTICE, "radius-auth: no username present");
		return ERR_AUTH_FAIL;
	}

	pctx = talloc_zero(pool, struct radius_ctx_st);
	if (pctx == NULL)
		return ERR_AUTH_FAIL;

	if (info->ip)
		strlcpy(pctx->remote_ip, info->ip, sizeof(pctx->remote_ip));
	if (info->our_ip)
		strlcpy(pctx->our_ip, info->our_ip, sizeof(pctx->our_ip));

	pctx->pass_msg[0] = 0;
	pctx->vctx = vctx;
	pctx->passwd_counter = 0;

	default_realm = rc_conf_str(pctx->vctx->rh, "default_realm");

	if ((strchr(info->username, '@') == NULL) && default_realm &&
	    default_realm[0] != 0) {
		snprintf(pctx->username, sizeof(pctx->username), "%s@%s",
			 info->username, default_realm);
	} else {
		strlcpy(pctx->username, info->username, sizeof(pctx->username));
	}
	pctx->id = info->id;

	if (info->user_agent)
		strlcpy(pctx->user_agent, info->user_agent,
			sizeof(pctx->user_agent));

	*ctx = pctx;

	return ERR_AUTH_CONTINUE;
}

static int radius_auth_group(void *ctx, const char *suggested, char *groupname,
			     int groupname_size)
{
	struct radius_ctx_st *pctx = ctx;
	unsigned int i;

	groupname[0] = 0;

	if (suggested != NULL) {
		for (i = 0; i < pctx->groupnames_size; i++) {
			if (strcmp(suggested, pctx->groupnames[i]) == 0) {
				strlcpy(groupname, pctx->groupnames[i],
					groupname_size);
				return 0;
			}
		}

		oc_syslog(
			LOG_NOTICE,
			"radius-auth: user '%s' requested group '%s' but is not a member",
			pctx->username, suggested);
		return -1;
	}

	if (pctx->groupnames_size > 0 && groupname[0] == 0) {
		strlcpy(groupname, pctx->groupnames[0], groupname_size);
	}

	return 0;
}

static int radius_auth_user(void *ctx, char *username, int username_size)
{
	/* do not update username */
	return -1;
}

static void append_route(struct radius_ctx_st *pctx, const char *route,
			 unsigned int len)
{
	unsigned int i;
	char *p;

	/* accept route/mask */
	p = strchr(route, '/');
	if (p == 0)
		return;

	p = strchr(p, ' ');
	if (p != NULL) {
		len = p - route;
	}

	if (pctx->routes_size == 0) {
		pctx->routes = talloc_size(pctx, sizeof(char *));
	} else {
		pctx->routes = talloc_realloc_size(pctx, pctx->routes,
						   (pctx->routes_size + 1) *
							   sizeof(char *));
	}

	if (pctx->routes != NULL) {
		i = pctx->routes_size;
		pctx->routes[i] = talloc_strndup(pctx, route, len);
		if (pctx->routes[i] != NULL)
			pctx->routes_size++;
	}
}

/* Parses group of format "OU=group1;group2;group3" */
static void parse_groupnames(struct radius_ctx_st *pctx, const char *full)
{
	char *p, *p2;

	if (pctx->groupnames_size >= MAX_GROUPS) {
		oc_syslog(
			LOG_WARNING,
			"radius-auth: cannot handle more than %d groups, ignoring group string %s",
			MAX_GROUPS, full);
	} else if (strncmp(full, "OU=", 3) == 0) {
		oc_syslog(LOG_DEBUG, "radius-auth: found group string %s",
			  full);
		full += 3;

		p = talloc_strdup(pctx, full);
		if (p == NULL)
			return;

		p2 = strsep(&p, ";");
		while (p2 != NULL) {
			pctx->groupnames[pctx->groupnames_size++] = p2;

			oc_syslog(LOG_DEBUG, "radius-auth: found group %s", p2);

			p2 = strsep(&p, ";");

			if (pctx->groupnames_size == MAX_GROUPS) {
				if (p2)
					oc_syslog(
						LOG_WARNING,
						"radius-auth: cannot handle more than %d groups, ignoring trailing group(s) %s",
						MAX_GROUPS, p2);
				break;
			}
		}
	} else {
		oc_syslog(LOG_DEBUG, "radius-auth: found group string %s",
			  full);
		p = talloc_strdup(pctx, full);
		if (p == NULL)
			return;
		pctx->groupnames[pctx->groupnames_size++] = p;
	}
}

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
static int radius_auth_pass(void *ctx, const char *pass, unsigned int pass_len)
{
	struct radius_ctx_st *pctx = ctx;
	VALUE_PAIR *send = NULL, *recvd = NULL;
	uint32_t service;
	char route[72];
	char txt[64];
	VALUE_PAIR *vp;
	int ret;

	/* send Access-Request */
	oc_syslog(LOG_DEBUG,
		  "radius-auth: communicating username (%s) and password",
		  pctx->username);
	if (rc_avpair_add(pctx->vctx->rh, &send, PW_USER_NAME, pctx->username,
			  -1, 0) == NULL) {
		oc_syslog(
			LOG_ERR,
			"%s:%u: error in constructing radius message for user '%s'",
			__func__, __LINE__, pctx->username);
		return ERR_AUTH_FAIL;
	}

	if (rc_avpair_add(pctx->vctx->rh, &send, PW_USER_PASSWORD, (char *)pass,
			  -1, 0) == NULL) {
		oc_syslog(
			LOG_ERR,
			"%s:%u: error in constructing radius message for user '%s'",
			__func__, __LINE__, pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	if (pctx->our_ip[0] != 0) {
		struct in_addr in;
		struct in6_addr in6;

		if (inet_pton(AF_INET, pctx->our_ip, &in) != 0) {
			in.s_addr = ntohl(in.s_addr);
			if (rc_avpair_add(pctx->vctx->rh, &send,
					  PW_NAS_IP_ADDRESS, (char *)&in,
					  sizeof(struct in_addr), 0) == NULL) {
				oc_syslog(
					LOG_ERR,
					"%s:%u: error in constructing radius message for user '%s'",
					__func__, __LINE__, pctx->username);
				ret = ERR_AUTH_FAIL;
				goto cleanup;
			}
		} else if (inet_pton(AF_INET6, pctx->our_ip, &in6) != 0) {
			if (rc_avpair_add(pctx->vctx->rh, &send,
					  PW_NAS_IPV6_ADDRESS, (char *)&in6,
					  sizeof(struct in6_addr), 0) == NULL) {
				oc_syslog(
					LOG_ERR,
					"%s:%u: error in constructing radius message for user '%s'",
					__func__, __LINE__, pctx->username);
				ret = ERR_AUTH_FAIL;
				goto cleanup;
			}
		}
	}

	if (pctx->vctx->nas_identifier[0] != 0) {
		if (rc_avpair_add(pctx->vctx->rh, &send, PW_NAS_IDENTIFIER,
				  pctx->vctx->nas_identifier, -1, 0) == NULL) {
			oc_syslog(
				LOG_ERR,
				"%s:%u: error in constructing radius message for user '%s'",
				__func__, __LINE__, pctx->username);
			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
	}

	if (rc_avpair_add(pctx->vctx->rh, &send, PW_CALLING_STATION_ID,
			  pctx->remote_ip, -1, 0) == NULL) {
		oc_syslog(
			LOG_ERR,
			"%s:%u: error in constructing radius message for user '%s'",
			__func__, __LINE__, pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	if (pctx->user_agent[0] != 0) {
		if (rc_avpair_add(pctx->vctx->rh, &send, PW_CONNECT_INFO,
				  pctx->user_agent, -1, 0) == NULL) {
			oc_syslog(
				LOG_ERR,
				"%s:%u: error in constructing radius message for user '%s'",
				__func__, __LINE__, pctx->username);
			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
	}

	service = PW_AUTHENTICATE_ONLY;
	if (rc_avpair_add(pctx->vctx->rh, &send, PW_SERVICE_TYPE, &service, -1,
			  0) == NULL) {
		oc_syslog(
			LOG_ERR,
			"%s:%u: error in constructing radius message for user '%s'",
			__func__, __LINE__, pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	service = PW_ASYNC;
	if (rc_avpair_add(pctx->vctx->rh, &send, PW_NAS_PORT_TYPE, &service, -1,
			  0) == NULL) {
		oc_syslog(
			LOG_ERR,
			"%s:%u: error in constructing radius message for user '%s'",
			__func__, __LINE__, pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	if (pctx->state != NULL) {
		if (rc_avpair_add(pctx->vctx->rh, &send, PW_STATE, pctx->state,
				  -1, 0) == NULL) {
			oc_syslog(
				LOG_ERR,
				"%s:%u: error in constructing radius message for user '%s'",
				__func__, __LINE__, pctx->username);
			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
		talloc_free(pctx->state);
		pctx->state = NULL;
	}

	pctx->pass_msg[0] = 0;
	ret = rc_aaa(pctx->vctx->rh, 0, send, &recvd, pctx->pass_msg, 0,
		     PW_ACCESS_REQUEST);

	if (ret == OK_RC) {
		uint32_t ipv4;
		uint8_t ipv6[16];

		vp = recvd;

		while (vp != NULL) {
			if (vp->attribute == PW_SERVICE_TYPE &&
			    vp->lvalue != PW_FRAMED) {
				oc_syslog(
					LOG_ERR,
					"%s:%u: unknown radius service type '%d'",
					__func__, __LINE__, (int)vp->lvalue);
				goto fail;
			} else if (vp->attribute == RAD_GROUP_NAME &&
				   vp->type == PW_TYPE_STRING) {
				/* Group-Name */
				parse_groupnames(pctx, vp->strvalue);
			} else if (vp->attribute == PW_FRAMED_IPV6_ADDRESS &&
				   vp->type == PW_TYPE_IPV6ADDR) {
				/* Framed-IPv6-Address */
				if (inet_ntop(AF_INET6, vp->strvalue,
					      pctx->ipv6,
					      sizeof(pctx->ipv6)) != NULL) {
					pctx->ipv6_subnet_prefix = 64;
					strlcpy(pctx->ipv6_net, pctx->ipv6,
						sizeof(pctx->ipv6_net));
				}
			} else if (vp->attribute == PW_DELEGATED_IPV6_PREFIX &&
				   vp->type == PW_TYPE_IPV6PREFIX) {
				/* Delegated-IPv6-Prefix */
				if (inet_ntop(AF_INET6, vp->strvalue,
					      pctx->ipv6,
					      sizeof(pctx->ipv6)) != NULL) {
					memset(ipv6, 0, sizeof(ipv6));
					memcpy(ipv6, vp->strvalue + 2,
					       vp->lvalue - 2);
					if (inet_ntop(AF_INET6, ipv6,
						      pctx->ipv6,
						      sizeof(pctx->ipv6)) !=
					    NULL) {
						pctx->ipv6_subnet_prefix =
							(unsigned int)(unsigned char)
								vp->strvalue[1];
					}
				}
			} else if (vp->attribute == PW_FRAMED_IPV6_PREFIX &&
				   vp->type == PW_TYPE_IPV6PREFIX) {
				if (vp->lvalue > 2 && vp->lvalue <= 18) {
					/* Framed-IPv6-Prefix */
					memset(ipv6, 0, sizeof(ipv6));
					memcpy(ipv6, vp->strvalue + 2,
					       vp->lvalue - 2);
					if (inet_ntop(AF_INET6, ipv6, txt,
						      sizeof(txt)) != NULL) {
						snprintf(
							route, sizeof(route),
							"%s/%u", txt,
							(unsigned int)(unsigned char)
								vp->strvalue[1]);
						append_route(pctx, vp->strvalue,
							     vp->lvalue);
					}
				}
			} else if (vp->attribute ==
					   PW_DNS_SERVER_IPV6_ADDRESS &&
				   vp->type == PW_TYPE_IPV6ADDR) {
				/* DNS-Server-IPv6-Address */
				if (pctx->ipv6_dns1[0] == 0)
					inet_ntop(AF_INET6, vp->strvalue,
						  pctx->ipv6_dns1,
						  sizeof(pctx->ipv6_dns1));
				else if (pctx->ipv6_dns2[0] == 0)
					inet_ntop(AF_INET6, vp->strvalue,
						  pctx->ipv6_dns2,
						  sizeof(pctx->ipv6_dns2));
				else {
					char dst[MAX_IP_STR];

					inet_ntop(AF_INET6, vp->strvalue, dst,
						  sizeof(dst));
					oc_syslog(
						LOG_NOTICE,
						"radius-auth: cannot handle more than 2 DNS servers, ignoring additional DNS server from RADIUS: %s",
						dst);
				}
			} else if (vp->attribute == PW_FRAMED_IP_ADDRESS &&
				   vp->type == PW_TYPE_IPADDR) {
				/* Framed-IP-Address */
				if (vp->lvalue != 0xffffffff &&
				    vp->lvalue != 0xfffffffe) {
					/* According to RFC2865 the values above (fe) instruct the
					 * server to assign an address from the pool of the server,
					 * and (ff) to assign address as negotiated with the client.
					 * We don't negotiate with clients.
					 */
					ipv4 = htonl(vp->lvalue);
					inet_ntop(AF_INET, &ipv4, pctx->ipv4,
						  sizeof(pctx->ipv4));
				}
			} else if (vp->attribute == PW_FRAMED_IP_NETMASK &&
				   vp->type == PW_TYPE_IPADDR) {
				/* Framed-IP-Netmask */
				ipv4 = htonl(vp->lvalue);
				inet_ntop(AF_INET, &ipv4, pctx->ipv4_mask,
					  sizeof(pctx->ipv4_mask));
			} else if (vp->attribute == MS_PRIMARY_DNS_SERVER &&
				   vp->type == PW_TYPE_IPADDR) {
				/* MS-Primary-DNS-Server */
				ipv4 = htonl(vp->lvalue);
				inet_ntop(AF_INET, &ipv4, pctx->ipv4_dns1,
					  sizeof(pctx->ipv4_dns1));
			} else if (vp->attribute == MS_SECONDARY_DNS_SERVER &&
				   vp->type == PW_TYPE_IPADDR) {
				/* MS-Secondary-DNS-Server */
				ipv4 = htonl(vp->lvalue);
				inet_ntop(AF_INET, &ipv4, pctx->ipv4_dns2,
					  sizeof(pctx->ipv4_dns2));
			} else if (vp->attribute == PW_FRAMED_ROUTE &&
				   vp->type == PW_TYPE_STRING) {
				/* Framed-Route */
				append_route(pctx, vp->strvalue, vp->lvalue);
			} else if (vp->attribute == PW_FRAMED_IPV6_ROUTE &&
				   vp->type == PW_TYPE_STRING) {
				/* Framed-IPv6-Route */
				append_route(pctx, vp->strvalue, vp->lvalue);
			} else if (vp->attribute == PW_ACCT_INTERIM_INTERVAL &&
				   vp->type == PW_TYPE_INTEGER) {
				pctx->interim_interval_secs = vp->lvalue;
			} else if (vp->attribute == PW_SESSION_TIMEOUT &&
				   vp->type == PW_TYPE_INTEGER) {
				pctx->session_timeout_secs = vp->lvalue;
			} else if (vp->attribute == RP_UPSTREAM_SPEED_LIMIT &&
				   vp->type == PW_TYPE_INTEGER) {
				pctx->rx_per_sec = vp->lvalue;
			} else if (vp->attribute == RP_DOWNSTREAM_SPEED_LIMIT &&
				   vp->type == PW_TYPE_INTEGER) {
				pctx->tx_per_sec = vp->lvalue;
			} else {
				oc_syslog(
					LOG_DEBUG,
					"radius-auth: ignoring server's attribute (%u,%u) of type %u",
					(unsigned int)ATTRID(vp->attribute),
					(unsigned int)VENDOR(vp->attribute),
					(unsigned int)vp->type);
			}
			vp = vp->next;
		}

		ret = 0;
		goto cleanup;
	} else if (ret == CHALLENGE_RC) {
		vp = recvd;

		while (vp != NULL) {
			if (vp->attribute == PW_STATE &&
			    vp->type == PW_TYPE_STRING) {
				/* State */
				if (vp->lvalue > 0)
					pctx->state = talloc_strdup(
						pctx, vp->strvalue);

				pctx->id++;
				oc_syslog(
					LOG_DEBUG,
					"radius-auth: Access-Challenge response stage %u, State %s",
					pctx->passwd_counter, vp->strvalue);
				ret = ERR_AUTH_CONTINUE;
			}
			vp = vp->next;
		}

		/* PW_STATE or PW_REPLY_MESSAGE is empty or MAX_CHALLENGES limit exceeded */
		if ((pctx->pass_msg[0] == 0) || (pctx->state == NULL) ||
		    (pctx->passwd_counter >= MAX_CHALLENGES)) {
			strlcpy(pctx->pass_msg, pass_msg_failed,
				sizeof(pctx->pass_msg));
			oc_syslog(
				LOG_ERR,
				"radius-auth: Access-Challenge with invalid State or Reply-Message, or max number of password requests exceeded");
			ret = ERR_AUTH_FAIL;
		}
		goto cleanup;
	} else {
fail:
		if (pctx->pass_msg[0] == 0)
			strlcpy(pctx->pass_msg, pass_msg_failed,
				sizeof(pctx->pass_msg));

		if (pctx->retries++ < MAX_PASSWORD_TRIES - 1 &&
		    pctx->passwd_counter == 0) {
			ret = ERR_AUTH_CONTINUE;
			goto cleanup;
		}

		oc_syslog(
			LOG_NOTICE,
			"radius-auth: error authenticating user '%s' (code %d)",
			pctx->username, ret);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

cleanup:
	if (send != NULL)
		rc_avpair_free(send);
	if (recvd != NULL)
		rc_avpair_free(recvd);
	return ret;
}

static int radius_auth_msg(void *ctx, void *pool, passwd_msg_st *pst)
{
	struct radius_ctx_st *pctx = ctx;
	size_t prompt_hash = 0;

	if (pctx->pass_msg[0] != 0)
		pst->msg_str = talloc_strdup(pool, pctx->pass_msg);

	if (pctx->state != NULL) {
		/* differentiate password prompts, if the hash of the prompt
		 * is different.
		 */
		prompt_hash =
			hash_any(pctx->pass_msg, strlen(pctx->pass_msg), 0);
		if (pctx->prev_prompt_hash != prompt_hash)
			pctx->passwd_counter++;
		pctx->prev_prompt_hash = prompt_hash;
		pst->counter = pctx->passwd_counter;
	}

	/* use default prompt */
	return 0;
}

static void radius_auth_deinit(void *ctx)
{
	struct radius_ctx_st *pctx = ctx;

	talloc_free(pctx);
}

const struct auth_mod_st radius_auth_funcs = {
	.type = AUTH_TYPE_RADIUS | AUTH_TYPE_USERNAME_PASS,
	.allows_retries = 1,
	.vhost_init = radius_vhost_init,
	.vhost_deinit = radius_vhost_deinit,
	.auth_init = radius_auth_init,
	.auth_deinit = radius_auth_deinit,
	.auth_msg = radius_auth_msg,
	.auth_pass = radius_auth_pass,
	.auth_user = radius_auth_user,
	.auth_group = radius_auth_group,
	.group_list = NULL
};

#endif
