/*
 * Copyright (C) 2013-2023 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef OC_VPN_H
#define OC_VPN_H

#include <config.h>
#include <gnutls/gnutls.h>
#include <llhttp.h>
#include <ccan/htable/htable.h>
#include <ccan/list/list.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <auth/common.h>

#include <ipc.pb-c.h>
#include <cfg.pb-c.h>

#ifdef __GNUC__
#define _OCSERV_GCC_VERSION \
	(__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if _OCSERV_GCC_VERSION >= 30000
#define _ATTR_PACKED __attribute__((__packed__))
#endif
#endif /* __GNUC__ */

#ifndef _ATTR_PACKED
#define _ATTR_PACKED
#endif

#define MAX_MSG_SIZE 16 * 1024
#define DTLS_PROTO_INDICATOR "PSK-NEGOTIATE"

typedef enum { SOCK_TYPE_TCP, SOCK_TYPE_UDP, SOCK_TYPE_UNIX } sock_type_t;

typedef enum {
	OC_COMP_NULL = 0,
	OC_COMP_LZ4,
	OC_COMP_LZS,
} comp_type_t;

typedef enum fw_proto_t {
	PROTO_UDP,
	PROTO_TCP,
	PROTO_SCTP,
	PROTO_ESP,
	PROTO_ICMP,
	PROTO_ICMPv6,

	/* fix proto2str below if anything is added */
	PROTO_MAX
} fw_proto_t;

inline static const char *proto_to_str(fw_proto_t proto)
{
	const char *proto2str[] = { "udp", "tcp",  "sctp",
				    "esp", "icmp", "icmpv6" };

	if ((int)proto < 0 || proto >= PROTO_MAX)
		return "unknown";
	return proto2str[proto];
}

#define DEFAULT_LOG_LEVEL 2

/* Banning works with a point system. A wrong password
 * attempt gives you PASSWORD_POINTS, and you are banned
 * when the maximum ban score is reached.
 */
#define DEFAULT_PASSWORD_POINTS 10
#define DEFAULT_CONNECT_POINTS 1
#define DEFAULT_KKDCP_POINTS 1
#define DEFAULT_MAX_BAN_SCORE 80
#define DEFAULT_BAN_TIME 300
#define DEFAULT_BAN_RESET_TIME 1200

#define MIN_NO_COMPRESS_LIMIT 64
#define DEFAULT_NO_COMPRESS_LIMIT 256

/* The time after which a user will be forced to authenticate
 * or disconnect. */
#define DEFAULT_AUTH_TIMEOUT_SECS 240

/* The time after a disconnection the cookie is valid */
#define DEFAULT_COOKIE_RECON_TIMEOUT 300

#define DEFAULT_KEEPALIVE_TIME 32400
#define DEFAULT_REKEY_TIME 172800
#define DEFAULT_SWITCH_TO_TCP_TIMEOUT 25

#define DEFAULT_DPD_TIME 90
#define DEFAULT_MOBILE_DPD_TIME 1800

#define AC_PKT_DATA 0 /* Uncompressed data */
#define AC_PKT_DPD_OUT 3 /* Dead Peer Detection */
#define AC_PKT_DPD_RESP 4 /* DPD response */
#define AC_PKT_DISCONN 5 /* Client disconnection notice */
#define AC_PKT_KEEPALIVE 7 /* Keepalive */
#define AC_PKT_COMPRESSED 8 /* Compressed data */
#define AC_PKT_TERM_SERVER 9 /* Server kick */

/* Disconnect reason for AC_PKT_DISCONN */
#define AC_BYE_USER_DISCONNECT 0xb0 /* User requested to disconnect */
#define AC_BYE_LOCAL_ERROR 0x70 /* E.g., unable to modify routing table */
#define AC_BYE_VPN_RECONNECT 0x91 /* VPN tunnel is reconnecting */
#define AC_BYE_VPN_PAUSE 0xd1 /* VPN tunnel is paused */

#define REKEY_METHOD_SSL 1
#define REKEY_METHOD_NEW_TUNNEL 2

/* the first is generic, for the methods that require a username password */
#define AUTH_TYPE_USERNAME_PASS (1 << 0)
#define AUTH_TYPE_PAM (1 << 1 | AUTH_TYPE_USERNAME_PASS)
#define AUTH_TYPE_PLAIN (1 << 2 | AUTH_TYPE_USERNAME_PASS)
#define AUTH_TYPE_CERTIFICATE (1 << 3)
#define AUTH_TYPE_RADIUS (1 << 5 | AUTH_TYPE_USERNAME_PASS)
#define AUTH_TYPE_GSSAPI (1 << 6)
#define AUTH_TYPE_OIDC (1 << 7)

#define ALL_AUTH_TYPES                                              \
	((AUTH_TYPE_PAM | AUTH_TYPE_PLAIN | AUTH_TYPE_CERTIFICATE | \
	  AUTH_TYPE_RADIUS | AUTH_TYPE_GSSAPI | AUTH_TYPE_OIDC) &   \
	 (~AUTH_TYPE_USERNAME_PASS))
#define VIRTUAL_AUTH_TYPES (AUTH_TYPE_USERNAME_PASS)
#define CONFIDENTIAL_USER_NAME_AUTH_TYPES (AUTH_TYPE_GSSAPI | AUTH_TYPE_OIDC)

#define ACCT_TYPE_PAM (1 << 1)
#define ACCT_TYPE_RADIUS (1 << 2)

#include "defs.h"

/* Allow few seconds prior to cleaning up entries, to avoid any race
 * conditions when session control is enabled, as well as to allow
 * anyconnect clients to reconnect (they often drop the connection and
 * re-establish using the same cookie).
 */
#define AUTH_SLACK_TIME 15

#define MAX_CIPHERSUITE_NAME 64
#define SID_SIZE 32

struct vpn_st {
	char name[IFNAMSIZ];
	char *ipv4_netmask;
	char *ipv4_network;
	char *ipv4;
	char *ipv4_local; /* local IPv4 address */
	char *ipv6_network;
	unsigned int ipv6_prefix;

	char *ipv6;
	char *ipv6_local; /* local IPv6 address */
	/* mtu: TUN device MTU assigned from config or peer negotiation.
	 * Starting point; worker reduces it to ws->link_mtu after subtracting
	 * DTLS/IP overhead.  Distinct from link_mtu (outer, includes all
	 * encapsulation headers) and tunnel_mtu / DATA_MTU (inner plaintext
	 * payload, equals link_mtu minus all overhead). */
	unsigned int mtu;
	unsigned int ipv6_subnet_prefix; /* ipv6 subnet prefix to assign */

	char **routes;
	size_t routes_size;

	/* excluded routes */
	char **no_routes;
	size_t no_routes_size;

	char **dns;
	size_t dns_size;

	char **nbns;
	size_t nbns_size;
};

#define MAX_AUTH_METHODS 4

typedef struct auth_struct_st {
	char *name;
	char *additional;
	unsigned int type;
	const struct auth_mod_st *amod;
	void *auth_ctx;
	void *dl_ctx;

	bool enabled;
} auth_struct_st;

typedef struct acct_struct_st {
	const char *name;
	char *additional;
	void *acct_ctx;
	const struct acct_mod_st *amod;
} acct_struct_st;

/*
 * Permanent config (static_cfg_st): requires server restart to change.
 * Scope tags:
 *   [scope: global (non-reloadable)] -- cannot differ per virtual host
 *   [scope: vhost (non-reloadable)]  -- can differ per virtual host
 *
 * Note: reloadable fields (ReloadableConfig *config, usage_count, attic) live
 * directly in vhost_cfg_st, not here.
 */
struct static_cfg_st {
	/* stuff here don't change on reload */
	auth_struct_st
		auth[MAX_AUTH_METHODS]; /* [scope: vhost (non-reloadable)] */
	unsigned int auth_methods; /* [scope: vhost (non-reloadable)] */
	acct_struct_st acct; /* [scope: vhost (non-reloadable)] */
	unsigned int
		sup_config_type; /* [scope: vhost (non-reloadable)] one of SUP_CONFIG_ */

	char *chroot_dir; /* [scope: global (non-reloadable)] where the xml files are served from */
	char *occtl_socket_file; /* [scope: global (non-reloadable)] */
	char *socket_file_prefix; /* [scope: global (non-reloadable)] */

	uid_t uid; /* [scope: global (non-reloadable)] */
	gid_t gid; /* [scope: global (non-reloadable)] */

	char *key_pin; /* [scope: vhost (non-reloadable)] */
	char *srk_pin; /* [scope: vhost (non-reloadable)] */

	char *pin_file; /* [scope: vhost (non-reloadable)] */
	char *srk_pin_file; /* [scope: vhost (non-reloadable)] */
	char **cert; /* [scope: vhost (non-reloadable)] */
	size_t cert_size; /* [scope: vhost (non-reloadable)] */
	char **key; /* [scope: vhost (non-reloadable)] */
	size_t key_size; /* [scope: vhost (non-reloadable)] */
#ifdef ANYCONNECT_CLIENT_COMPAT
	char *cert_hash; /* [scope: vhost (non-reloadable)] */
#endif
	unsigned int stats_reset_time; /* [scope: global (non-reloadable)] */
	unsigned int foreground; /* [scope: global (non-reloadable)] */
	unsigned int no_chdir; /* [scope: global (non-reloadable)] */
	unsigned int log_level; /* [scope: global (non-reloadable)] */
	unsigned int log_stderr; /* [scope: global (non-reloadable)] */
	unsigned int syslog; /* [scope: global (non-reloadable)] */
	int syslog_facility; /* [scope: global (non-reloadable)] */

	unsigned int pr_dumpable; /* [scope: global (non-reloadable)] */

	char *ca; /* [scope: vhost (non-reloadable)] */
	char *dh_params_file; /* [scope: vhost (non-reloadable)] */

	char *listen_host; /* [scope: global (non-reloadable)] */
	char *udp_listen_host; /* [scope: global (non-reloadable)] */
	char *listen_netns_name; /* [scope: global (non-reloadable)] */
	unsigned int port; /* [scope: global (non-reloadable)] */
	unsigned int udp_port; /* [scope: global (non-reloadable)] */

	unsigned int sec_mod_scale; /* [scope: global (non-reloadable)] */

	/* for testing ocserv only */
	unsigned int debug_no_secmod_stats; /* [scope: global (non-reloadable)] */
};

typedef struct attic_entry_st {
	struct list_node list;
	int *usage_count;
} attic_entry_st;

/* generic thing to stop complaints */
struct worker_st;
struct main_server_st;
struct dtls_st;

#define MAX_BANNER_SIZE 256
#define MAX_USERNAME_SIZE 64
#define MAX_AGENT_NAME 64
#define MAX_DEVICE_TYPE 64
#define MAX_DEVICE_PLATFORM 64
#define MAX_PASSWORD_SIZE 64
#define TLS_MASTER_SIZE 48
#define MAX_HOSTNAME_SIZE MAX_USERNAME_SIZE
#define MAX_GROUPNAME_SIZE MAX_USERNAME_SIZE
#define MAX_SESSION_DATA_SIZE (4 * 1024)

#if defined(CAPTURE_LATENCY_SUPPORT)
#define LATENCY_SAMPLE_SIZE 1024
#define LATENCY_WORKER_AGGREGATION_TIME 60
#endif

#define DEFAULT_CONFIG_ENTRIES 96

#include <tun.h>

unsigned int extract_prefix(char *network);

/* macros */
#define TOS_PACK(x) (x << 4)
#define TOS_UNPACK(x) (x >> 4)
#define IS_TOS(x) ((x & 0x0f) == 0)

/* Helper structures */
enum option_types {
	OPTION_NUMERIC,
	OPTION_STRING,
	OPTION_BOOLEAN,
	OPTION_MULTI_LINE
};

#include <ip-util.h>

void reload_cfg_file(void *pool, struct list_head *configs,
		     unsigned int sec_mod);
void clear_old_configs(struct list_head *configs);
void write_pid_file(void);
void remove_pid_file(void);

unsigned int switch_comp_priority(void *pool, const char *modstring);

extern sigset_t sig_default_set;

#endif
