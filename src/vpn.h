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
#define DEFAULT_MAX_BAN_SCORE (MAX_PASSWORD_TRIES * DEFAULT_PASSWORD_POINTS)
#define DEFAULT_BAN_RESET_TIME 300

#define MIN_NO_COMPRESS_LIMIT 64
#define DEFAULT_NO_COMPRESS_LIMIT 256

/* The time after which a user will be forced to authenticate
 * or disconnect. */
#define DEFAULT_AUTH_TIMEOUT_SECS 1800

/* The time after a disconnection the cookie is valid */
#define DEFAULT_COOKIE_RECON_TIMEOUT 120

#define DEFAULT_DPD_TIME 600

#define AC_PKT_DATA 0 /* Uncompressed data */
#define AC_PKT_DPD_OUT 3 /* Dead Peer Detection */
#define AC_PKT_DPD_RESP 4 /* DPD response */
#define AC_PKT_DISCONN 5 /* Client disconnection notice */
#define AC_PKT_KEEPALIVE 7 /* Keepalive */
#define AC_PKT_COMPRESSED 8 /* Compressed data */
#define AC_PKT_TERM_SERVER 9 /* Server kick */

#define REKEY_METHOD_SSL 1
#define REKEY_METHOD_NEW_TUNNEL 2

extern int syslog_open;

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
#define MAX_KRB_REALMS 16

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

typedef struct kkdcp_realm_st {
	char *realm;
	struct sockaddr_storage addr;
	socklen_t addr_len;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
} kkdcp_realm_st;

typedef struct kkdcp_st {
	char *url;
	/* the supported realms by this URL */
	kkdcp_realm_st realms[MAX_KRB_REALMS];
	unsigned int realms_size;
} kkdcp_st;

struct cfg_st {
	unsigned int is_dyndns;
	unsigned int listen_proxy_proto;
	unsigned int stats_report_time;

	kkdcp_st *kkdcp;
	unsigned int kkdcp_size;

	char *cert_user_oid; /* The OID that will be used to extract the username */
	char *cert_group_oid; /* The OID that will be used to extract the groupname */

	gnutls_certificate_request_t cert_req;
	char *priorities;
#ifdef ENABLE_COMPRESSION
	unsigned int enable_compression;
	unsigned int
		no_compress_limit; /* under this size (in bytes) of data there will be no compression */
#endif
	char *banner;
	char *pre_login_banner;
	char *ocsp_response; /* file with the OCSP response */
	char *default_domain; /* domain to be advertised */

	char **group_list; /* select_group */
	unsigned int group_list_size;

	char **friendly_group_list; /* the same size as group_list_size */

	unsigned int select_group_by_url;
	unsigned int auto_select_group;
	char *default_select_group;

	char **custom_header;
	size_t custom_header_size;

	char **split_dns;
	size_t split_dns_size;

	/* http headers to include */
	char **included_http_headers;
	size_t included_http_headers_size;

	unsigned int
		append_routes; /* whether to append global routes to per-user config */
	unsigned int
		restrict_user_to_routes; /* whether the firewall script will be run for the user */
	unsigned int
		deny_roaming; /* whether a cookie is restricted to a single IP */
	time_t cookie_timeout; /* in seconds */
	time_t session_timeout; /* in seconds */
	unsigned int
		persistent_cookies; /* whether cookies stay valid after disconnect */

	time_t rekey_time; /* in seconds */
	unsigned int rekey_method; /* REKEY_METHOD_ */

	time_t min_reauth_time; /* after a failed auth, how soon one can reauthenticate -> in seconds */
	unsigned int
		max_ban_score; /* the score allowed before a user is banned (see vpn.h) */
	int ban_reset_time;

	unsigned int ban_points_wrong_password;
	unsigned int ban_points_connect;
	unsigned int ban_points_kkdcp;

	/* when using the new PSK DTLS negotiation make sure that
	 * the negotiated DTLS cipher/mac matches the TLS cipher/mac. */
	unsigned int match_dtls_and_tls;
	unsigned int dtls_psk; /* whether to enable DTLS-PSK */
	unsigned int dtls_legacy; /* whether to enable DTLS-LEGACY */

	unsigned int isolate; /* whether seccomp should be enabled or not */

	unsigned int auth_timeout; /* timeout of HTTP auth */
	unsigned int idle_timeout; /* timeout when idle */
	unsigned int mobile_idle_timeout; /* timeout when a mobile is idle */
	unsigned int
		switch_to_tcp_timeout; /* length of no traffic period to automatically switch to TCP */
	unsigned int keepalive;
	unsigned int dpd;
	unsigned int mobile_dpd;
	unsigned int max_clients;
	unsigned int max_same_clients;
	unsigned int use_utmp;
	unsigned int tunnel_all_dns;
	unsigned int
		use_occtl; /* whether support for the occtl tool will be enabled */

	unsigned int try_mtu; /* MTU discovery enabled */
	unsigned int cisco_client_compat; /* do not require client certificate,
				       * and allow auth to complete in different
				       * TCP sessions. */
	unsigned int
		cisco_svc_client_compat; /* force allowed ciphers and disable dtls-legacy */
	unsigned int
		rate_limit_ms; /* if non zero force a connection every rate_limit milliseconds if ocserv-sm is heavily loaded */
	unsigned int
		ping_leases; /* non zero if we need to ping prior to leasing */
	unsigned int
		server_drain_ms; /* how long to wait after we stop accepting new connections before closing old connections */

	size_t rx_per_sec;
	size_t tx_per_sec;
	unsigned int net_priority;

	char *crl;

	unsigned int output_buffer;
	unsigned int default_mtu;
	unsigned int predictable_ips; /* boolean */

	char *route_add_cmd;
	char *route_del_cmd;

	char *connect_script;
	char *host_update_script;
	char *disconnect_script;

	char *cgroup;
	char *proxy_url;

#ifdef ANYCONNECT_CLIENT_COMPAT
	char *xml_config_file;
	char *xml_config_hash;
#endif

	unsigned int client_bypass_protocol;

	/* additional configuration files */
	char *per_group_dir;
	char *per_user_dir;
	char *default_group_conf;
	char *default_user_conf;

	bool gssapi_no_local_user_map;

	/* known iroutes - only sent to the users who are not registering them
	 */
	char **known_iroutes;
	size_t known_iroutes_size;

	FwPortSt **fw_ports;
	size_t n_fw_ports;

	/* the tun network */
	struct vpn_st network;

	/* holds a usage count of holders of pointers in this struct */
	int *usage_count;

	bool camouflage;
	char *camouflage_secret;
	char *camouflage_realm;
};

struct perm_cfg_st {
	/* gets reloaded */
	struct cfg_st *config;

	/* stuff here don't change on reload */
	auth_struct_st auth[MAX_AUTH_METHODS];
	unsigned int auth_methods;
	acct_struct_st acct;
	unsigned int sup_config_type; /* one of SUP_CONFIG_ */

	char *chroot_dir; /* where the xml files are served from */
	char *occtl_socket_file;
	char *socket_file_prefix;

	uid_t uid;
	gid_t gid;

	char *key_pin;
	char *srk_pin;

	char *pin_file;
	char *srk_pin_file;
	char **cert;
	size_t cert_size;
	char **key;
	size_t key_size;
#ifdef ANYCONNECT_CLIENT_COMPAT
	char *cert_hash;
#endif
	unsigned int stats_reset_time;
	unsigned int foreground;
	unsigned int no_chdir;
	unsigned int log_level;
	unsigned int log_stderr;
	unsigned int syslog;

	unsigned int pr_dumpable;

	char *ca;
	char *dh_params_file;

	char *listen_host;
	char *udp_listen_host;
	char *listen_netns_name;
	unsigned int port;
	unsigned int udp_port;

	unsigned int sec_mod_scale;

	/* for testing ocserv only */
	unsigned int debug_no_secmod_stats;

	/* attic, where old config allocated values are stored */
	struct list_head attic;
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
