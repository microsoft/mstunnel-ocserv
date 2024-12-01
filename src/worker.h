/*
 * Copyright (C) 2013-2016 Nikos Mavrogiannopoulos
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
#ifndef OC_WORKER_H
#define OC_WORKER_H

#include <config.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>
#include <net/if.h>
#include <vpn.h>
#include <tlslib.h>
#include <common.h>
#include <str.h>
#include <worker-bandwidth.h>
#include <stdbool.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <hmac.h>
#include "vhost.h"
#include "ev.h"
#include "common/common.h"

#include "log.h"

// Name of environment variable used to pass worker_startup_msg
// between ocserv-main and ocserv-worker.
#define OCSERV_ENV_WORKER_STARTUP_MSG "OCSERV_WORKER_STARTUP_MSG"

typedef enum {
	UP_DISABLED,
	UP_WAIT_FD,
	UP_SETUP,
	UP_HANDSHAKE,
	UP_INACTIVE,
	UP_ACTIVE
} udp_port_state_t;

enum {
	HEADER_COOKIE = 1,
	HEADER_MASTER_SECRET,
	HEADER_HOSTNAME,
	HEADER_CSTP_MTU,
	HEADER_CSTP_BASE_MTU,
	HEADER_CSTP_ATYPE,
	HEADER_DEVICE_TYPE,
	HEADER_PLATFORM,
	HEADER_DTLS_CIPHERSUITE,
	HEADER_DTLS12_CIPHERSUITE,
	HEADER_CONNECTION,
	HEADER_FULL_IPV6,
	HEADER_USER_AGENT,
	HEADER_CSTP_ENCODING,
	HEADER_DTLS_ENCODING,
	HEADER_SUPPORT_SPNEGO,
	HEADER_AUTHORIZATION
};

enum { HTTP_HEADER_INIT = 0, HTTP_HEADER_RECV, HTTP_HEADER_VALUE_RECV };

enum {
	S_AUTH_INACTIVE = 0,
	S_AUTH_INIT,
	S_AUTH_REQ,
	S_AUTH_COOKIE,
	S_AUTH_COMPLETE
};

enum {
	AGENT_UNKNOWN,
	AGENT_OPENCONNECT_V3,
	AGENT_OPENCONNECT,
	AGENT_ANYCONNECT,
	AGENT_OPENCONNECT_CLAVISTER,
	AGENT_ANYLINK,
	AGENT_SVC_IPPHONE
};

typedef int (*decompress_fn)(void *dst, int maxDstSize, const void *src,
			     int src_size);
typedef int (*compress_fn)(void *dst, int dst_size, const void *src,
			   int src_size);

typedef struct compression_method_st {
	comp_type_t id;
	const char *name;
	decompress_fn decompress;
	compress_fn compress;
	unsigned int
		server_prio; /* the highest the more we want to negotiate that */
} compression_method_st;

typedef struct dtls_ciphersuite_st {
	const char *oc_name;
	const char *gnutls_name; /* the gnutls priority string to set */
	unsigned int dtls12_mode;
	unsigned int
		server_prio; /* the highest the more we want to negotiate that */
	unsigned int gnutls_cipher;
	unsigned int gnutls_kx;
	unsigned int gnutls_mac;
	unsigned int gnutls_version;
} dtls_ciphersuite_st;

#ifdef HAVE_GSSAPI
#include <libtasn1.h>
/* main has initialized that for us */
extern asn1_node _kkdcp_pkix1_asn;
#endif

struct http_req_st {
	char url[256];

	str_st header;
	str_st value;
	unsigned int header_state;

	char devtype[MAX_AGENT_NAME]; /* Device-Type */
	char devplatform[MAX_AGENT_NAME]; /* Device-Platform */
	char hostname[MAX_HOSTNAME_SIZE];
	char user_agent[MAX_AGENT_NAME];
	unsigned int user_agent_type;

	unsigned int next_header;

	bool is_mobile;
	bool is_ios;
	bool spnego_set;

	unsigned char master_secret[TLS_MASTER_SIZE];
	unsigned int master_secret_set;

	char *body;
	unsigned int body_length;

	const dtls_ciphersuite_st *selected_ciphersuite;
	unsigned int use_psk; /* i.e., ignore selected_ciphersuite */

	unsigned int headers_complete;
	unsigned int message_complete;
	unsigned int link_mtu;
	unsigned int tunnel_mtu;

	unsigned int no_ipv4;
	unsigned int no_ipv6;

	char *authorization;
	unsigned int authorization_size;
};

typedef struct dtls_transport_ptr {
	int fd;
	UdpFdMsg *msg; /* holds the data of the first client hello */
	int consumed;
#if defined(CAPTURE_LATENCY_SUPPORT)
	struct timespec rx_time;
#endif
} dtls_transport_ptr;

typedef struct dtls_st {
	ev_io io;
	dtls_transport_ptr dtls_tptr;
	gnutls_session_t dtls_session;
	udp_port_state_t udp_state;
	time_t last_dtls_rehandshake;
} dtls_st;

/* Given a base MTU, this macro provides the DTLS plaintext data we can send;
 * the output value does not include the DTLS header */
#define DATA_MTU(ws, mtu) \
	(mtu - ws->dtls_crypto_overhead - ws->dtls_proto_overhead)

typedef struct worker_st {
	gnutls_session_t session;

	auth_struct_st *selected_auth;
	const compression_method_st *dtls_selected_comp;
	const compression_method_st *cstp_selected_comp;

	struct http_req_st req;

	/* inique session identifier */
	uint8_t sid[SID_SIZE];
	unsigned int sid_set;

	int cmd_fd;
	int conn_fd;
	sock_type_t conn_type; /* AF_UNIX or something else */

	llhttp_t *parser;

	struct list_head *vconfig;

	/* pointer inside vconfig */
#define WSCREDS(ws) (&ws->vhost->creds)
#define WSCONFIG(ws) (ws->vhost->perm_config.config)
#define WSPCONFIG(ws) (&ws->vhost->perm_config)
	struct vhost_cfg_st *vhost;

	unsigned int auth_state; /* S_AUTH */

	struct sockaddr_un secmod_addr; /* sec-mod unix address */
	socklen_t secmod_addr_len;

	struct sockaddr_storage our_addr; /* our address */
	socklen_t our_addr_len;
	struct sockaddr_storage remote_addr; /* peer's address */
	socklen_t remote_addr_len;
	char our_ip_str[MAX_IP_STR];
	char remote_ip_str[MAX_IP_STR];

	/* this is a snapshot of remote_ip_str at process start - doesn't
	 * get updated. */
	char orig_remote_ip_str[MAX_IP_STR];
	const uint8_t sec_auth_init_hmac[HMAC_DIGEST_SIZE];

	int proto; /* AF_INET or AF_INET6 */

	time_t session_start_time;

	/* for dead peer detection */
	time_t last_msg_udp;
	time_t last_msg_tcp;

	time_t last_nc_msg; /* last message that wasn't control, on any channel */

	time_t last_periodic_check;

	/* set after authentication */
	time_t udp_recv_time; /* time last udp packet was received */
	uint8_t dtls_active_session : 1;
	dtls_st dtls[2];
#define DTLS_ACTIVE(ws) (&ws->dtls[ws->dtls_active_session])
#define DTLS_INACTIVE(ws) (&ws->dtls[ws->dtls_active_session ^ 1])

	/* protection from multiple rehandshakes */
	time_t last_tls_rehandshake;

	/* the time the last stats message was sent */
	time_t last_stats_msg;

	/* for mtu trials */
	unsigned int last_good_mtu;
	unsigned int last_bad_mtu;

	/* bandwidth stats */
	bandwidth_st b_tx;
	bandwidth_st b_rx;

	/* ws->link_mtu: The MTU of the link of the connecting. The plaintext
	 *  data we can send to the client (i.e., MTU of the tun device,
	 *  can be accessed using the DATA_MTU() macro and this value. */
	unsigned int link_mtu;
	unsigned int adv_link_mtu; /* the MTU advertised on connection setup */

	unsigned int
		cstp_crypto_overhead; /* estimated overhead of DTLS ciphersuite + DTLS CSTP HEADER */
	unsigned int cstp_proto_overhead; /* UDP + IP header size */

	unsigned int
		dtls_crypto_overhead; /* estimated overhead of DTLS ciphersuite + DTLS CSTP HEADER */
	unsigned int dtls_proto_overhead; /* UDP + IP header size */

	/* Indicates whether the new IPv6 headers will
	 * be sent or the old */
	unsigned int full_ipv6;

	/* Buffer used by worker */
	uint8_t buffer[16 * 1024];
	/* Buffer used for decompression */
	uint8_t decomp[16 * 1024];
	unsigned int buffer_size;

	/* the following are set only if authentication is complete */

	char username[MAX_USERNAME_SIZE];
	char groupname[MAX_GROUPNAME_SIZE];

	char cert_username[MAX_USERNAME_SIZE];
	char **cert_groups;
	unsigned int cert_groups_size;

	char hostname[MAX_HOSTNAME_SIZE];
	uint8_t cookie[SID_SIZE];

	unsigned int cookie_set;

	GroupCfgSt *user_config;

	uint8_t master_secret[TLS_MASTER_SIZE];
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	unsigned int cert_auth_ok;
	int tun_fd;

	/* ban points to be sent on exit */
	unsigned int ban_points;

	/* tun device stats */
	uint64_t tun_bytes_in;
	uint64_t tun_bytes_out;

	/* information on the tun device addresses and network */
	struct vpn_st vinfo;
	unsigned int default_route;

	void *main_pool; /* to be used only on deinitialization */

#if defined(CAPTURE_LATENCY_SUPPORT)
	/* latency stats */
	struct {
		uint64_t median_total;
		uint64_t rms_total;
		uint64_t sample_set_count;
		size_t next_sample;
		time_t last_stats_msg;
		uint32_t samples[LATENCY_SAMPLE_SIZE];
	} latency;
#endif
	bool camouflage_check_passed;
} worker_st;

void vpn_server(struct worker_st *ws);

int auth_cookie(worker_st *ws, void *cookie, size_t cookie_size);
int auth_user_deinit(worker_st *ws);

int get_auth_handler(worker_st *server, unsigned int http_ver);
int post_auth_handler(worker_st *server, unsigned int http_ver);
int post_kkdcp_handler(worker_st *server, unsigned int http_ver);
int get_cert_handler(worker_st *ws, unsigned int http_ver);
int get_cert_der_handler(worker_st *ws, unsigned int http_ver);
int get_ca_handler(worker_st *ws, unsigned int http_ver);
int get_ca_der_handler(worker_st *ws, unsigned int http_ver);
int get_svc_handler(worker_st *ws, unsigned int http_ver);
int post_svc_handler(worker_st *ws, unsigned int http_ver);

int response_404(worker_st *ws, unsigned int http_ver);
int response_401(worker_st *ws, unsigned int http_ver, char *realm);
int get_empty_handler(worker_st *server, unsigned int http_ver);
#ifdef ANYCONNECT_CLIENT_COMPAT
int get_config_handler(worker_st *ws, unsigned int http_ver);
#endif
int get_string_handler(worker_st *ws, unsigned int http_ver);
int get_dl_handler(worker_st *ws, unsigned int http_ver);
int get_cert_names(worker_st *ws, const gnutls_datum_t *raw);

void set_resume_db_funcs(gnutls_session_t);

typedef int (*url_handler_fn)(worker_st *, unsigned int http_ver);
int http_url_cb(llhttp_t *parser, const char *at, size_t length);
int http_header_value_cb(llhttp_t *parser, const char *at, size_t length);
int http_header_field_cb(llhttp_t *parser, const char *at, size_t length);
int http_header_complete_cb(llhttp_t *parser);
int http_message_complete_cb(llhttp_t *parser);
int http_body_cb(llhttp_t *parser, const char *at, size_t length);
void http_req_deinit(worker_st *ws);
void http_req_reset(worker_st *ws);
void http_req_init(worker_st *ws);

unsigned int valid_hostname(const char *host);

url_handler_fn http_get_url_handler(const char *url);
url_handler_fn http_post_url_handler(worker_st *ws, const char *url);
url_handler_fn http_post_known_service_check(worker_st *ws, const char *url);

int complete_vpn_info(worker_st *ws, struct vpn_st *vinfo);

int send_tun_mtu(worker_st *ws, unsigned int mtu);
int handle_commands_from_main(struct worker_st *ws);
int disable_system_calls(struct worker_st *ws);
void ocsigaltstack(struct worker_st *ws);

void exit_worker(worker_st *ws);
void exit_worker_reason(worker_st *ws, unsigned int reason);

int ws_switch_auth_to(struct worker_st *ws, unsigned int auth);
int ws_switch_auth_to_next(struct worker_st *ws);
void ws_add_score_to_ip(worker_st *ws, unsigned int points, unsigned int final,
			unsigned int discon_reason);

int connect_to_secmod(worker_st *ws);
inline static int send_msg_to_secmod(worker_st *ws, int sd, uint8_t cmd,
				     const void *msg, pack_size_func get_size,
				     pack_func pack)
{
	oclog(ws, LOG_DEBUG, "sending message '%s' to secmod",
	      cmd_request_to_str(cmd));

	return send_msg(ws, sd, cmd, msg, get_size, pack);
}

int recv_auth_reply(worker_st *ws, int sd, char **txt, unsigned int *pcounter);
int get_cert_info(worker_st *ws);
int parse_reply(worker_st *ws, char *body, unsigned int body_length,
		const char *field, unsigned int field_size,
		const char *xml_field, unsigned int xml_field_size,
		char **value);

inline static int send_msg_to_main(worker_st *ws, uint8_t cmd, const void *msg,
				   pack_size_func get_size, pack_func pack)
{
	oclog(ws, LOG_DEBUG, "sending message '%s' to main",
	      cmd_request_to_str(cmd));
	return send_msg(ws, ws->cmd_fd, cmd, msg, get_size, pack);
}

int parse_proxy_proto_header(struct worker_st *ws, int fd);

void cookie_authenticate_or_exit(worker_st *ws);

int add_owasp_headers(worker_st *ws);

/* after that time (secs) of inactivity in the UDP part, connection switches to
 * TCP (if activity occurs there).
 */
#define UDP_SWITCH_TIME 15

#endif
