/*
 * Copyright (C) 2013-2016 Nikos Mavrogiannopoulos
 * Copyright (C) 2015-2016 Red Hat, Inc.
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
#ifndef OC_TLSLIB_H
#define OC_TLSLIB_H

#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>
#include <vpn.h>
#include <ccan/htable/htable.h>
#include <errno.h>

#if GNUTLS_VERSION_NUMBER < 0x030200
#define GNUTLS_DTLS1_2 202
#endif

#if GNUTLS_VERSION_NUMBER >= 0x030305
#define ZERO_COPY
#endif

#define PSK_KEY_SIZE 32
#if TLS_MASTER_SIZE < PSK_KEY_SIZE
#error
#endif

typedef struct {
	struct htable *ht;
	unsigned int entries;
} tls_sess_db_st;

typedef struct tls_st {
	gnutls_certificate_credentials_t xcred;
	gnutls_psk_server_credentials_t pskcred;
	gnutls_priority_t cprio;
	gnutls_dh_params_t dh_params;
	gnutls_datum_t ocsp_response;
} tls_st;

struct vhost_cfg_st;

void tls_reload_crl(struct main_server_st *s, struct vhost_cfg_st *vhost,
		    unsigned int force);
void tls_global_init(void);
void tls_vhost_init(struct vhost_cfg_st *vhost);
void tls_vhost_deinit(struct vhost_cfg_st *vhost);
void tls_load_files(struct main_server_st *s, struct vhost_cfg_st *vhost,
		    unsigned int silent);
void tls_load_prio(struct main_server_st *s, struct vhost_cfg_st *vhost);

size_t tls_get_overhead(gnutls_protocol_t, gnutls_cipher_algorithm_t,
			gnutls_mac_algorithm_t);

#define GNUTLS_FATAL_ERR DTLS_FATAL_ERR

#define GNUTLS_ALERT_PRINT(ws, session, err)                              \
	{                                                                 \
		if (err == GNUTLS_E_FATAL_ALERT_RECEIVED ||               \
		    err == GNUTLS_E_WARNING_ALERT_RECEIVED) {             \
			oclog(ws, LOG_NOTICE, "TLS alert (at %s:%d): %s", \
			      __FILE__, __LINE__,                         \
			      gnutls_alert_get_name(                      \
				      gnutls_alert_get(session)));        \
		}                                                         \
	}

#define DTLS_FATAL_ERR_CMD(err, CMD)                                     \
	{                                                                \
		if (err < 0 && gnutls_error_is_fatal(err) != 0) {        \
			if (syslog_open)                                 \
				syslog(LOG_WARNING,                      \
				       "GnuTLS error (at %s:%d): %s",    \
				       __FILE__, __LINE__,               \
				       gnutls_strerror(err));            \
			else                                             \
				fprintf(stderr,                          \
					"GnuTLS error (at %s:%d): %s\n", \
					__FILE__, __LINE__,              \
					gnutls_strerror(err));           \
			CMD;                                             \
		}                                                        \
	}

#define DTLS_FATAL_ERR(err) DTLS_FATAL_ERR_CMD(err, exit(EXIT_FAILURE))

#define CSTP_FATAL_ERR_CMD(ws, err, CMD)                                       \
	{                                                                      \
		if (ws->session != NULL) {                                     \
			if (err < 0 && gnutls_error_is_fatal(err) != 0) {      \
				oclog(ws, LOG_WARNING,                         \
				      "GnuTLS error (at %s:%d): %s", __FILE__, \
				      __LINE__, gnutls_strerror(err));         \
				CMD;                                           \
			}                                                      \
		} else {                                                       \
			if (err < 0 && errno != EINTR && errno != EAGAIN) {    \
				oclog(ws, LOG_WARNING,                         \
				      "socket error (at %s:%d): %s", __FILE__, \
				      __LINE__, strerror(errno));              \
				CMD;                                           \
			}                                                      \
		}                                                              \
	}

#define CSTP_FATAL_ERR(ws, err) CSTP_FATAL_ERR_CMD(ws, err, exit(EXIT_FAILURE))

void tls_close(gnutls_session_t session);

unsigned int tls_has_session_cert(struct worker_st *ws);

void tls_fatal_close(gnutls_session_t session, gnutls_alert_description_t a);

typedef struct {
	/* does not allow resumption from different address
   * than the original */
	struct sockaddr_storage remote_addr;
	socklen_t remote_addr_len;

	char session_id[GNUTLS_MAX_SESSION_ID];
	unsigned int session_id_size;

	char session_data[MAX_SESSION_DATA_SIZE];
	unsigned int session_data_size;

	char *vhostname;
} tls_cache_st;

#define TLS_SESSION_EXPIRATION_TIME(config) ((config)->cookie_timeout)
#define DEFAULT_MAX_CACHED_TLS_SESSIONS 64

void tls_cache_init(void *pool, tls_sess_db_st *db);
void tls_cache_deinit(tls_sess_db_st *db);
void *calc_sha1_hash(void *pool, char *file, unsigned int cert);

/* TLS API */
int __attribute__((format(printf, 2, 3))) cstp_printf(struct worker_st *ws,
						      const char *fmt, ...);
void cstp_close(struct worker_st *ws);
void cstp_fatal_close(struct worker_st *ws, gnutls_alert_description_t a);
ssize_t cstp_recv(struct worker_st *ws, void *data, size_t data_size);
ssize_t cstp_send_file(struct worker_st *ws, const char *file);
ssize_t cstp_send(struct worker_st *ws, const void *data, size_t data_size);
#define cstp_puts(s, str) cstp_send(s, str, sizeof(str) - 1)

void cstp_cork(struct worker_st *ws);
int cstp_uncork(struct worker_st *ws);

/* DTLS API */
void dtls_close(struct dtls_st *dtls);
ssize_t dtls_send(struct dtls_st *dtls, const void *data, size_t data_size);

/* packet API */
inline static void packet_deinit(void *p)
{
#ifdef ZERO_COPY
	gnutls_packet_t packet = p;

	if (packet)
		gnutls_packet_deinit(packet);
#endif
}

ssize_t cstp_recv_packet(struct worker_st *ws, gnutls_datum_t *data, void **p);
ssize_t dtls_recv_packet(struct dtls_st *dtls, gnutls_datum_t *data, void **p);

/* Helper functions */
unsigned int need_file_reload(const char *file, time_t last_access);
void safe_hash(const uint8_t *data, unsigned int data_size, uint8_t output[20]);

#endif
