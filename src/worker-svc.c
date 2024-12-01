/*
 * Copyright (C) 2023 Gareth Palmer
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

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <base64-helper.h>

#include <vpn.h>
#include "html.h"
#include <worker.h>
#include <tlslib.h>

int get_svc_handler(worker_st *ws, unsigned int http_ver)
{
	int ret;

	if (!WSCONFIG(ws)->cisco_svc_client_compat)
		oclog(ws, LOG_WARNING,
		      "request to /svc but cisco-svc-client-compat = false");

	if (ws->req.user_agent_type != AGENT_SVC_IPPHONE)
		oclog(ws, LOG_WARNING, "unexpected /svc user-agent of '%s'",
		      ws->req.user_agent);

	oclog(ws, LOG_HTTP_DEBUG, "HTTP sending: 200 OK");
	cstp_cork(ws);

	ret = cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Content-Length: 0\r\n");
	if (ret < 0)
		goto fail;

	ret = cstp_puts(
		ws,
		"Set-Cookie: webvpn=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure\r\n");
	if (ret < 0)
		goto fail;

	/* this tells the client to send a post request with auth credentials */
	ret = cstp_puts(ws, "Set-Cookie: webvpnlogin=1; secure\r\n");
	if (ret < 0)
		goto fail;

	ret = cstp_puts(ws, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		goto fail;

	/* end of headers */
	ret = cstp_puts(ws, "\r\n");
	if (ret < 0)
		goto fail;

	ret = cstp_uncork(ws);
	if (ret < 0)
		goto fail;

	ret = 0;

fail:
	if (ret < 0)
		ret = -1;

	return ret;
}

static int client_auth(worker_st *ws, char *password)
{
	int ret = -1, sd = -1;
	char *msg;
	unsigned int pcounter = 0;
	SecAuthInitMsg init = SEC_AUTH_INIT_MSG__INIT;
	SecAuthContMsg cont = SEC_AUTH_CONT_MSG__INIT;

	if (ws->auth_state != S_AUTH_INACTIVE) {
		oclog(ws, LOG_ERR, "not in auth inactive state");
		return -1;
	}

	ws->auth_state = S_AUTH_INIT;

	if (ws->selected_auth->type & AUTH_TYPE_USERNAME_PASS) {
		ws->groupname[0] = '\0';
		init.user_name = ws->username;
		init.auth_type |= AUTH_TYPE_USERNAME_PASS;
	} else if (ws->selected_auth->type & AUTH_TYPE_CERTIFICATE) {
		init.tls_auth_ok = ws->cert_auth_ok;
		init.cert_user_name = ws->cert_username;
		init.cert_group_names = ws->cert_groups;
		init.n_cert_group_names = ws->cert_groups_size;
		init.auth_type |= AUTH_TYPE_CERTIFICATE;
	}
	init.vhost = ws->vhost->name;
	init.remote_ip = ws->remote_ip_str;
	init.orig_remote_ip = ws->orig_remote_ip_str;
	init.our_ip = ws->our_ip_str;
	init.session_start_time = ws->session_start_time;
	init.hmac.data = (uint8_t *)ws->sec_auth_init_hmac;
	init.hmac.len = sizeof(ws->sec_auth_init_hmac);

	if (ws->req.user_agent[0] != 0)
		init.user_agent = ws->req.user_agent;

	if (ws->req.devtype[0] != 0)
		init.device_type = ws->req.devtype;

	if (ws->req.devplatform[0] != 0)
		init.device_platform = ws->req.devplatform;

	sd = connect_to_secmod(ws);
	if (sd == -1) {
		oclog(ws, LOG_ERR, "failed connecting to sec mod");
		goto fail;
	}

	ret = send_msg_to_secmod(
		ws, sd, CMD_SEC_AUTH_INIT, &init,
		(pack_size_func)sec_auth_init_msg__get_packed_size,
		(pack_func)sec_auth_init_msg__pack);
	if (ret < 0) {
		oclog(ws, LOG_ERR,
		      "failed sending auth init message to sec mod");
		goto fail;
	}

	ret = recv_auth_reply(ws, sd, &msg, &pcounter);

	if (ws->selected_auth->type & AUTH_TYPE_USERNAME_PASS) {
		if (ret != ERR_AUTH_CONTINUE) {
			oclog(ws, LOG_ERR, "not in auth continue state");
			goto fail;
		}

		ws->auth_state = S_AUTH_INIT;

		cont.ip = ws->remote_ip_str;
		cont.password = password;

		if (ws->sid_set != 0) {
			cont.sid.data = ws->sid;
			cont.sid.len = sizeof(ws->sid);
		}

		close(sd);

		sd = connect_to_secmod(ws);
		if (sd == -1) {
			oclog(ws, LOG_ERR, "failed connecting to sec mod");
			goto fail;
		}

		ret = send_msg_to_secmod(
			ws, sd, CMD_SEC_AUTH_CONT, &cont,
			(pack_size_func)sec_auth_cont_msg__get_packed_size,
			(pack_func)sec_auth_cont_msg__pack);
		if (ret < 0) {
			oclog(ws, LOG_ERR,
			      "failed sending auth cont message to sec mod");
			goto fail;
		}

		ret = recv_auth_reply(ws, sd, &msg, &pcounter);
	}

	if (ret != ERR_SUCCESS) {
		oclog(ws, LOG_ERR, "failed authentication for '%s'",
		      ws->username);
		goto fail;
	}

	ws->auth_state = S_AUTH_REQ;

fail:
	if (sd != -1)
		close(sd);

	return ret;
}

int post_svc_handler(worker_st *ws, unsigned int http_ver)
{
	char *username = NULL;
	char *password = NULL;
	int ret = -1;
	char cookie[BASE64_ENCODE_RAW_LENGTH(sizeof(ws->cookie)) + 1];

	if (!WSCONFIG(ws)->cisco_svc_client_compat)
		oclog(ws, LOG_WARNING,
		      "request to /svc but cisco-svc-client-compat = false");

	if (ws->req.user_agent_type != AGENT_SVC_IPPHONE)
		oclog(ws, LOG_WARNING, "unexpected /svc user-agent of '%s'",
		      ws->req.user_agent);

	if (ws->selected_auth->type & AUTH_TYPE_USERNAME_PASS) {
		/* fail if username or password is missing */
		ret = parse_reply(ws, ws->req.body, ws->req.body_length,
				  "username", 8, NULL, 0, &username);
		if (ret < 0) {
			oclog(ws, LOG_ERR, "no username field in body");
			return get_svc_handler(ws, http_ver);
		}

		strlcpy(ws->username, username, sizeof(ws->username));
		talloc_free(username);

		ret = parse_reply(ws, ws->req.body, ws->req.body_length,
				  "password", 8, NULL, 0, &password);
		if (ret < 0) {
			oclog(ws, LOG_ERR, "no password field in body");
			return get_svc_handler(ws, http_ver);
		}
	} else if (ws->selected_auth->type & AUTH_TYPE_CERTIFICATE) {
		ret = get_cert_info(ws);
	}

	if (ret >= 0)
		ret = client_auth(ws, password);
	talloc_free(password);

	if (ret < 0) {
		oclog(ws, LOG_HTTP_DEBUG, "HTTP sending: 401 Unauthorized");
		ret = cstp_printf(ws,
				  "HTTP/1.%d 401 Authentication failed\r\n"
				  "Content-Length: 0\r\n"
				  "\r\n",
				  http_ver);

		if (ret >= 0)
			cstp_fatal_close(ws, GNUTLS_A_ACCESS_DENIED);
		exit_worker(ws);
		return -1;
	}

	oclog(ws, LOG_HTTP_DEBUG, "user '%s' obtained cookie", ws->username);
	ws->auth_state = S_AUTH_COOKIE;

	oc_base64_encode((char *)ws->cookie, sizeof(ws->cookie), cookie,
			 sizeof(cookie));

	/* reply */
	oclog(ws, LOG_HTTP_DEBUG, "HTTP sending: 200 OK");
	cstp_cork(ws);

	ret = cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Connection: Keep-Alive\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Content-Length: 0\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_printf(ws, "Set-Cookie: webvpn=%s; secure\r\n", cookie);
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	/* end of headers */
	ret = cstp_puts(ws, "\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_uncork(ws);
	if (ret < 0)
		return -1;

	return 0;
}
