/*
 * Copyright (C) 2024 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Unit test for proxy protocol v2 TLV parsing, specifically verifying that
 * PP2_SUBTYPE_SSL_CN (0x22) is correctly parsed as a sub-TLV inside the
 * PP2_TYPE_SSL body rather than as a top-level TLV.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#define UNDER_TEST
#define force_read_timeout(fd, buf, count, time) read(fd, buf, count)
#include "../src/worker-proxyproto.c"

/* Proxy protocol v2 signature (12 bytes) */
static const uint8_t PP2_SIG[] =
	"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

/*
 * Build a proxy protocol v2 packet with an IPv4 address block and an optional
 * PP2_TYPE_SSL TLV (with PP2_SUBTYPE_SSL_CN sub-TLV) into buf[].
 * Returns the total number of bytes written.
 *
 * ssl_client_flags: PP2_CLIENT_* flags (0 = omit SSL TLV entirely)
 * ssl_verify:       value for the verify field (0 = certificate verified)
 * cn:               common name string, or NULL to omit the CN sub-TLV
 */
static size_t build_v2_packet(uint8_t *buf, size_t bufsz,
			      uint8_t ssl_client_flags, uint32_t ssl_verify,
			      const char *cn)
{
	size_t pos = 0;

	/* --- fixed 16-byte header --- */
	/* signature */
	memcpy(buf + pos, PP2_SIG, 12);
	pos += 12;
	/* ver_cmd: version 2, PROXY command */
	buf[pos++] = 0x21;
	/* family: AF_INET (0x1) | TCP (0x1) */
	buf[pos++] = 0x11;
	/* len placeholder (2 bytes, filled in below) */
	size_t len_offset = pos;
	buf[pos++] = 0;
	buf[pos++] = 0;

	/* --- payload starts here --- */
	size_t payload_start = pos;

	/* IPv4 address block (12 bytes):
	 *  src IP  1.2.3.4   (4 bytes)
	 *  dst IP  5.6.7.8   (4 bytes)
	 *  src port 100      (2 bytes, network order)
	 *  dst port 443      (2 bytes, network order)
	 */
	buf[pos++] = 1;
	buf[pos++] = 2;
	buf[pos++] = 3;
	buf[pos++] = 4;
	buf[pos++] = 5;
	buf[pos++] = 6;
	buf[pos++] = 7;
	buf[pos++] = 8;
	buf[pos++] = 0x00;
	buf[pos++] = 0x64; /* src port 100 */
	buf[pos++] = 0x01;
	buf[pos++] = 0xBB; /* dst port 443 */

	if (ssl_client_flags != 0) {
		/* PP2_TYPE_SSL TLV header — length filled in below */
		size_t ssl_tlv_hdr = pos;
		buf[pos++] = 0x20; /* PP2_TYPE_SSL */
		size_t ssl_len_offset = pos;
		buf[pos++] = 0;
		buf[pos++] = 0; /* length placeholder */

		/* pp2_tlv_ssl fixed part (5 bytes):
		 *   client (1 byte) + verify (4 bytes, network order)
		 */
		buf[pos++] = ssl_client_flags;
		buf[pos++] = (ssl_verify >> 24) & 0xff;
		buf[pos++] = (ssl_verify >> 16) & 0xff;
		buf[pos++] = (ssl_verify >> 8) & 0xff;
		buf[pos++] = (ssl_verify) & 0xff;

		if (cn != NULL) {
			size_t cn_len = strlen(cn);
			/* PP2_SUBTYPE_SSL_CN sub-TLV */
			buf[pos++] = 0x22; /* PP2_TYPE_SSL_CN */
			buf[pos++] = (cn_len >> 8) & 0xff;
			buf[pos++] = cn_len & 0xff;
			memcpy(buf + pos, cn, cn_len);
			pos += cn_len;
		}

		/* back-fill SSL TLV length (body after the 3-byte TLV header) */
		uint16_t ssl_body_len = (uint16_t)(pos - ssl_tlv_hdr - 3);
		buf[ssl_len_offset] = (ssl_body_len >> 8) & 0xff;
		buf[ssl_len_offset + 1] = ssl_body_len & 0xff;
	}

	/* back-fill payload length in fixed header */
	uint16_t payload_len = (uint16_t)(pos - payload_start);
	buf[len_offset] = (payload_len >> 8) & 0xff;
	buf[len_offset + 1] = payload_len & 0xff;

	assert(pos <= bufsz);
	return pos;
}

/*
 * Build a proxy protocol v2 packet with an IPv6 address block into buf[].
 * Returns the total number of bytes written.
 */
static size_t build_v2_ipv6_packet(uint8_t *buf, size_t bufsz,
				   const struct in6_addr *src_addr,
				   uint16_t src_port,
				   const struct in6_addr *dst_addr,
				   uint16_t dst_port)
{
	size_t pos = 0;
	uint16_t sp, dp, plen;

	memcpy(buf + pos, PP2_SIG, 12);
	pos += 12;
	buf[pos++] = 0x21; /* ver=2, PROXY command */
	buf[pos++] = 0x21; /* AF_INET6 (0x2) | TCP (0x1) */

	size_t len_offset = pos;
	buf[pos++] = 0;
	buf[pos++] = 0;

	size_t payload_start = pos;

	/* IPv6 address block (36 bytes):
	 *  src IP   (16 bytes)
	 *  dst IP   (16 bytes)
	 *  src port (2 bytes, network order)
	 *  dst port (2 bytes, network order)
	 */
	memcpy(buf + pos, src_addr, 16);
	pos += 16;
	memcpy(buf + pos, dst_addr, 16);
	pos += 16;
	sp = htons(src_port);
	dp = htons(dst_port);
	memcpy(buf + pos, &sp, 2);
	pos += 2;
	memcpy(buf + pos, &dp, 2);
	pos += 2;

	plen = (uint16_t)(pos - payload_start);
	buf[len_offset] = (plen >> 8) & 0xff;
	buf[len_offset + 1] = plen & 0xff;

	assert(pos <= bufsz);
	return pos;
}

/*
 * Feed pkt into a pipe and call parse_proxy_proto_header.
 * ws->conn_type must be set by the caller.
 */
static int run_parse(struct worker_st *ws, const uint8_t *pkt, size_t pkt_len)
{
	int fds[2];
	int ret;

	if (pipe(fds) < 0) {
		perror("pipe");
		return -1;
	}

	/* write all bytes; pipe buffer is large enough for our small packets */
	if (write(fds[1], pkt, pkt_len) != (ssize_t)pkt_len) {
		perror("write");
		close(fds[0]);
		close(fds[1]);
		return -1;
	}
	close(fds[1]);

	ret = parse_proxy_proto_header(ws, fds[0]);
	close(fds[0]);
	return ret;
}

int main(void)
{
	uint8_t pkt[256];
	size_t pkt_len;
	struct worker_st ws = { 0 };
	int ret;

	/* ------------------------------------------------------------------ */
	/* Test 1: valid SSL TLV with CN sub-TLV — cert_auth_ok and username   */
	/* ------------------------------------------------------------------ */
	memset(&ws, 0, sizeof(ws));
	ws.conn_type = SOCK_TYPE_UNIX; /* triggers TLV parsing */

	/*
	 * PP2_CLIENT_SSL (0x01) | PP2_CLIENT_CERT_SESS (0x04) = 0x05
	 * verify = 0  =>  cert verified
	 * CN = "testuser"
	 */
	pkt_len = build_v2_packet(pkt, sizeof(pkt), 0x05, 0, "testuser");
	ret = run_parse(&ws, pkt, pkt_len);
	if (ret != 0) {
		fprintf(stderr, "Test 1: parse failed (%d)\n", ret);
		return 1;
	}
	if (!ws.cert_auth_ok) {
		fprintf(stderr, "Test 1: cert_auth_ok not set\n");
		return 1;
	}
	if (strcmp(ws.cert_username, "testuser") != 0) {
		fprintf(stderr,
			"Test 1: cert_username='%s', expected 'testuser'\n",
			ws.cert_username);
		return 1;
	}

	/* ------------------------------------------------------------------ */
	/* Test 2: verify != 0 — cert NOT accepted, no CN extracted            */
	/* ------------------------------------------------------------------ */
	memset(&ws, 0, sizeof(ws));
	ws.conn_type = SOCK_TYPE_UNIX;

	pkt_len = build_v2_packet(pkt, sizeof(pkt), 0x05, 1 /* verify!=0 */,
				  "testuser");
	ret = run_parse(&ws, pkt, pkt_len);
	if (ret != 0) {
		fprintf(stderr, "Test 2: parse failed (%d)\n", ret);
		return 1;
	}
	if (ws.cert_auth_ok) {
		fprintf(stderr,
			"Test 2: cert_auth_ok should NOT be set when verify!=0\n");
		return 1;
	}
	if (ws.cert_username[0] != '\0') {
		fprintf(stderr, "Test 2: cert_username should be empty\n");
		return 1;
	}

	/* ------------------------------------------------------------------ */
	/* Test 3: PP2_CLIENT_CERT_SESS not set — no cert auth                 */
	/* ------------------------------------------------------------------ */
	memset(&ws, 0, sizeof(ws));
	ws.conn_type = SOCK_TYPE_UNIX;

	/* only PP2_CLIENT_SSL, no PP2_CLIENT_CERT_SESS */
	pkt_len = build_v2_packet(pkt, sizeof(pkt), 0x01, 0, "testuser");
	ret = run_parse(&ws, pkt, pkt_len);
	if (ret != 0) {
		fprintf(stderr, "Test 3: parse failed (%d)\n", ret);
		return 1;
	}
	if (ws.cert_auth_ok) {
		fprintf(stderr,
			"Test 3: cert_auth_ok should NOT be set without CERT_SESS\n");
		return 1;
	}

	/* ------------------------------------------------------------------ */
	/* Test 4: valid cert but no CN sub-TLV — cert_auth_ok set, name empty */
	/* ------------------------------------------------------------------ */
	memset(&ws, 0, sizeof(ws));
	ws.conn_type = SOCK_TYPE_UNIX;

	pkt_len = build_v2_packet(pkt, sizeof(pkt), 0x05, 0, NULL /* no CN */);
	ret = run_parse(&ws, pkt, pkt_len);
	if (ret != 0) {
		fprintf(stderr, "Test 4: parse failed (%d)\n", ret);
		return 1;
	}
	if (!ws.cert_auth_ok) {
		fprintf(stderr, "Test 4: cert_auth_ok not set\n");
		return 1;
	}
	if (ws.cert_username[0] != '\0') {
		fprintf(stderr,
			"Test 4: cert_username should be empty when no CN sub-TLV\n");
		return 1;
	}

	/* ------------------------------------------------------------------ */
	/* Test 5: no SSL TLV at all — conn_type TCP, TLVs not parsed          */
	/* ------------------------------------------------------------------ */
	memset(&ws, 0, sizeof(ws));
	ws.conn_type = SOCK_TYPE_TCP; /* TLV parsing skipped */

	pkt_len = build_v2_packet(pkt, sizeof(pkt), 0x05, 0, "testuser");
	ret = run_parse(&ws, pkt, pkt_len);
	if (ret != 0) {
		fprintf(stderr, "Test 5: parse failed (%d)\n", ret);
		return 1;
	}
	if (ws.cert_auth_ok) {
		fprintf(stderr,
			"Test 5: cert_auth_ok should NOT be set for TCP conn\n");
		return 1;
	}

	/* ------------------------------------------------------------------ */
	/* Test 6: IPv6 proxy protocol v2 — both remote and local addr correct  */
	/*                                                                       */
	/* Reproducer for the bug where sa->sin6_family was assigned before sa  */
	/* was redirected to &ws->our_addr, leaving our_addr.sin6_family == 0. */
	/* ------------------------------------------------------------------ */
	{
		struct in6_addr src6, dst6;
		struct sockaddr_in6 *rem6, *loc6;

		memset(&ws, 0, sizeof(ws));
		ws.conn_type = SOCK_TYPE_TCP;

		inet_pton(AF_INET6, "2001:db8::1", &src6);
		inet_pton(AF_INET6, "2001:db8::2", &dst6);

		pkt_len = build_v2_ipv6_packet(pkt, sizeof(pkt), &src6, 1234,
					       &dst6, 443);
		ret = run_parse(&ws, pkt, pkt_len);
		if (ret != 0) {
			fprintf(stderr, "Test 6: parse failed (%d)\n", ret);
			return 1;
		}

		if (ws.remote_addr_len != sizeof(struct sockaddr_in6)) {
			fprintf(stderr, "Test 6: remote_addr_len wrong (%u)\n",
				ws.remote_addr_len);
			return 1;
		}
		if (ws.our_addr_len != sizeof(struct sockaddr_in6)) {
			fprintf(stderr, "Test 6: our_addr_len wrong (%u)\n",
				ws.our_addr_len);
			return 1;
		}

		rem6 = (void *)&ws.remote_addr;
		loc6 = (void *)&ws.our_addr;

		if (rem6->sin6_family != AF_INET6) {
			fprintf(stderr,
				"Test 6: remote sin6_family wrong: %d\n",
				rem6->sin6_family);
			return 1;
		}
		/* This check catches the bug: sin6_family was written to
		 * remote_addr a second time instead of to our_addr. */
		if (loc6->sin6_family != AF_INET6) {
			fprintf(stderr,
				"Test 6: local sin6_family wrong: %d (expected %d)\n",
				loc6->sin6_family, AF_INET6);
			return 1;
		}

		if (memcmp(&rem6->sin6_addr, &src6, 16) != 0) {
			fprintf(stderr, "Test 6: remote address mismatch\n");
			return 1;
		}
		if (memcmp(&loc6->sin6_addr, &dst6, 16) != 0) {
			fprintf(stderr, "Test 6: local address mismatch\n");
			return 1;
		}
		if (ntohs(rem6->sin6_port) != 1234) {
			fprintf(stderr, "Test 6: remote port wrong: %u\n",
				ntohs(rem6->sin6_port));
			return 1;
		}
		if (ntohs(loc6->sin6_port) != 443) {
			fprintf(stderr, "Test 6: local port wrong: %u\n",
				ntohs(loc6->sin6_port));
			return 1;
		}
	}

	return 0;
}
