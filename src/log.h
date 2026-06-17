/*
 * Copyright (C) 2023 Nikos Mavrogiannopoulos
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
#ifndef OC_LOG_H
#define OC_LOG_H

#include <stdint.h>
#include <stdio.h>
#include <syslog.h>
#include "defs.h"

extern int syslog_open;
extern int global_log_prio;

/* For logging in the main process or sec-mod use the following:
 * mslog(const struct main_server_st * s, const struct proc_st* proc,
 *	 int priority, const char *fmt, ...);
 * seclog(const struct sec_mod_st* sec, int priority, const char *fmt, ...);
 *	  int priority, const char *fmt, ...);
 *
 * For logging in the worker process:
 * oclog(const struct worker_st * server, int priority, const char *fmt, ...);
 *
 * Each ensures that the log gets the necessary information to distinguish
 * between sessions and users. On low-level functions or on startup use:
 * oc_syslog(int priority, const char *fmt, ...);
 *
 * All the logging functions respect the configured log-level and
 * send the logging to stderr or syslog, as requested.
 */

#ifdef __GNUC__
#define _oc_syslog(prio, fmt, ...)                                \
	do {                                                      \
		if (syslog_open) {                                \
			syslog(prio, fmt, ##__VA_ARGS__);         \
		} else {                                          \
			fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
		}                                                 \
	} while (0)
#else
#define _oc_syslog(prio, ...)                         \
	do {                                          \
		if (syslog_open) {                    \
			syslog(prio, __VA_ARGS__);    \
		} else {                              \
			fprintf(stderr, __VA_ARGS__); \
			fputc('\n', stderr);          \
		}                                     \
	} while (0)
#endif

#ifdef UNDER_TEST
/* for testing */
#define mslog(...)
#define oclog(...)
#define seclog(...)
#define oc_syslog _oc_syslog

#else

struct main_server_st;
struct worker_st;
struct proc_st;
struct sec_mod_st;

void __attribute__((format(printf, 4, 5)))
_mslog(const struct main_server_st *s, const struct proc_st *proc, int priority,
       const char *fmt, ...);

void __attribute__((format(printf, 3, 4)))
_oclog(const struct worker_st *server, int priority, const char *fmt, ...);

void __attribute__((format(printf, 3, 4)))
_seclog(const struct sec_mod_st *sec, int priority, const char *fmt, ...);

void __attribute__((format(printf, 2, 3))) oc_syslog(int priority,
						     const char *fmt, ...);

#ifdef __GNUC__
#define mslog(s, proc, prio, fmt, ...)                                     \
	(prio == LOG_ERR) ? _mslog(s, proc, prio, "%s:%d: " fmt, __FILE__, \
				   __LINE__, ##__VA_ARGS__) :              \
			    _mslog(s, proc, prio, fmt, ##__VA_ARGS__)

#define oclog(server, prio, fmt, ...)                                     \
	(prio == LOG_ERR) ? _oclog(server, prio, "%s:%d: " fmt, __FILE__, \
				   __LINE__, ##__VA_ARGS__) :             \
			    _oclog(server, prio, fmt, ##__VA_ARGS__)

#define seclog(sec, prio, fmt, ...)                                     \
	(prio == LOG_ERR) ? _seclog(sec, prio, "%s:%d: " fmt, __FILE__, \
				    __LINE__, ##__VA_ARGS__) :          \
			    _seclog(sec, prio, fmt, ##__VA_ARGS__)
#else
#define mslog _mslog
#define seclog _seclog
#define oclog _oclog
#endif

void mslog_hex(const struct main_server_st *s, const struct proc_st *proc,
	       int priority, const char *prefix, uint8_t *bin,
	       unsigned int bin_size, unsigned int b64);

void oclog_hex(const struct worker_st *ws, int priority, const char *prefix,
	       uint8_t *bin, unsigned int bin_size, unsigned int b64);

void seclog_hex(const struct sec_mod_st *sec, int priority, const char *prefix,
		uint8_t *bin, unsigned int bin_size, unsigned int b64);

#endif

/* Returns zero when the given priority is not sufficient
 * for logging. Updates the priority with */
inline static unsigned int log_check_priority(int oc_priority, int log_prio,
					      int *syslog_prio)
{
	switch (oc_priority) {
	case LOG_ERR:
	case LOG_WARNING:
	case LOG_NOTICE:
		if (syslog_prio)
			*syslog_prio = oc_priority;
		break;
	case LOG_DEBUG:
		if (log_prio < OCLOG_DEBUG)
			return 0;
		if (syslog_prio)
			*syslog_prio = oc_priority;
		break;
	case LOG_INFO:
		if (log_prio < OCLOG_INFO)
			return 0;

		if (syslog_prio)
			*syslog_prio = oc_priority;
		break;
	case LOG_HTTP_DEBUG:
		if (log_prio < OCLOG_HTTP)
			return 0;

		if (syslog_prio)
			*syslog_prio = LOG_DEBUG;
		break;
	case LOG_TRANSFER_DEBUG:
		if (log_prio < OCLOG_TRANSFERRED)
			return 0;

		if (syslog_prio)
			*syslog_prio = LOG_DEBUG;
		break;
	case LOG_SENSITIVE:
		if (log_prio < OCLOG_SENSITIVE)
			return 0;

		if (syslog_prio)
			*syslog_prio = LOG_DEBUG;
		break;
	default:
		syslog(LOG_DEBUG, "unknown log level %d", oc_priority);

		if (syslog_prio)
			*syslog_prio = LOG_DEBUG;
	}

	return 1;
}

#endif /* OC_LOG_H */
