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
# define OC_LOG_H

#include <stdint.h>
#include <stdio.h>
#include <syslog.h>

extern int syslog_open;

#ifdef __GNUC__
# define oc_syslog(prio, fmt, ...) do { \
	if (syslog_open) { \
		syslog(prio, "sec-mod: "fmt, ##__VA_ARGS__); \
	} else { \
		fprintf(stderr, "sec-mod: "fmt, ##__VA_ARGS__); \
	}} while(0)
#else
# define oc_syslog(prio, ...) do { \
	if (syslog_open) { \
		syslog(prio, __VA_ARGS__); \
	} else { \
		fprintf(stderr, __VA_ARGS__); \
	}} while(0)
#endif

#ifdef UNDER_TEST
/* for testing */
# define mslog(...)
# define oclog(...)
# define seclog(...)

#else

struct main_server_st;
struct worker_st;
struct proc_st;
struct sec_mod_st;

void
__attribute__ ((format(printf, 4, 5)))
    _mslog(const struct main_server_st * s, const struct proc_st* proc,
    	int priority, const char *fmt, ...);

void __attribute__ ((format(printf, 3, 4)))
    _oclog(const struct worker_st * server, int priority, const char *fmt, ...);

void __attribute__ ((format(printf, 3, 4)))
    _seclog(const struct sec_mod_st* sec, int priority, const char *fmt, ...);

# ifdef __GNUC__
#  define mslog(s, proc, prio, fmt, ...) \
	(prio==LOG_ERR)?_mslog(s, proc, prio, "%s:%d: "fmt, __FILE__, __LINE__, ##__VA_ARGS__): \
	_mslog(s, proc, prio, fmt, ##__VA_ARGS__)

#  define oclog(server, prio, fmt, ...) \
	(prio==LOG_ERR)?_oclog(server, prio, "%s:%d: "fmt, __FILE__, __LINE__, ##__VA_ARGS__): \
	_oclog(server, prio, fmt, ##__VA_ARGS__)

#  define seclog(sec, prio, fmt, ...) \
	(prio==LOG_ERR)?_seclog(sec, prio, "%s:%d: "fmt, __FILE__, __LINE__, ##__VA_ARGS__): \
	_seclog(sec, prio, fmt, ##__VA_ARGS__)
# else
#  define mslog _mslog
#  define seclog _seclog
#  define oclog _oclog
# endif

void mslog_hex(const struct main_server_st * s, const struct proc_st* proc,
	       int priority, const char *prefix, uint8_t* bin, unsigned bin_size, unsigned b64);

void oclog_hex(const struct worker_st* ws, int priority,
		const char *prefix, uint8_t* bin, unsigned bin_size, unsigned b64);

void seclog_hex(const struct sec_mod_st* sec, int priority,
		const char *prefix, uint8_t* bin, unsigned bin_size, unsigned b64);

#endif

#endif /* OC_LOG_H */
