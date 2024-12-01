/*
 * Copyright (C) 2015 Nikos Mavrogiannopoulos
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
#ifndef OC_MAIN_BAN_H
#define OC_MAIN_BAN_H

#include "main.h"

typedef struct inaddr_st {
	uint8_t ip[16];
	unsigned int size; /* 4 or 16 */
} inaddr_st;

typedef struct ban_entry_st {
	inaddr_st ip;
	unsigned int score;

	time_t last_reset; /* the time its score counting started */
	time_t expires; /* the time after the client is allowed to login */
} ban_entry_st;

void cleanup_banned_entries(main_server_st *s);
unsigned int check_if_banned(main_server_st *s, struct sockaddr_storage *addr,
			     socklen_t addr_size);
int add_str_ip_to_ban_list(main_server_st *s, const char *ip,
			   unsigned int score);
int remove_ip_from_ban_list(main_server_st *s, const uint8_t *ip,
			    unsigned int size);
unsigned int main_ban_db_elems(main_server_st *s);
void main_ban_db_deinit(main_server_st *s);
void *main_ban_db_init(main_server_st *s);

int if_address_init(main_server_st *s);
void if_address_cleanup(main_server_st *s);

#endif
