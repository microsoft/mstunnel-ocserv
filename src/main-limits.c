/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
 * Copyright (C) 2015-2016 Red Hat, Inc.
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

#include <config.h>

#include <fcntl.h>
#include <sys/resource.h>
#include <grp.h>

#include <main.h>
#include <limits.h>

void init_fd_limits_default(main_server_st *s)
{
#ifdef RLIMIT_NOFILE
	int ret = getrlimit(RLIMIT_NOFILE, &s->fd_limits_default_set);

	if (ret < 0) {
		oc_syslog(LOG_ERR, "error in getrlimit: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#endif
}

/* (Maximum clients) + (small buffer) + (sec mod fds)
 * The (small buffer) is to allow unknown fds used by backends (e.g.,
 * gnutls) as well as to allow running up to that many scripts (due to dup2)
 * when close to the maximum limit.
 */
#define MAX_FD_LIMIT(clients) (clients + 128 + s->sec_mod_instance_count * 2)

/* Adjusts the file descriptor limits for the main or worker processes
 */
void set_main_fd_limits(main_server_st *s)
{
#ifdef RLIMIT_NOFILE
	struct rlimit new_set;
	unsigned int max;
	int ret;

	if (GETCONFIG(s)->max_clients > 0)
		max = MAX_FD_LIMIT(GETCONFIG(s)->max_clients);
	else
		// If the admin doesn't specify max_clients,
		// then we are limiting it to around 8K.
		max = MAX_FD_LIMIT(8 * 1024);

	if (max > s->fd_limits_default_set.rlim_cur) {
		new_set.rlim_cur = max;
		new_set.rlim_max = s->fd_limits_default_set.rlim_max;
		ret = setrlimit(RLIMIT_NOFILE, &new_set);
		if (ret < 0) {
			fprintf(stderr,
				"error in setrlimit(%u): %s (cur: %u)\n", max,
				strerror(errno),
				(unsigned int)s->fd_limits_default_set.rlim_cur);
		}
	}
#endif
}

void set_self_oom_score_adj(main_server_st *s)
{
#ifdef __linux__
	static const char proc_self_oom_adj_score_path[] =
		"/proc/self/oom_score_adj";
	static const char oom_adj_score_value[] = "1000";
	size_t written = 0;
	int fd;

	fd = open(proc_self_oom_adj_score_path, O_WRONLY,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1) {
		int e = errno;

		mslog(s, NULL, LOG_ERR, "cannot open %s: %s",
		      proc_self_oom_adj_score_path, strerror(e));
		goto cleanup;
	}

	written = write(fd, oom_adj_score_value, sizeof(oom_adj_score_value));
	if (written != sizeof(oom_adj_score_value)) {
		int e = errno;

		mslog(s, NULL, LOG_ERR, "cannot write %s: %s",
		      proc_self_oom_adj_score_path, strerror(e));
		goto cleanup;
	}

cleanup:
	if (fd >= 0) {
		close(fd);
	}
#endif
}
