/*
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
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

/*
 * Verify that pam_stack_alloc() produces a PROT_NONE guard page that converts
 * coroutine stack overflow into a deterministic fault rather than silent heap
 * corruption (issues #619, #657).
 *
 * A PCL coroutine is created on the stack returned by pam_stack_alloc().  The
 * coroutine recurses until the stack is exhausted.  A SIGSEGV handler (running
 * on an alternate signal stack) checks that the fault address falls within the
 * guard page — proving it was the guard page that fired, not an accidental
 * fault past the end of an unguarded malloc'd buffer.
 *
 * Linux only — pam_stack_alloc() installs a guard page only on Linux.
 * Returns 77 (meson skip) on other platforms.
 */

#include <config.h>

#ifndef __linux__
int main(void)
{
	return 77; /* skip on non-Linux */
}
#else

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pcl.h>
#include "auth/pam-stack.h"

/* Small coroutine stack: enough for PCL bookkeeping, small enough to overflow
 * quickly under the recursive load below. */
#define TEST_STACK_SIZE (64 * 1024)

/* Alternate signal stack — static so no allocation is needed after fork. */
static char altstack_buf[65536];

/* Guard page extent, set before fork so the child inherits the values. */
static void *guard_base;
static size_t guard_size;

static void sigsegv_handler(int sig, siginfo_t *si, void *ctx)
{
	(void)sig;
	(void)ctx;
	/* _exit(0) only when the fault is precisely in the guard page. */
	if ((char *)si->si_addr >= (char *)guard_base &&
	    (char *)si->si_addr < (char *)guard_base + guard_size)
		_exit(0);
	/* Fault elsewhere — not the guard page; report failure. */
	_exit(1);
}

static void recurse(int depth);
/* volatile pointer breaks static infinite-recursion analysis */
static void (*volatile recurse_ptr)(int) = recurse;

/* Each frame consumes ~512 bytes; ~128 frames exhaust a 64 KB stack. */
static void recurse(int depth)
{
	volatile char frame[512];
	frame[0] = (char)depth;
	(void)frame[0]; /* read back to prevent the frame being optimized away */
	recurse_ptr(depth + 1);
}

static void overflow_coroutine(void *data)
{
	(void)data;
	recurse(0);
	/* unreachable — loop so PCL never sees a clean return */
	while (1)
		co_resume();
}

int main(void)
{
	struct pam_stack_st st = { 0 };
	struct sigaction sa;
	stack_t ss;
	void *stack;
	pid_t pid;
	int status;

	stack = pam_stack_alloc(&st, TEST_STACK_SIZE);
	if (stack == NULL) {
		fprintf(stderr, "pam_stack_alloc failed\n");
		return 77;
	}

	/* Record the guard page extent for the signal handler. */
	guard_base = st.base;
	guard_size = (size_t)((char *)stack - (char *)st.base);

	pid = fork();
	if (pid < 0) {
		perror("fork");
		pam_stack_free(&st);
		return 1;
	}

	if (pid == 0) {
		/* Child: install an alternate signal stack so the SIGSEGV
		 * handler can run even after the coroutine stack is exhausted. */
		ss.ss_sp = altstack_buf;
		ss.ss_size = sizeof(altstack_buf);
		ss.ss_flags = 0;
		if (sigaltstack(&ss, NULL) == -1) {
			perror("sigaltstack");
			_exit(1);
		}

		sa.sa_sigaction = sigsegv_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
		if (sigaction(SIGSEGV, &sa, NULL) == -1) {
			perror("sigaction");
			_exit(1);
		}

		coroutine_t cr = co_create(overflow_coroutine, NULL, stack,
					   TEST_STACK_SIZE);
		if (cr == NULL) {
			fprintf(stderr, "co_create failed\n");
			_exit(1);
		}
		co_call(cr);
		/* Reached only if the coroutine returned without overflowing. */
		_exit(1);
	}

	/* Parent owns the mapping; child has its own copy after fork. */
	pam_stack_free(&st);

	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		return 1;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		fprintf(stderr,
			"PASS: fault address confirmed in guard page\n");
		return 0;
	}

	if (WIFEXITED(status))
		fprintf(stderr,
			"FAIL: child exited with status %d "
			"(fault outside guard page or no fault)\n",
			WEXITSTATUS(status));
	else
		fprintf(stderr,
			"FAIL: child killed by signal %d "
			"(SIGSEGV handler did not run?)\n",
			WTERMSIG(status));
	return 1;
}

#endif /* __linux__ */
