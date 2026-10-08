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
 * PAM module for regression-testing issue #741 (and #657).
 *
 * Detects whether pam_end() is called while the conversation function has
 * not yet returned (i.e. the PAM coroutine is still live in ocserv_conv()).
 *
 * Mechanism:
 *   pam_sm_authenticate() obtains the conversation function, allocates a
 *   flag, and registers it with pam_set_data().  The pam_set_data() cleanup
 *   runs when pam_end() fires; if the flag is still set at that point the
 *   coroutine is live and we call abort().
 *
 *   Before calling conv->conv() the flag is set; after conv->conv() returns
 *   (normally or via PAM_CONV_ERR) it is cleared.
 *
 * With the fix (commit af108817 / pam_auth_deinit co_call):
 *   pam_auth_deinit() resumes the coroutine before calling pam_end(), so
 *   conv->conv() returns, the flag is cleared, and pam_end() sees flag == 0.
 *
 * Without the fix:
 *   pam_end() fires while the coroutine is suspended inside conv->conv(),
 *   the cleanup sees flag == 1, and calls abort().
 */

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <stdlib.h>
#include <stdio.h>

struct abort_data {
	int in_progress;
};

static void conv_cleanup(pam_handle_t *pamh, void *data, int error_status)
{
	struct abort_data *d = data;

	if (d->in_progress) {
		fprintf(stderr, "pam_abort_test: pam_end() called while "
				"conversation is active (issue #657)\n");
		abort();
	}
	free(d);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	const struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp = &msg;
	struct pam_response *resp = NULL;
	struct abort_data *d;
	int ret;

	ret = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (ret != PAM_SUCCESS || conv == NULL || conv->conv == NULL)
		return PAM_AUTH_ERR;

	d = malloc(sizeof(*d));
	if (d == NULL)
		return PAM_BUF_ERR;
	d->in_progress = 0;

	ret = pam_set_data(pamh, "ocserv_abort_in_progress", d, conv_cleanup);
	if (ret != PAM_SUCCESS) {
		free(d);
		return ret;
	}

	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = "Password: ";

	d->in_progress = 1;
	ret = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
	d->in_progress = 0;

	if (resp != NULL) {
		if (resp[0].resp != NULL)
			free(resp[0].resp);
		free(resp);
	}

	return (ret == PAM_SUCCESS) ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv)
{
	return PAM_SUCCESS;
}
