#ifndef HTTP_AUTH_H
#define HTTP_AUTH_H

#include <stddef.h>
#include <strings.h>

#define HTTP_AUTH_BEARER_SCHEME "Bearer"

static inline int
http_auth_is_bearer(const char *authorization, size_t authorization_size)
{
	static const char prefix[] = HTTP_AUTH_BEARER_SCHEME " ";

	return authorization != NULL &&
	       authorization_size > sizeof(prefix) - 1 &&
	       strncasecmp(authorization, prefix, sizeof(prefix) - 1) == 0;
}

#endif
