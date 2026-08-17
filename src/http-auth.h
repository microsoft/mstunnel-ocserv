#ifndef HTTP_AUTH_H
#define HTTP_AUTH_H

#include <stddef.h>

#define HTTP_AUTH_BEARER_SCHEME "Bearer"

int http_auth_is_bearer(const char *authorization, size_t authorization_size);

#endif
