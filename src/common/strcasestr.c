/* Test and measure strcasestr functions.
   Copyright (C) 2010 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Written by Ulrich Drepper <drepper@redhat.com>, 2010.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <ctype.h>
#include <string.h>
#include <unistd.h>

char *
oc_strcasestr (const char *s1, const char *s2)
{
  ssize_t s1len = strlen (s1);
  ssize_t s2len = strlen (s2);
  ssize_t i;

  if (s2len > s1len)
    return NULL;

  for (i = 0; i <= s1len - s2len; ++i)
    {
      size_t j;
      for (j = 0; j < s2len; ++j)
	if (tolower (s1[i + j]) != tolower (s2[j]))
	  break;
      if (j == s2len)
	return (char *) s1 + i;
    }

  return NULL;
}

