/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UTIL_SSTRNCPY_H
#define UTIL_SSTRNCPY_H

#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include <string.h>

#ifdef __STDC_LIB_EXT1__
// If safe string functions already available in the system, use them
#elif ENABLE_SAFEC
// If safe string functions not available and SafeC is enabled,
// use SafeC
#include <safe_string.h>
#else
// Use custom safe string functions
typedef int errno_t;
#define EOK 0

#ifndef HICN_VPP_PLUGIN
/* This function is already defined in vppinfra/string.h */

/**
 * @brief This function assures a null byte at the end of the buffer.
 */
static inline errno_t
strcpy_s (char *dst, size_t n, const char *src)
{
  if (!dst || !src || !n)
    {
      fprintf (stderr, "[strncpy] invalid input received");
      return EINVAL;
    }

  dst[n - 1] = 0;
  strncpy (dst, src, n);

  if (dst[n - 1] != 0)
    {
      fprintf (stderr, "[strncpy] '%s' has been trucated\n", src);
      dst[n - 1] = 0;
      return EINVAL;
    }

  return EOK;
}

static inline size_t
strnlen_s (const char *s, size_t maxlen)
{
  if (s == NULL)
    return 0;

  return strnlen (s, maxlen);
}
#endif /* HICN_VPP_PLUGIN */

#endif /* __STDC_LIB_EXT1__ */
#endif /* UTIL_SSTRNCPY_H */
