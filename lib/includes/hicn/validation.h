/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

/**
 * \file validation.h
 * \brief Functions for input validation
 */
#include <ctype.h>
#include <hicn/util/sstrncpy.h>

static inline bool
is_number (const char *string, size_t maxlen)
{
  size_t len = strnlen_s (string, maxlen);
  for (size_t i = 0; i < len; i++)
    {
      if (!isdigit (string[i]))
	return false;
    }
  return len != 0;
}

/**
 * A symbolic name must be at least 1 character and must begin with an alpha.
 * The remainder must be an alphanum.
 */
static inline bool
is_symbolic_name (const char *name, size_t maxlen)
{
  size_t len = strnlen_s (name, maxlen);
  if (len <= 0)
    return false;
  if (!isalpha (name[0]))
    return false;

  for (size_t i = 1; i < len; i++)
    {
      if (!isalnum (name[i]) && name[i] != '_' && name[i] != '-')
	return false;
    }

  return true;
}
