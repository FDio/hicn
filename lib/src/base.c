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

/**
 * @file base.c
 * @brief Implementation of base hICN definitions.
 */

#include <hicn/base.h>
#include "ops.h"

const char *_hicn_packet_type_str[] = {
#define _(x) [HICN_PACKET_TYPE_##x] = #x,
  foreach_packet_type
#undef _
};

int
hicn_packet_format_snprintf (char *s, size_t size, hicn_packet_format_t format)
{
  char *cur = s;
  int rc;
  for (unsigned i = 0; i < 4; i++)
    {
      if (i > 0)
	{
	  rc = snprintf (cur, size - (cur - s), " %s ", "/");
	  if (rc < 0 || rc >= size - (cur - s))
	    return rc;
	  cur += rc;
	}

      rc = snprintf (cur, size - (cur - s), "%s",
		     hicn_ops_vft[format.as_u8[i]]->name);
      if (rc < 0 || rc >= size - (cur - s))
	return rc;
      cur += rc;
    }
  return (int) (cur - s);
}
