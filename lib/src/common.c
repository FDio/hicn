/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
 * @file common.c
 * @brief Implementation of common interfaces abstracting low-level platform.
 * details.
 */

#include <stdlib.h>
#include <string.h>		// memset
#include <sys/types.h>		// getaddrinfo
#ifndef _WIN32
#include <sys/socket.h>
#include <netdb.h>
#endif
#include <stdio.h>

#include <hicn/common.h>
#include <hicn/util/log.h>



int
get_addr_family (const char *ip_address)
{
  struct addrinfo hint, *res = NULL;
  int rc;

  memset (&hint, '\0', sizeof hint);

  hint.ai_family = PF_UNSPEC;
  hint.ai_flags = AI_NUMERICHOST;

  rc = getaddrinfo (ip_address, NULL, &hint, &res);
  if (rc)
    {
      return -1;
    }
  rc = res->ai_family;
  freeaddrinfo (res);
  return rc;
}

/* hashes */

u32
cumulative_hash32 (const void *data, size_t len, u32 lastValue)
{
  // Standard FNV 32-bit prime: see http://www.isthe.com/chongo/tech/comp/fnv/#FNV-param
  const u32 fnv1a_prime = 0x01000193;
  u32 hash = lastValue;
  size_t i;

  const char *chardata = data;

  for (i = 0; i < len; i++)
    {
      hash = hash ^ chardata[i];
      hash = hash * fnv1a_prime;
    }

  return hash;
}

u32
hash32 (const void *data, size_t len)
{
  // Standard FNV 32-bit offset: see http://www.isthe.com/chongo/tech/comp/fnv/#FNV-param
  const u32 fnv1a_offset = 0x811C9DC5;
  return cumulative_hash32 (data, len, fnv1a_offset);
}

u64
cumulative_hash64 (const void *data, size_t len, u64 lastValue)
{
  // Standard FNV 64-bit prime: see http://www.isthe.com/chongo/tech/comp/fnv/#FNV-param
  const u64 fnv1a_prime = 0x00000100000001B3ULL;
  u64 hash = lastValue;
  const char *chardata = data;
  size_t i;

  for (i = 0; i < len; i++)
    {
      hash = hash ^ chardata[i];
      hash = hash * fnv1a_prime;
    }

  return hash;
}

u64
hash64 (const void *data, size_t len)
{
  // Standard FNV 64-bit offset: see http://www.isthe.com/chongo/tech/comp/fnv/#FNV-param
  const u64 fnv1a_offset = 0xCBF29CE484222325ULL;
  return cumulative_hash64 (data, len, fnv1a_offset);
}

void
hicn_packet_dump (const uint8_t * buffer, size_t len)
{
  int i;
  unsigned char buff[17];
  unsigned char *pc = (unsigned char *) buffer;

  // Output description if given.
  if (len == 0)
    {
      printf ("  ZERO LENGTH\n");
      return;
    }

  // Process every byte in the data.
  for (i = 0; i < len; i++)
    {
      // Multiple of 16 means new line (with line offset).

      if ((i % 16) == 0)
	{
	  // Just don't print ASCII for the zeroth line.
	  if (i != 0)
	    printf ("  %s\n", buff);

	  // Output the offset.
	  printf ("  %04x ", i);
	}

      // Now the hex code for the specific character.
      printf (" %02x", pc[i]);

      // And store a printable ASCII character for later.
      if ((pc[i] < 0x20) || (pc[i] > 0x7e))
	buff[i % 16] = '.';
      else
	buff[i % 16] = pc[i];
      buff[(i % 16) + 1] = '\0';
    }

  // Pad out last line if not exactly 16 characters.
  while ((i % 16) != 0)
    {
      printf ("   ");
      i++;
    }

  // And print the final ASCII bit.
  printf ("  %s\n", buff);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
