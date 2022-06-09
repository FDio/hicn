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
 * @file common.c
 * @brief Implementation of common interfaces abstracting low-level platform.
 * details.
 */

#include <stdlib.h>
#include <string.h>    // memset
#include <sys/types.h> // getaddrinfo
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

// FNV-1a 32-bit http://www.isthe.com/chongo/tech/comp/fnv/
typedef u_int32_t Fnv32_t;
#define FNV_32_PRIME  ((Fnv32_t) 0x01000193)
#define FNV1_32_INIT  ((Fnv32_t) 0x811c9dc5)
#define FNV1_32A_INIT FNV1_32_INIT

Fnv32_t
cumulative_hash32 (const void *buf, size_t len, Fnv32_t hval)
{
  unsigned char *bp = (unsigned char *) buf; /* start of buffer */
  unsigned char *be = bp + len;		     /* beyond end of buffer */

  /*
   * FNV-1a hash each octet in the buffer
   */
  while (bp < be)
    {

      /* xor the bottom with the current octet */
      hval ^= (Fnv32_t) *bp++;

      /* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
      hval *= FNV_32_PRIME;
#else
      hval +=
	(hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
#endif
    }

  /* return our new hash value */
  return hval;
}

u32
hash32 (const void *data, size_t len)
{
  return cumulative_hash32 (data, len, FNV1_32A_INIT);
}

void
hicn_packet_dump (const uint8_t *buffer, size_t len)
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
