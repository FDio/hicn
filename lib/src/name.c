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
 * @file name.c
 * @brief Implementation of hICN name helpers.
 */

#ifndef _WIN32
#include <arpa/inet.h> // inet_ptin
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h> // strtoul
#include <string.h> // memcpy

#include <hicn/common.h>
#include <hicn/error.h>
#include <hicn/name.h>
#include <hicn/util/sstrncpy.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

int
hicn_name_create (const char *ip_address, u32 id, hicn_name_t *name)
{
  int af, rc;

  memset (name, 0, sizeof (hicn_name_t));

  af = get_addr_family (ip_address);
  int v4 = (af == AF_INET);
  u8 *dst = (u8 *) (v4 * (intptr_t) (name->prefix.v4.as_u8) +
		    (1 - v4) * (intptr_t) (name->prefix.v6.as_u8));
  rc = inet_pton (af, ip_address, dst);

  if (rc != 1)
    {
      return HICN_LIB_ERROR_UNKNOWN_ADDRESS;
    }

  name->suffix = id;

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_create_from_ip_address (const hicn_ip_address_t ip_address,
				  u32 suffix, hicn_name_t *name)
{
  name->prefix = ip_address;
  name->suffix = suffix;

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_create_from_ip_prefix (const hicn_ip_prefix_t *prefix, u32 id,
				 hicn_name_t *name)
{
  name->prefix = prefix->address;
  name->suffix = id;

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_compare (const hicn_name_t *name_1, const hicn_name_t *name_2,
		   bool consider_segment)
{
  int ret;
  ret = memcmp (&name_1->prefix.v6.buffer, &name_2->prefix.v6.buffer,
		sizeof (name_1->prefix.v6));

  if (consider_segment)
    ret |= !(name_1->suffix == name_2->suffix);

  return ret;
}

uint32_t
_hicn_name_get_hash (const hicn_name_t *name, bool consider_suffix)
{
  uint32_t hash = hash32 (&name->prefix, sizeof (name->prefix));

  if (consider_suffix)
    hash = cumulative_hash32 (&name->suffix, sizeof (name->suffix), hash);

  return hash;
}

int
hicn_name_empty (hicn_name_t *name)
{
  return _is_unspec (name);
}

int
hicn_name_copy (hicn_name_t *dst, const hicn_name_t *src)
{
  *dst = *src;
  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_copy_prefix_to_destination (u8 *dst, const hicn_name_t *name)
{
  int v4 = _is_inet4 (name);
  const u8 *src = (u8 *) (v4 * (intptr_t) (name->prefix.v4.as_u8) +
			  (1 - v4) * (intptr_t) (name->prefix.v6.as_u8));
  size_t size = v4 * IPV4_ADDR_LEN + (1 - v4) * IPV6_ADDR_LEN;
  memcpy (dst, src, size);

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_set_suffix (hicn_name_t *name, hicn_name_suffix_t suffix)
{
  name->suffix = suffix;
  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_to_sockaddr_address (const hicn_name_t *name,
			       struct sockaddr *ip_address)
{
  struct sockaddr_in6 *tmp6 = (struct sockaddr_in6 *) ip_address;
  struct sockaddr_in *tmp4 = (struct sockaddr_in *) ip_address;

  assert (!_is_unspec (name));

  if (_is_inet4 (name))
    {
      tmp4->sin_family = AF_INET;
      tmp4->sin_port = DUMMY_PORT;
      memcpy (&tmp4->sin_addr, &name->prefix.v4, IPV4_ADDR_LEN);
    }
  else
    {
      tmp6->sin6_family = AF_INET6;
      tmp6->sin6_scope_id = 0;
      tmp6->sin6_port = DUMMY_PORT;
      memcpy (&tmp6->sin6_addr, &name->prefix.v6, IPV6_ADDR_LEN);
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_to_hicn_ip_prefix (const hicn_name_t *name, hicn_ip_prefix_t *prefix)
{
  int family, rc;
  rc = hicn_name_get_family (name, &family);
  if (rc)
    return rc;

  prefix->family = family;
  prefix->address.v6.as_u64[0] = name->prefix.v6.as_u64[0];
  prefix->address.v6.as_u64[1] = name->prefix.v6.as_u64[1];
  prefix->len = 128;
  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_get_seq_number (const hicn_name_t *name, u32 *seq_number)
{
  *seq_number = name->suffix;
  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_ntop (const hicn_name_t *src, char *dst, size_t len)
{
  int offset;
  const char *rc = NULL;
  int v4 = _is_inet4 (src);
  const u8 *addr = (u8 *) (v4 * (intptr_t) src->prefix.v4.as_u8 +
			   (1 - v4) * (intptr_t) src->prefix.v6.as_u8);
  int family = v4 * AF_INET + (1 - v4) * AF_INET6;
  rc = inet_ntop (family, addr, dst, (socklen_t) len);

  if (!rc)
    {
      return HICN_LIB_ERROR_UNSPECIFIED;
    }

  offset = (int) strnlen_s (dst, len);
  dst[offset] = '|';

  snprintf (dst + offset + 1, len - offset - 1, "%lu",
	    (unsigned long) (src->suffix));

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_pton (const char *src, hicn_name_t *dst)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
}

int
hicn_name_get_family (const hicn_name_t *name, int *family)
{
  assert (!_is_unspec (name));
  int v4 = _is_inet4 (name);
  *family = v4 * AF_INET + (1 - v4) * AF_INET6;

  return HICN_LIB_ERROR_NONE;
}

bool
hicn_name_is_v4 (const hicn_name_t *name)
{
  return _is_inet4 (name);
}

int
hicn_name_snprintf (char *s, size_t size, const hicn_name_t *name)
{
  int n, rc;
  n = hicn_ip_address_snprintf (s, size, &name->prefix);
  if (n < 0 || n >= size)
    return n;
  rc = snprintf (s + n, size - n, "|%d", name->suffix);
  if (rc < 0)
    return rc;
  return rc + n;
}

int
hicn_prefix_create_from_ip_prefix (const hicn_ip_prefix_t *hicn_ip_prefix,
				   hicn_prefix_t *prefix)
{
  if (hicn_ip_prefix->family != AF_INET || hicn_ip_prefix->family != AF_INET6)
    return HICN_LIB_ERROR_INVALID_IP_ADDRESS;
  prefix->name = hicn_ip_prefix->address;
  prefix->len = (u8) (hicn_ip_prefix->len);

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_cmp (const hicn_name_t *n1, const hicn_name_t *n2)
{
  int rc = hicn_ip_address_cmp (&n1->prefix, &n2->prefix);
  if (rc != 0)
    return rc;
  return n2->suffix - n1->suffix;
}

bool
hicn_name_equals (const hicn_name_t *n1, const hicn_name_t *n2)
{
  return (hicn_name_cmp (n1, n2) == 0);
}

int
hicn_prefix_create_from_ip_address_len (const hicn_ip_address_t *ip_address,
					uint8_t len, hicn_prefix_t *prefix)
{
  prefix->name = *ip_address;
  prefix->len = len;

  return HICN_LIB_ERROR_NONE;
}

hicn_prefix_t *
hicn_prefix_dup (const hicn_prefix_t *prefix)
{
  hicn_prefix_t *copy = malloc (sizeof (hicn_prefix_t));
  if (!copy)
    goto ERR_MALLOC;
  if (hicn_prefix_copy (copy, prefix) < 0)
    goto ERR_COPY;
  return copy;

ERR_COPY:
  free (copy);
ERR_MALLOC:
  return NULL;
}

int
hicn_prefix_copy (hicn_prefix_t *dst, const hicn_prefix_t *src)
{
  dst->name = src->name;
  dst->len = src->len;
  return 0;
}

bool
hicn_prefix_is_v4 (const hicn_prefix_t *prefix)
{
  return hicn_ip_address_is_v4 (&prefix->name);
}

/*
 * The ip address is in network byte order (big endian, msb last) in
 * hicn_{prefix,name}_t, as in ip_address_t which builds upon struct in*_addr,
 * But the bits are in host order... so we cannot use builtin functions to get
 * the position of the first 1 unless we swap bytes as was done previously,
 * which is costly and non-essential.
 */

uint64_t
_log2_nbo (uint64_t val)
{
  assert (val != 0); /* There is at least 1 bit set (network byte order) */

  uint64_t result = 0;

  if (val & 0xFFFFFFFF00000000)
    val = val >> 32;
  else
    /* The first 32 bits of val are 0 */
    result = result | 32;

  if (val & 0xFFFF0000)
    val = val >> 16;
  else
    result = result | 16;

  if (val & 0xFF00)
    val = val >> 8;
  else
    result = result | 8;

  /* Val now contains the byte with at last 1 bit set (host bit order) */
  if (val & 0xF0)
    {
      val = val >> 4;
      result = result | 4;
    }

  if (val & 0xC)
    {
      val = val >> 2;
      result = result | 2;
    }
  if (val & 0x2)
    {
      val = val >> 1;
      result = result | 1;
    }

  return result;
}

uint32_t
hicn_prefix_lpm (const hicn_prefix_t *p1, const hicn_prefix_t *p2)
{
  uint32_t prefix_len = 0;
  /* Test each block of 64 bits as a whole */
  for (unsigned i = 0; i < 2; i++)
    {

      /* Check for differences in the two u64 */
      uint64_t diff = p1->name.v6.as_u64[i] ^ p2->name.v6.as_u64[i];
      if (diff)
	{
	  /*
	   * As the ip_address_t mimics in*_addr and has network byte order
	   * (and host bit order, we cannot directly use 64-bit operations:
	   *
	   * Example:
	   *
	   * bits |  7 ..   0 | 15 14 13 12 11 10  9  8 | .. | 127 .. 120 |
	   * diff |           |  1  0  1  0  0  0  0  0 | .. |            |
	   *                           ^
	   * bit of interest  ---------+
	   */
	  prefix_len += _log2_nbo (diff);
	  break;
	}
      prefix_len += 8 * sizeof (uint64_t);
    }

  /* Bound the returned prefix length by the length of all input */
  return MIN (prefix_len,
	      MIN (hicn_prefix_get_len (p1), hicn_prefix_get_len (p2)));
}

void
hicn_prefix_clear (hicn_prefix_t *prefix, uint8_t start_from)
{
  uint8_t *buffer = prefix->name.v6.as_u8;

  /* Compute the offset of the byte from which to clear the name... */
  uint8_t offset = start_from / 8;
  if (hicn_prefix_is_v4 (prefix))
    offset += IP_ADDRESS_V4_OFFSET_LEN; /* Ignore padding */
  /* ... and the position of the first bit to clear */
  uint8_t pos = start_from % 8;

  /* Mask to clear specific bits at offset...
   * pos   7 6 5 4 3 2 1 0  (eg. start_from = 19, pos = 3)
   * mask  0 0 0 0 0 1 1 1  (= 1<<pos - 1)
   * */
  buffer[offset] &= 1 << (pos - 1);
  /* ... then fully clear remaining bytes */
  for (uint8_t i = offset + 1; i < HICN_PREFIX_MAX_LEN; i++)
    buffer[i] = 0;
}

void
hicn_prefix_truncate (hicn_prefix_t *prefix, uint8_t len)
{
  hicn_prefix_clear (prefix, len);
  prefix->len = len;
}

int
hicn_prefix_cmp (const hicn_prefix_t *p1, const hicn_prefix_t *p2)
{
  if (p1->len != p2->len)
    return p2->len - p1->len;
  return hicn_ip_address_cmp (&p1->name, &p2->name);
}

bool
hicn_prefix_equals (const hicn_prefix_t *p1, const hicn_prefix_t *p2)
{
  return hicn_prefix_cmp (p1, p2) == 0;
}

int
hicn_prefix_snprintf (char *s, size_t size, const hicn_prefix_t *prefix)
{
  hicn_ip_prefix_t ip_prefix = { .family =
				   hicn_ip_address_get_family (&prefix->name),
				 .address = prefix->name,
				 .len = prefix->len };
  return hicn_ip_prefix_snprintf (s, size, &ip_prefix);
}

uint8_t
hicn_prefix_get_bit (const hicn_prefix_t *prefix, uint8_t pos)
{
  assert (pos <= hicn_prefix_get_len (prefix));
  const hicn_ip_address_t *address = hicn_prefix_get_ip_address (prefix);
  return hicn_ip_address_get_bit (address, pos);
}

int
hicn_prefix_get_ip_prefix (const hicn_prefix_t *prefix,
			   hicn_ip_prefix_t *ip_prefix)
{
  *ip_prefix =
    (hicn_ip_prefix_t){ .family = hicn_ip_address_get_family (&prefix->name),
			.address = prefix->name,
			.len = prefix->len };
  return HICN_LIB_ERROR_NONE;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
