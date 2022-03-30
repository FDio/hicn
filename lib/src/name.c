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
hicn_name_create_from_ip_prefix (const ip_prefix_t *prefix, u32 id,
				 hicn_name_t *name)
{
  name->prefix.v6.as_u64[0] = prefix->address.v6.as_u64[0];
  name->prefix.v6.as_u64[1] = prefix->address.v6.as_u64[1];
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

int
hicn_name_hash (const hicn_name_t *name, u32 *hash, bool consider_suffix)
{
  *hash = hash32 (&name->prefix, sizeof (name->prefix));

  if (consider_suffix)
    *hash = cumulative_hash32 (&name->suffix, sizeof (name->suffix), *hash);

  return HICN_LIB_ERROR_NONE;
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
hicn_name_set_seq_number (hicn_name_t *name, u32 seq_number)
{
  name->suffix = seq_number;
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
hicn_name_to_ip_prefix (const hicn_name_t *name, ip_prefix_t *prefix)
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

int
hicn_prefix_create_from_ip_prefix (const ip_prefix_t *ip_prefix,
				   hicn_prefix_t *prefix)
{
  switch (ip_prefix->family)
    {
    case AF_INET:
      prefix->name.v4.as_u32 = ip_prefix->address.v4.as_u32;
      break;
    case AF_INET6:
      prefix->name.v6.as_u64[0] = ip_prefix->address.v6.as_u64[0];
      prefix->name.v6.as_u64[1] = ip_prefix->address.v6.as_u64[1];
      break;
    default:
      return HICN_LIB_ERROR_INVALID_IP_ADDRESS;
    }
  prefix->len = (u8) (ip_prefix->len);

  return HICN_LIB_ERROR_NONE;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
