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
 * @file name.c
 * @brief Implementation of hICN name helpers.
 */

#ifndef _WIN32
#include <arpa/inet.h>          // inet_ptin
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>             // strtoul
#include <string.h>             // memcpy

#include <hicn/common.h>
#include <hicn/error.h>
#include <hicn/name.h>

#if ! HICN_VPP_PLUGIN
int
hicn_name_create (const char *ip_address, u32 id, hicn_name_t * name)
{
  int af, rc;
  u8 *dst;

  af = get_addr_family (ip_address);

  switch (af)
    {
    case AF_INET:
      dst = (u8*)(&name->prefix.ip4);
      break;
    case AF_INET6:
      dst = (u8*)(&name->prefix.ip6.as_u8);
      break;
    default:
      return HICN_LIB_ERROR_INVALID_IP_ADDRESS;
    }

  rc = inet_pton (af, ip_address, dst);
  if (rc <= 0)
    {
      return HICN_LIB_ERROR_UNKNOWN_ADDRESS;
    }
  name->suffix = id;

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_create_from_ip_prefix (const ip_prefix_t * prefix, u32 id,
                                  hicn_name_t * name)
{
  int i;

  for (i = 0; i < 2; i++)
    name->prefix.ip6.as_u64[i] = prefix->address.v6.as_u64[i];
  name->suffix = id;

  return HICN_LIB_ERROR_NONE;
}

u8
hicn_name_get_length (const hicn_name_t * name)
{
  return hicn_name_is_ip4(name) ? HICN_V4_NAME_LEN : HICN_V4_NAME_LEN;
}

int
hicn_name_compare (const hicn_name_t * name_1, const hicn_name_t * name_2,
                   bool consider_segment)
{
  size_t size = (u8)consider_segment * sizeof(hicn_name_suffix_t) + IPV6_ADDR_LEN;
  return memcmp (name_1, name_2, size);
}

int
hicn_name_hash (const hicn_name_t * name, u32 * hash, bool consider_suffix)
{
  size_t size = (u8)consider_suffix * sizeof(hicn_name_suffix_t) + IPV6_ADDR_LEN;
  *hash = hash32 (name->buffer, size);
  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_copy (hicn_name_t * dst, const hicn_name_t * src)
{
  memcpy (dst, src, sizeof(*dst));
  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_copy_to_destination (u8 * dst, const hicn_name_t * src,
                               bool copy_suffix)
{
  u8 is_ip4 = hicn_name_is_ip4(src);
  size_t size = is_ip4 * IPV4_ADDR_LEN + (1 - is_ip4) * IPV6_ADDR_LEN;
  size += (u8)copy_suffix * sizeof (hicn_name_suffix_t);
  void *_src = (void *)(is_ip4 * (u64)(&src->prefix.ip4) + (1 - is_ip4) * (u64)(&src->prefix.ip6));
  memcpy (dst, _src, size);
  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_set_seq_number (hicn_name_t * name, u32 seq_number)
{
  name->suffix = seq_number;
  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_to_sockaddr_address (const hicn_name_t * name,
                               struct sockaddr *ip_address)
{
  struct sockaddr_in6 *tmp6 = (struct sockaddr_in6 *) ip_address;
  struct sockaddr_in *tmp4 = (struct sockaddr_in *) ip_address;

  u8 is_ip4 = hicn_name_is_ip4 (name);
  ip_address->sa_family = AF_INET * is_ip4 + AF_INET6 * (1 - is_ip4);

  if (is_ip4)
    {
      tmp4->sin_family = AF_INET;
      tmp4->sin_port = DUMMY_PORT;
      tmp4->sin_addr = name->prefix.ip4.as_inaddr;
    }
  else
    {
      tmp6->sin6_family = AF_INET6;
      tmp6->sin6_port = DUMMY_PORT;
      memcpy (&tmp6->sin6_addr, name->prefix.ip6.as_u8, IPV6_ADDR_LEN);
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_to_ip_prefix (const hicn_name_t * name, ip_prefix_t * prefix)
{
  memcpy (prefix, &name->prefix, sizeof(*prefix));
  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_get_seq_number (const hicn_name_t * name, u32 * seq_number)
{
  *seq_number = name->suffix;
  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_ntop (const hicn_name_t * src, char *dst, size_t len)
{
  int offset;
  const char *rc;
  u8 is_ip4 = hicn_name_is_ip4 (src);

  if (is_ip4)
    rc = inet_ntop (AF_INET, &src->prefix.ip4.as_inaddr, dst, (socklen_t)len);
  else
    rc = inet_ntop (AF_INET6, &src->prefix.ip6.as_in6addr, dst, (socklen_t)len);

  if (!rc)
    {
      goto ERR;
    }

  offset = (int) strlen (dst);
  dst[offset] = '|';

  sprintf (dst + offset + 1, "%lu", (unsigned long) src->suffix);
  return HICN_LIB_ERROR_NONE;

ERR:
  return HICN_LIB_ERROR_UNSPECIFIED;
}

int
hicn_name_pton (const char *src, hicn_name_t * dst)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
}

int
hicn_name_get_family (const hicn_name_t * name, int *family)
{
  u8 is_ip4 = hicn_name_is_ip4 (name);
  *family = AF_INET * is_ip4 + (1 - is_ip4) * AF_INET6;

  return HICN_LIB_ERROR_NONE;
}

int
hicn_prefix_create_from_ip_prefix (const ip_prefix_t * ip_prefix,
                                    hicn_prefix_t * prefix)
{
  switch (ip_prefix->family)
    {
    case AF_INET:
      prefix->name.ip4.as_u32 = ip_prefix->address.v4.as_u32;
      break;
    case AF_INET6:
      prefix->name.ip6.as_u64[0] = ip_prefix->address.v6.as_u64[0];
      prefix->name.ip6.as_u64[1] = ip_prefix->address.v6.as_u64[1];
      break;
    default:
      return HICN_LIB_ERROR_INVALID_IP_ADDRESS;
    }

  prefix->len = (u8) (ip_prefix->len);

  return HICN_LIB_ERROR_NONE;
}

#endif /* ! HICN_VPP_PLUGIN */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
