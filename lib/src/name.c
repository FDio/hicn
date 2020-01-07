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

  af = get_addr_family (ip_address);

  switch (af)
    {
    case AF_INET:
      if (name->type == HNT_UNSPEC)
        {
          name->type = HNT_CONTIGUOUS_V4;
        }
      name->len = IPV4_ADDR_LEN;
      break;
    case AF_INET6:
      if (name->type == HNT_UNSPEC)
        {
          name->type = HNT_CONTIGUOUS_V6;
        }
      name->len = IPV6_ADDR_LEN;
      break;
    default:
      return HICN_LIB_ERROR_INVALID_IP_ADDRESS;
    }

  if ((name->type != HNT_CONTIGUOUS_V4) && (name->type != HNT_CONTIGUOUS_V6))
    {
      return HICN_LIB_ERROR_NOT_IMPLEMENTED;
    }

  rc = inet_pton (af, ip_address, name->buffer);
  if (rc <= 0)
    {
      return HICN_LIB_ERROR_UNKNOWN_ADDRESS;
    }
  *(u32 *) (name->buffer + name->len) = id;

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_create_from_ip_prefix (const ip_prefix_t * prefix, u32 id,
                                  hicn_name_t * name)
{
  switch (prefix->family)
    {
      case AF_INET:
        name->type = HNT_CONTIGUOUS_V4;
        memcpy (name->buffer, prefix->address.v4.buffer,
                ip_address_len(prefix->family));
        break;
      case AF_INET6:
        name->type = HNT_CONTIGUOUS_V6;
        memcpy (name->buffer, prefix->address.v6.buffer,
                ip_address_len(prefix->family));
        break;
      default:
        return HICN_LIB_ERROR_INVALID_IP_ADDRESS;
    }

  name->len = (u8) (prefix->len);
  *(u32 *) (name->buffer + name->len) = id;

  return HICN_LIB_ERROR_NONE;
}

u8
hicn_name_get_length (const hicn_name_t * name)
{
  return name->len;
}

int
hicn_name_compare (const hicn_name_t * name_1, const hicn_name_t * name_2,
                   bool consider_segment)
{
  hicn_name_t *name1 = (hicn_name_t *) name_1;
  hicn_name_t *name2 = (hicn_name_t *) name_2;

  if ((name1->type == HNT_CONTIGUOUS_V4 && name2->type == HNT_CONTIGUOUS_V6)
      || (name1->type == HNT_CONTIGUOUS_V6
          && name2->type == HNT_CONTIGUOUS_V4))
    {
      return -1;
    }

  if ((name1->type == HNT_IOV_V4 && name2->type == HNT_IOV_V6) ||
      (name1->type == HNT_IOV_V6 && name2->type == HNT_IOV_V4))
    {
      return -1;
    }

  if ((name1->type == HNT_IOV_V4 && name2->type == HNT_CONTIGUOUS_V6) ||
      (name1->type == HNT_IOV_V6 && name2->type == HNT_CONTIGUOUS_V4))
    {
      return -1;
    }

  if (name1->type == HNT_UNSPEC || name2->type == HNT_UNSPEC)
    {
      return -1;
    }

  size_t len1 = 0, len2 = 0;

  u8 *buffer11, *buffer12, *buffer21, *buffer22;

  switch (name1->type)
    {
    case HNT_CONTIGUOUS_V4:
      buffer11 = name1->buffer;
      buffer12 = name1->buffer + IPV4_ADDR_LEN;
      len1 = IPV4_ADDR_LEN;
      break;
    case HNT_CONTIGUOUS_V6:
      buffer11 = name1->buffer;
      buffer12 = name1->buffer + IPV6_ADDR_LEN;
      len1 = IPV6_ADDR_LEN;
      break;
    case HNT_IOV_V4:
      buffer11 = name1->iov.buffers[0].iov_base;
      buffer12 = name1->iov.buffers[1].iov_base;
      len1 = IPV4_ADDR_LEN;
      break;
    case HNT_IOV_V6:
      buffer11 = name1->iov.buffers[0].iov_base;
      buffer12 = name1->iov.buffers[1].iov_base;
      len1 = IPV6_ADDR_LEN;
      break;
    default:
      return HICN_LIB_ERROR_NOT_IMPLEMENTED;
    }

  switch (name2->type)
    {
    case HNT_CONTIGUOUS_V4:
      buffer21 = name2->buffer;
      buffer22 = name2->buffer + IPV4_ADDR_LEN;
      len2 = IPV4_ADDR_LEN;
      break;
    case HNT_CONTIGUOUS_V6:
      buffer21 = name2->buffer;
      buffer22 = name2->buffer + IPV6_ADDR_LEN;
      len2 = IPV6_ADDR_LEN;
      break;
    case HNT_IOV_V4:
      buffer21 = name2->iov.buffers[0].iov_base;
      buffer22 = name2->iov.buffers[1].iov_base;
      len2 = IPV4_ADDR_LEN;
      break;
    case HNT_IOV_V6:
      buffer21 = name2->iov.buffers[0].iov_base;
      buffer22 = name2->iov.buffers[1].iov_base;
      len2 = IPV6_ADDR_LEN;
      break;
    default:
      return HICN_LIB_ERROR_NOT_IMPLEMENTED;
    }

  // Sanity check
  if (len1 != len2)
    {
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  int ret1 = memcmp ((u8 *) buffer11, (u8 *) buffer21, len1);

  if (!consider_segment)
    {
      return ret1;
    }

  int ret2 = memcmp ((u8 *) buffer12, (u8 *) buffer22, HICN_SEGMENT_LEN);

  return ret1 || ret2;
}

int
hicn_name_hash (const hicn_name_t * name, u32 * hash, bool consider_suffix)
{
  switch (name->type)
    {
    case HNT_CONTIGUOUS_V4:
      *hash = hash32 (name->buffer, consider_suffix ? HICN_V4_NAME_LEN : HICN_V4_PREFIX_LEN);
      break;
    case HNT_CONTIGUOUS_V6:
      *hash = hash32 (name->buffer, consider_suffix ? HICN_V6_NAME_LEN : HICN_V6_PREFIX_LEN);
      break;
    case HNT_IOV_V4:
    case HNT_IOV_V6:
      *hash =
	hash32 (name->iov.buffers[0].iov_base, name->iov.buffers[0].iov_len);
      if (consider_suffix)
        {
          *hash = cumulative_hash32 (name->iov.buffers[1].iov_base,
			      name->iov.buffers[1].iov_len, *hash);
        }
      break;
    default:
      return HICN_LIB_ERROR_NOT_IMPLEMENTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_empty (hicn_name_t * name)
{
  return name->type == HNT_UNSPEC ? HICN_LIB_ERROR_NONE : 1;
}

int
hicn_name_copy (hicn_name_t * dst, const hicn_name_t * src)
{
  switch (src->type)
    {
    case HNT_CONTIGUOUS_V4:
    case HNT_CONTIGUOUS_V6:
      *dst = *src;
      break;
    case HNT_IOV_V4:
    case HNT_IOV_V6:
      dst->type =
        src->type == HNT_IOV_V4 ? HNT_CONTIGUOUS_V4 : HNT_CONTIGUOUS_V6;
      memcpy (dst->buffer, src->iov.buffers[0].iov_base,
              src->iov.buffers[0].iov_len);
      memcpy (dst->buffer + src->iov.buffers[0].iov_len,
              src->iov.buffers[1].iov_base, src->iov.buffers[1].iov_len);
      break;
    default:
      return HICN_LIB_ERROR_NOT_IMPLEMENTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_copy_to_destination (u8 * dst, const hicn_name_t * src,
                               bool copy_suffix)
{
  size_t length;

  switch (src->type)
    {
    case HNT_CONTIGUOUS_V4:
      if (copy_suffix)
        {
          length = HICN_V4_NAME_LEN;
        }
      else
        {
          length = IPV4_ADDR_LEN;
        }
      memcpy (dst, src->buffer, length);
      break;
    case HNT_CONTIGUOUS_V6:
      if (copy_suffix)
        {
          length = HICN_V6_NAME_LEN;
        }
      else
        {
          length = IPV6_ADDR_LEN;
        }
      memcpy (dst, src->buffer, length);
      break;
    case HNT_IOV_V4:
    case HNT_IOV_V6:
      memcpy (dst, src->iov.buffers[0].iov_base, src->iov.buffers[0].iov_len);
      if (copy_suffix)
        {
          memcpy (dst + src->iov.buffers[0].iov_len,
                  src->iov.buffers[1].iov_base, src->iov.buffers[1].iov_len);
        }
      break;
    default:
      return HICN_LIB_ERROR_NOT_IMPLEMENTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_set_seq_number (hicn_name_t * name, u32 seq_number)
{
  u8 *sequence_number = NULL;

  switch (name->type)
    {
    case HNT_CONTIGUOUS_V6:
      sequence_number = name->buffer + IPV6_ADDR_LEN;
      break;
    case HNT_CONTIGUOUS_V4:
      sequence_number = name->buffer + IPV4_ADDR_LEN;
      break;
    case HNT_IOV_V6:
    case HNT_IOV_V4:
      sequence_number = name->iov.buffers[1].iov_base;
      break;
    case HNT_UNSPEC:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  if (sequence_number)
    {
      *(u32 *) sequence_number = seq_number;
    }
  else
    {
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_to_sockaddr_address (const hicn_name_t * name,
                               struct sockaddr *ip_address)
{
  struct sockaddr_in6 *tmp6 = (struct sockaddr_in6 *) ip_address;
  struct sockaddr_in *tmp4 = (struct sockaddr_in *) ip_address;

  switch (name->type)
    {
    case HNT_CONTIGUOUS_V6:
      tmp6->sin6_family = AF_INET6;
      tmp6->sin6_scope_id = 0;
      tmp6->sin6_port = DUMMY_PORT;
      memcpy (&tmp6->sin6_addr, name->buffer, IPV6_ADDR_LEN);
      break;
    case HNT_IOV_V6:
      tmp6->sin6_family = AF_INET6;
      tmp6->sin6_scope_id = 0;
      tmp6->sin6_port = DUMMY_PORT;
      memcpy (&tmp6->sin6_addr, name->iov.buffers[0].iov_base,
              name->iov.buffers[0].iov_len);
      break;
    case HNT_CONTIGUOUS_V4:
      tmp4->sin_family = AF_INET;
      tmp4->sin_port = DUMMY_PORT;
      memcpy (&tmp4->sin_addr, name->buffer, IPV4_ADDR_LEN);
      break;
    case HNT_IOV_V4:
      tmp4->sin_family = AF_INET;
      tmp4->sin_port = DUMMY_PORT;
      memcpy (&tmp4->sin_addr, name->iov.buffers[0].iov_base,
              name->iov.buffers[0].iov_len);
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_to_ip_prefix (const hicn_name_t * name, ip_prefix_t * prefix)
{
  switch (name->type)
    {
    case HNT_CONTIGUOUS_V6:
      memcpy (&prefix->address.v6.buffer, name->buffer, IPV6_ADDR_LEN);
      prefix->family = AF_INET6;
      break;
    case HNT_IOV_V6:
      memcpy (&prefix->address.v6.buffer, name->iov.buffers[0].iov_base,
              name->iov.buffers[0].iov_len);
      prefix->family = AF_INET6;
      break;
    case HNT_CONTIGUOUS_V4:
      memcpy (&prefix->address.v4.buffer, name->buffer, IPV4_ADDR_LEN);
      prefix->family = AF_INET;
      break;
    case HNT_IOV_V4:
      memcpy (&prefix->address.v4.buffer, name->iov.buffers[0].iov_base,
              name->iov.buffers[0].iov_len);
      prefix->family = AF_INET;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_get_seq_number (const hicn_name_t * name, u32 * seq_number)
{
  const u8 *sequence_number = NULL;

  switch (name->type)
    {
    case HNT_CONTIGUOUS_V6:
      sequence_number = name->buffer + IPV6_ADDR_LEN;
      break;
    case HNT_CONTIGUOUS_V4:
      sequence_number = name->buffer + IPV4_ADDR_LEN;
      break;
    case HNT_IOV_V6:
    case HNT_IOV_V4:
      sequence_number = name->iov.buffers[1].iov_base;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  if (sequence_number)
    {
      *seq_number = *(u32 *) sequence_number;
    }
  else
    {
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_name_ntop (const hicn_name_t * src, char *dst, size_t len)
{
  int offset;
  const char *rc;
  void *seg_number = NULL;

  switch (src->type)
    {
    case HNT_CONTIGUOUS_V6:
      rc = inet_ntop (AF_INET6, src->buffer, dst, len);
      seg_number = (u8 *) src->buffer + IPV6_ADDR_LEN;
      break;
    case HNT_CONTIGUOUS_V4:
      rc = inet_ntop (AF_INET, src->buffer, dst, len);
      seg_number = (u8 *) src->buffer + IPV4_ADDR_LEN;
      break;
    case HNT_IOV_V6:
      rc = inet_ntop (AF_INET6, src->iov.buffers[0].iov_base, dst, len);
      seg_number = src->iov.buffers[1].iov_base;
      break;
    case HNT_IOV_V4:
      rc = inet_ntop (AF_INET, src->iov.buffers[0].iov_base, dst, len);
      seg_number = src->iov.buffers[1].iov_base;
      break;
    default:
      return HICN_LIB_ERROR_NOT_IMPLEMENTED;
    }

  if (!rc)
    {
      goto ERR;
    }

  offset = (int) strlen (dst);
  dst[offset] = '|';

  sprintf (dst + offset + 1, "%lu", (unsigned long) (*(u32 *) seg_number));

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
  switch (name->type)
    {
    case HNT_CONTIGUOUS_V6:
    case HNT_IOV_V6:
      *family = AF_INET6;
      break;
    case HNT_CONTIGUOUS_V4:
    case HNT_IOV_V4:
      *family = AF_INET;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

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
