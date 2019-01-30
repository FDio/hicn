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
#include <arpa/inet.h>		// inet_ptin
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>		// strtoul
#include <string.h>		// memcpy

#include "common.h"
#include "error.h"
#include "name.h"

#define DUMMY_PORT ntohs(1234)

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
hicn_name_create_from_ip_address (const ip_address_t * ip_address, u32 id,
				  hicn_name_t * name)
{
  switch (ip_address->family)
    {
    case AF_INET:
      if (name->type == HNT_UNSPEC)
	{
	  name->type = HNT_CONTIGUOUS_V4;
	}
      break;
    case AF_INET6:
      if (name->type == HNT_UNSPEC)
	{
	  name->type = HNT_CONTIGUOUS_V6;
	}
      break;
    default:
      return HICN_LIB_ERROR_INVALID_IP_ADDRESS;
    }

  name->len = ip_address->prefix_len;
  if ((name->type != HNT_CONTIGUOUS_V4) && (name->type != HNT_CONTIGUOUS_V6))
    {
      return HICN_LIB_ERROR_NOT_IMPLEMENTED;
    }

  memcpy (name->buffer, ip_address->buffer, ip_address_len (ip_address));
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
hicn_name_hash (const hicn_name_t * name, u32 * hash)
{
  switch (name->type)
    {
    case HNT_CONTIGUOUS_V4:
      *hash = hash32 (name->buffer, HICN_V4_NAME_LEN);
      break;
    case HNT_CONTIGUOUS_V6:
      *hash = hash32 (name->buffer, HICN_V6_NAME_LEN);
      break;
    case HNT_IOV_V4:
    case HNT_IOV_V6:
      *hash =
	hash32 (name->iov.buffers[0].iov_base, name->iov.buffers[0].iov_len);
      *hash =
	cumulative_hash32 (name->iov.buffers[1].iov_base,
			   name->iov.buffers[1].iov_len, *hash);
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
hicn_name_to_ip_address (const hicn_name_t * name, ip_address_t * ip_address)
{
  switch (name->type)
    {
    case HNT_CONTIGUOUS_V6:
      memcpy (&ip_address->buffer, name->buffer, IPV6_ADDR_LEN);
      ip_address->family = AF_INET6;
      break;
    case HNT_IOV_V6:
      memcpy (&ip_address->buffer, name->iov.buffers[0].iov_base,
	      name->iov.buffers[0].iov_len);
      ip_address->family = AF_INET6;
      break;
    case HNT_CONTIGUOUS_V4:
      memcpy (&ip_address->buffer, name->buffer, IPV4_ADDR_LEN);
      ip_address->family = AF_INET;
      break;
    case HNT_IOV_V4:
      memcpy (&ip_address->buffer, name->iov.buffers[0].iov_base,
	      name->iov.buffers[0].iov_len);
      ip_address->family = AF_INET;
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

  offset = strlen (dst);
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
hicn_prefix_create_from_ip_address (const ip_address_t * ip_address,
				    hicn_prefix_t * prefix)
{
  switch (ip_address->family)
    {
    case AF_INET:
      prefix->name.ip4.as_u32 = ip_address->as_u32[0];
      break;
    case AF_INET6:
      prefix->name.ip6.as_u64[0] = ip_address->as_u64[0];
      prefix->name.ip6.as_u64[1] = ip_address->as_u64[1];
      break;
    default:
      return HICN_LIB_ERROR_INVALID_IP_ADDRESS;
    }
  prefix->len = ip_address->prefix_len;

  return HICN_LIB_ERROR_NONE;
}

#endif /* ! HICN_VPP_PLUGIN */

/********
 * IP
 */

inline int
ip_address_len (const ip_address_t * ip_address)
{
  return (ip_address->family == AF_INET6) ? IPV6_ADDR_LEN :
    (ip_address->family == AF_INET) ? IPV4_ADDR_LEN : 0;
}

bool
ip_address_empty (const ip_address_t * ip_address)
{
  return ip_address->prefix_len == 0;
}

int
hicn_ip_ntop (const ip_address_t * ip_address, char *dst, const size_t len)
{
  const char *rc;

  rc = inet_ntop (ip_address->family, ip_address->buffer, dst, len);
  if (!rc)
    {
      printf ("error ntop: %d %s\n", errno, strerror (errno));
      return HICN_LIB_ERROR_INVALID_IP_ADDRESS;
    }

  return HICN_LIB_ERROR_NONE;
}

/*
 * Parse ip addresses in presentation format, or prefixes (in bits, separated by a slash)
 */
int
hicn_ip_pton (const char *ip_address_str, ip_address_t * ip_address)
{
  int pton_fd;
  char *p;
  char *eptr;
  u32 dst_len;
  char *addr = strdup (ip_address_str);

  p = strchr (addr, '/');
  if (!p)
    {
      dst_len = 0;		// until we get the ip address family
    }
  else
    {
      dst_len = strtoul (p + 1, &eptr, 10);
      *p = 0;
    }

  ip_address->family = get_addr_family (addr);

  switch (ip_address->family)
    {
    case AF_INET6:
      if (dst_len > IPV6_ADDR_LEN_BITS)
	goto ERR;
      pton_fd = inet_pton (AF_INET6, addr, &ip_address->buffer);
      ip_address->prefix_len = dst_len ? dst_len : IPV6_ADDR_LEN_BITS;
      break;
    case AF_INET:
      if (dst_len > IPV4_ADDR_LEN_BITS)
	goto ERR;
      pton_fd = inet_pton (AF_INET, addr, &ip_address->buffer);
      ip_address->prefix_len = dst_len ? dst_len : IPV4_ADDR_LEN_BITS;
      break;
    default:
      goto ERR;
    }

  //   0 = not in presentation format
  // < 0 = other error (use perror)
  if (pton_fd <= 0)
    {
      goto ERR;
    }

  return HICN_LIB_ERROR_NONE;
ERR:
  free (addr);
  return HICN_LIB_ERROR_INVALID_IP_ADDRESS;
}

int
hicn_ip_to_sockaddr_address (const ip_address_t * ip_address,
			     struct sockaddr *sockaddr_address)
{
  struct sockaddr_in6 *tmp6 = (struct sockaddr_in6 *) sockaddr_address;
  struct sockaddr_in *tmp4 = (struct sockaddr_in *) sockaddr_address;

  switch (ip_address->family)
    {
    case AF_INET6:
      tmp6->sin6_family = AF_INET6;
      tmp6->sin6_port = DUMMY_PORT;
      tmp6->sin6_scope_id = 0;
      memcpy (&tmp6->sin6_addr, ip_address->buffer, IPV6_ADDR_LEN);
      break;
    case AF_INET:
      tmp4->sin_family = AF_INET;
      tmp4->sin_port = DUMMY_PORT;
      memcpy (&tmp4->sin_addr, ip_address->buffer, IPV4_ADDR_LEN);
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  return HICN_LIB_ERROR_NONE;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
