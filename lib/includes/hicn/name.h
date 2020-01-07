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
 * @file name.h
 * @brief hICN name helpers.
 *
 * The purpose of the file is to offer an efficient, platform- and protocol-
 * independent way to manipulate hICN names.
 */

#ifndef HICN_NAME_H
#define HICN_NAME_H

#include <stdbool.h>
#ifndef _WIN32
#include <netinet/in.h>		// struct sockadd
#endif
#include <hicn/util/ip_address.h>
#include "common.h"

/******************************************************************************
 * hICN names
 ******************************************************************************/

#define TCP_SEQNO_LEN 4		/* bytes */
#define HICN_V4_PREFIX_LEN IPV4_ADDR_LEN
#define HICN_V6_PREFIX_LEN IPV6_ADDR_LEN
#define HICN_SEGMENT_LEN TCP_SEQNO_LEN
#define HICN_V6_NAME_LEN (HICN_V6_PREFIX_LEN + HICN_SEGMENT_LEN)	/* 20 bytes */
#define HICN_V4_NAME_LEN (HICN_V4_PREFIX_LEN + HICN_SEGMENT_LEN)	/*  8 bytes */

/* Prefix */

typedef u32 hicn_name_suffix_t;

typedef struct
{
  ip46_address_t name;
  u8 len;
} hicn_prefix_t;

/*
 * Name
 *
 * A name is a prefix + a segment name (suffix)
 */

typedef union
{
  struct
  {
    union
    {
      u32 prefix;
      u8 prefix_as_u8[4];
      ip4_address_t prefix_as_ip4;
    };
    hicn_name_suffix_t suffix;
  };
  u8 buffer[HICN_V4_NAME_LEN];
} hicn_v4_name_t;

typedef union
{
  struct
  {
    union
    {
      u64 prefix[2];
      u8 prefix_as_u8[16];
      ip6_address_t prefix_as_ip6;
    };
    hicn_name_suffix_t suffix;
  };
  u8 buffer[HICN_V6_NAME_LEN];
} hicn_v6_name_t;

typedef struct
{
  u8 buffer[0];
} hicn_v46_name_t;

#ifndef HICN_VPP_PLUGIN
#define HICN_NAME_COMPONENT_SIZE 2

typedef struct
{
  struct iovec buffers[HICN_NAME_COMPONENT_SIZE];
} hicn_iov_name_t;

#define UNSPEC            1 << 0
#define HNT_CONTIGUOUS    1 << 1
#define HNT_IOV           1 << 2
#define HNT_INET          1 << 3
#define HNT_INET6         1 << 4

typedef enum
{
  HNT_UNSPEC = UNSPEC,
  HNT_CONTIGUOUS_V4 = HNT_CONTIGUOUS | HNT_INET,
  HNT_CONTIGUOUS_V6 = HNT_CONTIGUOUS | HNT_INET6,
  HNT_IOV_V4 = HNT_IOV | HNT_INET,
  HNT_IOV_V6 = HNT_IOV | HNT_INET6,
} hicn_name_type_t;
#endif /* HICN_VPP_PLUGIN */

typedef struct
{
#ifndef HICN_VPP_PLUGIN
  hicn_name_type_t type;
  u8 len;
#endif				/* HICN_VPP_PLUGIN */
  union
  {
    hicn_v4_name_t ip4;
    hicn_v6_name_t ip6;
    ip46_address_t ip46;
#ifndef HICN_VPP_PLUGIN
    hicn_iov_name_t iov;
    u8 buffer[0];
#endif				/* HICN_VPP_PLUGIN */
  };
} hicn_name_t;

#ifndef HICN_VPP_PLUGIN
#define _is_unspec(name)     ((name->type & UNSPEC))
#define _is_contiguous(name) ((name->type & HNT_CONTIGUOUS) >> 1)
#define _is_iov(name)        ((name->type & HNT_IOV) >> 2)
#define _is_inet4(name)      ((name->type & HNT_INET) >> 3)
#define _is_inet6(name)      ((name->type & HNT_INET6) >> 4)
#endif /* HICN_VPP_PLUGIN */

/**
 * @brief Create an hICN name from IP address in presentation format
 * @param [in] ip_address - IP address
 * @param [in] id - Segment identifier
 * @param [out] Resulting hICN name
 * @return hICN error code
 */
int hicn_name_create (const char *ip_address, u32 id, hicn_name_t * name);

/**
 * @brief Create an hICN name from IP address
 * @param [in] ip_address - IP address
 * @param [in] id Segment - identifier
 * @param [out] Resulting - hICN name
 * @return hICN error code
 */
int hicn_name_create_from_ip_prefix (const ip_prefix_t * prefix, u32 id,
				      hicn_name_t * name);

/**
 * @brief Returns the length of an hICN name
 * @param [in] name - hICN name
 * @return Name length
 */
u8 hicn_name_get_length (const hicn_name_t * name);

/**
 * @brief Compare two hICN names
 * @param [in] name_1 - First name to compare
 * @param [in] name_2 - Second name to compare
 * @param [in] consider_segment - Flag indicating whether the segment part has to be
 *   considered
 * @return An integer less than, equal to, or greater than zero if name_1 is
 *   found, respectively, to be lest than, to match, or be greater than name_2
 *   based on numeric order.
 */
int hicn_name_compare (const hicn_name_t * name_1, const hicn_name_t * name_2,
		       bool consider_segment);

/**
 * @brief Provides a 32-bit hash of an hICN name
 * @param [in] name - Name to hash
 * @param [out] hash - Resulting hash
 * @param [in] consider_suffix - Consider the suffix in the hash computation
 * @return hICN error code
 */
int hicn_name_hash (const hicn_name_t * name, u32 * hash, bool consider_suffix);

/**
 * @brief Test whether an hICN name is empty
 * @param [in] name - Name to test
 * @return 0 if the name is empty, any other value otherwise (implementation
 *   returns 1)
 */
int hicn_name_empty (hicn_name_t * name);

/**
 * @brief Copy an hICN name
 * @param [out] dst - Destination name
 * @param [in] src - Source name to copy
 * @return hICN error code
 */
int hicn_name_copy (hicn_name_t * dst, const hicn_name_t * src);

/**
 * @brief Copy an hICN name to a buffer
 * @param [out] dst - Destination buffer
 * @param [in] src - Source name to copy
 * @param [in] copy_suffix - Flag indicating whether the suffix has to be
 *   considered
 */
int hicn_name_copy_to_destination (u8 * dst, const hicn_name_t * src,
				   bool copy_suffix);

/**
 * @brief Sets the segment part of an hICN name
 * @param [in,out] name - hICN name to modify
 * @param [in] seq_number - Segment identifier
 * @return hICN error code
 */
int hicn_name_set_seq_number (hicn_name_t * name, u32 seq_number);

/**
 * @brief Retrieves the segment part of an hICN name
 * @param [in,out] name - hICN name
 * @param [in] seq_number - Segment identifier
 * @return hICN error code
 */
int hicn_name_get_seq_number (const hicn_name_t * name, u32 * seq_number);

/**
 * @brief Convert an hICN name to a socket address
 * @param [in] name - Name to convert
 * @param [out] ip_address - Resulting socket address
 * @return hICN error code
 */
int hicn_name_to_sockaddr_address (const hicn_name_t * name,
				   struct sockaddr *ip_address);

/**
 * @brief Convert an hICN name to an IP address
 * @param [in] name - Name to convert
 * @param [out] ip_address - Resulting IP address
 * @return hICN error code
 */
int hicn_name_to_ip_prefix (const hicn_name_t * name,
			     ip_prefix_t * ip_prefix);

/**
 * @brief Convert an hICN name to presentation format
 * @param [in] src - Name to convert
 * @param [out] dst - Buffer to receive the name in presentation format
 * @param [in] len - Number of bytes available in the buffer
 * @return hICN error code
 */
int hicn_name_ntop (const hicn_name_t * src, char *dst, size_t len);

/**
 * @brief Convert an hICN name from presentation format
 * @param [in] src - Name in presentation format to parse
 * @param [out] dst - Resulting name
 * @return hICN error code
 */
int hicn_name_pton (const char *src, hicn_name_t * dst);

/**
 * @brief Returns the IP address family of an hICN name
 * @param [in] name - Name to lookup
 * @param [out] family - Resulting IP address family (AF_INET or AF_INET6)
 * @return hICN error code
 */
int hicn_name_get_family (const hicn_name_t * name, int *family);

/**
 * @brief Creates an hICN prefix from an IP address
 * @param [in] ip_address - Input IP address
 * @param [out] prefix - Resulting prefix
 * @return hICN error code
 */
int hicn_prefix_create_from_ip_prefix (const ip_prefix_t * ip_prefix,
					hicn_prefix_t * prefix);

#endif /* HICN_NAME_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
