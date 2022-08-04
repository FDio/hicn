/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#ifndef _WIN32
#include <netinet/in.h> // struct sockadd
#endif
#include <hicn/common.h>
#include <hicn/util/ip_address.h>

/******************************************************************************
 * hICN names
 ******************************************************************************/

#define TCP_SEQNO_LEN	   4 /* bytes */
#define HICN_V4_PREFIX_LEN IPV4_ADDR_LEN
#define HICN_V6_PREFIX_LEN IPV6_ADDR_LEN

#if 0
#define HICN_SEGMENT_LEN TCP_SEQNO_LEN

#define HICN_V6_NAME_LEN                                                      \
  (HICN_V6_PREFIX_LEN + HICN_SEGMENT_LEN) /* 20 bytes                         \
					   */
#define HICN_V4_NAME_LEN                                                      \
  (HICN_V4_PREFIX_LEN + HICN_SEGMENT_LEN) /*  8 bytes                         \
					   */
#endif

#define HICN_INVALID_SUFFIX ((uint32_t) (~0))

/* Prefix */

#define HICN_PREFIX_MAX_LEN IP_ADDRESS_MAX_LEN

typedef struct
{
  hicn_ip_address_t name;
  u8 len;
} hicn_prefix_t;

#define HICN_PREFIX_EMPTY                                                     \
  (hicn_prefix_t) { .name = IP_ADDRESS_EMPTY, .len = 0 }

static inline const hicn_ip_address_t *
hicn_prefix_get_ip_address (const hicn_prefix_t *prefix)
{
  return &prefix->name;
}

static inline u8
hicn_prefix_get_len (const hicn_prefix_t *prefix)
{
  return prefix->len;
}

int hicn_prefix_get_ip_prefix (const hicn_prefix_t *prefix,
			       hicn_ip_prefix_t *ip_prefix);
/*
 * Name
 *
 * A name is a prefix + a segment name (suffix)
 */

typedef hicn_ip_address_t hicn_name_prefix_t;
typedef uint32_t hicn_name_suffix_t;

#define hicn_name_prefix_cmp	      hicn_ip_address_cmp
#define hicn_name_prefix_equals	      hicn_ip_address_equals
#define hicn_name_prefix_get_len_bits hicn_ip_address_get_len_bits
#define hicn_name_prefix_get_hash     hicn_ip_address_get_hash
#define hicn_name_prefix_snprintf     hicn_ip_address_snprintf
#define HICN_NAME_PREFIX_EMPTY	      IP_ADDRESS_EMPTY

typedef struct
{
  hicn_name_prefix_t prefix;
  hicn_name_suffix_t suffix;
} hicn_name_t;

static_assert (offsetof (hicn_name_t, prefix) == 0, "");
static_assert (offsetof (hicn_name_t, suffix) == 16, "");
static_assert (sizeof (hicn_name_t) == 20, "");

#define HICN_NAME_EMPTY                                                       \
  (hicn_name_t) { .prefix = HICN_NAME_PREFIX_EMPTY, .suffix = 0, }

static inline const hicn_name_prefix_t *
hicn_name_get_prefix (const hicn_name_t *name)
{
  return &name->prefix;
}

static inline const hicn_name_suffix_t
hicn_name_get_suffix (const hicn_name_t *name)
{
  return name->suffix;
}

#define _is_unspec(name)                                                      \
  (((name)->prefix.pad[0] | (name)->prefix.pad[1] | (name)->prefix.pad[2] |   \
    (name)->prefix.v4.as_u32) == 0)
#define _is_inet4(name) (hicn_ip_address_is_v4 (&name->prefix))
#define _is_inet6(name) (!_is_inet4 (name))

/**
 * @brief Create an hICN name from IP address in presentation format
 * @param [in] ip_address - IP address
 * @param [in] id - Segment identifier
 * @param [out] Resulting hICN name
 * @return hICN error code
 */
int hicn_name_create (const char *ip_address, u32 id, hicn_name_t *name);

/**
 * @brief Create an hICN name from IP address
 * @param [in] ip_address - IP address
 * @param [in] suffix - Name suffix
 * @param [out] Resulting - hICN name
 * @return hICN error code
 */
int hicn_name_create_from_ip_address (const hicn_ip_address_t ip_address,
				      u32 suffix, hicn_name_t *name);

/**
 * @brief Create an hICN name from IP prefix
 * @param [in] prefix - IP prefix
 * @param [in] suffix - Name suffix
 * @param [out] Resulting - hICN name
 * @return hICN error code
 */
int hicn_name_create_from_ip_prefix (const hicn_ip_prefix_t *prefix, u32 id,
				     hicn_name_t *name);

/**
 * @brief Compare two hICN names
 * @param [in] name_1 - First name to compare
 * @param [in] name_2 - Second name to compare
 * @param [in] consider_segment - Flag indicating whether the segment part has
 * to be considered
 * @return An integer less than, equal to, or greater than zero if name_1 is
 *   found, respectively, to be lest than, to match, or be greater than name_2
 *   based on numeric order.
 */
int hicn_name_compare (const hicn_name_t *name_1, const hicn_name_t *name_2,
		       bool consider_segment);

/**
 * @brief Provides a 32-bit hash of an hICN name
 * @param [in] name - Name to hash
 * @param [out] hash - Resulting hash
 * @param [in] consider_suffix - Consider the suffix in the hash computation
 * @return hICN error code
 */
uint32_t _hicn_name_get_hash (const hicn_name_t *name, bool consider_suffix);

#define hicn_name_get_hash(NAME)	_hicn_name_get_hash (NAME, true)
#define hicn_name_get_prefix_hash(NAME) _hicn_name_get_hash (NAME, false)

/**
 * @brief Test whether an hICN name is empty
 * @param [in] name - Name to test
 * @return 0 if the name is empty, any other value otherwise (implementation
 *   returns 1)
 */
int hicn_name_empty (hicn_name_t *name);

/**
 * @brief Copy an hICN name
 * @param [out] dst - Destination name
 * @param [in] src - Source name to copy
 * @return hICN error code
 */
int hicn_name_copy (hicn_name_t *dst, const hicn_name_t *src);

/**
 * @brief Copy an hICN name to a buffer
 * @param [out] dst - Destination buffer
 * @param [in] src - Source name to copy
 * @param [in] copy_suffix - Flag indicating whether the suffix has to be
 *   considered
 */
int hicn_name_copy_prefix_to_destination (u8 *dst, const hicn_name_t *src);

/**
 * @brief Sets the segment part of an hICN name
 * @param [in,out] name - hICN name to modify
 * @param [in] seq_number - Segment identifier
 * @return hICN error code
 */
int hicn_name_set_suffix (hicn_name_t *name, hicn_name_suffix_t suffix);

/**
 * @brief Retrieves the segment part of an hICN name
 * @param [in,out] name - hICN name
 * @param [in] seq_number - Segment identifier
 * @return hICN error code
 */
int hicn_name_get_seq_number (const hicn_name_t *name, u32 *seq_number);

/**
 * @brief Convert an hICN name to a socket address
 * @param [in] name - Name to convert
 * @param [out] ip_address - Resulting socket address
 * @return hICN error code
 */
int hicn_name_to_sockaddr_address (const hicn_name_t *name,
				   struct sockaddr *ip_address);

/**
 * @brief Convert an hICN name to an IP address
 * @param [in] name - Name to convert
 * @param [out] ip_address - Resulting IP address
 * @return hICN error code
 */
int hicn_name_to_hicn_ip_prefix (const hicn_name_t *name,
				 hicn_ip_prefix_t *hicn_ip_prefix);

/**
 * @brief Convert an hICN name to presentation format
 * @param [in] src - Name to convert
 * @param [out] dst - Buffer to receive the name in presentation format
 * @param [in] len - Number of bytes available in the buffer
 * @return hICN error code
 */
int hicn_name_ntop (const hicn_name_t *src, char *dst, size_t len);

/**
 * @brief Convert an hICN name from presentation format
 * @param [in] src - Name in presentation format to parse
 * @param [out] dst - Resulting name
 * @return hICN error code
 */
int hicn_name_pton (const char *src, hicn_name_t *dst);

/**
 * @brief Returns the IP address family of an hICN name
 * @param [in] name - Name to lookup
 * @param [out] family - Resulting IP address family (AF_INET or AF_INET6)
 * @return hICN error code
 */
int hicn_name_get_family (const hicn_name_t *name, int *family);

bool hicn_name_is_v4 (const hicn_name_t *name);

int hicn_name_snprintf (char *s, size_t size, const hicn_name_t *name);

int hicn_name_cmp (const hicn_name_t *n1, const hicn_name_t *n2);
bool hicn_name_equals (const hicn_name_t *n1, const hicn_name_t *n2);

#define MAXSZ_HICN_NAME MAXSZ_IP_ADDRESS

/**
 * @brief Creates an hICN prefix from an IP address
 * @param [in] ip_address - Input IP address
 * @param [out] prefix - Resulting prefix
 * @return hICN error code
 */
int hicn_prefix_create_from_ip_prefix (const hicn_ip_prefix_t *hicn_ip_prefix,
				       hicn_prefix_t *prefix);

int
hicn_prefix_create_from_ip_address_len (const hicn_ip_address_t *ip_address,
					uint8_t len, hicn_prefix_t *prefix);

hicn_prefix_t *hicn_prefix_dup (const hicn_prefix_t *prefix);

int hicn_prefix_copy (hicn_prefix_t *dst, const hicn_prefix_t *src);

bool hicn_prefix_is_v4 (const hicn_prefix_t *prefix);

uint32_t hicn_prefix_lpm (const hicn_prefix_t *p1, const hicn_prefix_t *p2);

void hicn_prefix_clear (hicn_prefix_t *prefix, uint8_t start_from);

void hicn_prefix_truncate (hicn_prefix_t *prefix, uint8_t len);

int hicn_prefix_cmp (const hicn_prefix_t *p1, const hicn_prefix_t *p2);

bool hicn_prefix_equals (const hicn_prefix_t *p1, const hicn_prefix_t *p2);

int hicn_prefix_snprintf (char *s, size_t size, const hicn_prefix_t *prefix);

uint8_t hicn_prefix_get_bit (const hicn_prefix_t *prefix, uint8_t pos);

#define MAXSZ_HICN_PREFIX MAXSZ_IP_PREFIX

#endif /* HICN_NAME_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
