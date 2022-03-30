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
 * @file protocol/ah.h
 * @brief AH packet header
 */
#ifndef HICN_PROTOCOL_NEW_H
#define HICN_PROTOCOL_NEW_H

#include "../common.h"
#include "../name.h"

/*
 * The length of the new header struct must be 28 bytes.
 */
#define EXPECTED_NEW_HDRLEN 32

typedef struct
{
  u8 version_reserved;
  u8 flags;
  u16 payload_length;
  u32 lifetime;
  ip_address_t prefix;
  u32 suffix;
  u32 path_label;
} _new_header_t;

#define NEW_HDRLEN sizeof (_new_header_t)
static_assert (EXPECTED_NEW_HDRLEN == NEW_HDRLEN,
	       "Size of new_header Struct does not match its expected size.");

/* TCP flags bit 0 first. */
#define foreach_hicn_new_flag                                                 \
  _ (SIG) /**< Signature header after. */                                     \
  _ (MAN) /**< Payload type is manifest. */                                   \
  _ (INT) /**< Packet is interest. */                                         \
  _ (LST) /**< Last data. */

enum
{
#define _(f) HICN_NEW_FLAG_BIT_##f,
  foreach_hicn_new_flag
#undef _
    HICN_NEW_N_FLAG_BITS,
};

enum
{
#define _(f) HICN_NEW_FLAG_##f = 1 << HICN_NEW_FLAG_BIT_##f,
  foreach_hicn_new_flag
#undef _
};

static inline int
_get_new_header_version (const _new_header_t *new_hdr)
{
  return ((new_hdr->version_reserved >> 4) & 0x0F);
}

static inline void
_set_new_header_version (_new_header_t *new_hdr)
{
  new_hdr->version_reserved = (0x9 << 4) & 0xF0;
}

#endif /* HICN_PROTOCOL_NEW_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
