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
 * @file protocol/ah.h
 * @brief AH packet header
 */
#ifndef HICN_PROTOCOL_AH_H
#define HICN_PROTOCOL_AH_H

#include "../common.h"

/*
 * The TCP PSH flag is set to indicate TCP payload in fact contains a AH header
 * with signature information for the packet
 */
#define AH_FLAG 0x10

/*
 * The length of the AH struct must be 44 bytes.
 */
#define EXPECTED_AH_HDRLEN 44

typedef struct
{
  u8 nh;			// (to match with reserved in IPSEC AH)
  u8 payloadlen;		// Len of signature/HMAC in 4-bytes words
  union
  {
    u16 reserved;

    struct
    {
      u8 validationAlgorithm;	// As defined in parc_SignerAlgorithm.h
      u8 unused;		// Unused (to match with reserved in IPSEC AH)
    };
  };
  union
  {
    struct
    {
      u32 spi;
      u32 seq;
    };
    // Unix timestamp indicating when the signature has been calculated
    u8 timestamp_as_u8[8];
    u16 timestamp_as_u16[4];
    u32 timestamp_as_u32[2];
  };
  // ICV would follow
  u8 keyId[32];			// Hash of the pub key
  /* 44 B + validationPayload */
  u8 validationPayload[0];	// Holds the signature
} _ah_header_t;

#define AH_HDRLEN sizeof(_ah_header_t)
static_assert (EXPECTED_AH_HDRLEN == AH_HDRLEN,
	       "Size of AH Struct does not match its expected size.");

#endif /* HICN_PROTOCOL_AH_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
