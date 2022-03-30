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

#ifndef HICN_PROTOCOL_UDP_H
#define HICN_PROTOCOL_UDP_H

/*
 * The length of the UDP header struct must be 8 bytes.
 */
#define EXPECTED_UDP_HDRLEN 8

typedef struct
{
  u16 src_port;
  u16 dst_port;
  u16 length;
  u16 checksum;
} _udp_header_t;

#define UDP_HDRLEN sizeof (_udp_header_t)
static_assert (EXPECTED_UDP_HDRLEN == UDP_HDRLEN,
	       "Size of UDP struct does not match its expected size.");

#endif /* HICN_PROTOCOL_UDP_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
