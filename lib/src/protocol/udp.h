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

#ifndef HICN_PROTOCOL_UDP_H
#define HICN_PROTOCOL_UDP_H

PACKED(
struct _udp_header_s
{
  u16 src_port;
  u16 dst_port;
  u16 length;
  u16 checksum;
});
typedef struct _udp_header_s _udp_header_t;

#define UDP_HDRLEN sizeof(_udp_header_t)

#endif /* HICN_PROTOCOL_UDP_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
