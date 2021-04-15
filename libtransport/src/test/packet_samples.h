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

#define TCP_PROTO 0x06
#define ICMP_PROTO 0x01
#define ICMP6_PROTO 0x3a

#define IPV6_HEADER(next_header, payload_length)                               \
  0x60, 0x00, 0x00, 0x00, 0x00, payload_length, next_header, 0x40, 0xb0, 0x06, \
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd, 0xab,  \
      0xcd, 0xef, 0xb0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  \
      0x00, 0x00, 0x00, 0x00, 0x00, 0xca

#define IPV4_HEADER(next_header, payload_length)                       \
  0x45, 0x02, 0x00, payload_length + 20, 0x47, 0xc4, 0x40, 0x00, 0x25, \
      next_header, 0x6e, 0x76, 0x03, 0x7b, 0xd9, 0xd0, 0xc0, 0xa8, 0x01, 0x5c

#define TCP_HEADER(flags)                                                 \
  0x12, 0x34, 0x43, 0x21, 0x00, 0x00, 0x00, 0x01, 0xb2, 0x8c, 0x03, 0x1f, \
      0x80, flags, 0x00, 0x0a, 0xb9, 0xbb, 0x00, 0x00

#define PAYLOAD \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x20, 0x00, 0x00

#define PAYLOAD_SIZE 12

#define ICMP_ECHO_REQUEST                                                     \
  0x08, 0x00, 0x87, 0xdb, 0x38, 0xa7, 0x00, 0x05, 0x60, 0x2b, 0xc2, 0xcb,     \
      0x00, 0x02, 0x29, 0x7c, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, \
      0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, \
      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, \
      0x34, 0x35, 0x36, 0x37

#define ICMP6_ECHO_REQUEST                                                    \
  0x80, 0x00, 0x86, 0x3c, 0x11, 0x0d, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,     \
      0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, \
      0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, \
      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33

#define AH_HEADER                                                             \
  0x00, (128 >> 2), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     \
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
