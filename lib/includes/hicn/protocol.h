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
 * @file protocol.h
 * @brief Protocol header definitions
 */
#ifndef HICN_PROTOCOL_H
#define HICN_PROTOCOL_H

#include "protocol/ah.h"
#include "protocol/ipv4.h"
#include "protocol/ipv6.h"
#include "protocol/icmp.h"
#include "protocol/icmprd.h"
#include "protocol/tcp.h"
#include "protocol/udp.h"
#include "protocol/new.h"

typedef union
{
  _new_header_t newhdr;
  _ipv4_header_t ipv4;
  _ipv6_header_t ipv6;
  _tcp_header_t tcp;
  _udp_header_t udp;
  _icmp_header_t icmp;
  _icmprd_header_t icmprd;
  _ah_header_t ah;
  void *bytes;
} hicn_protocol_t;

#endif /* HICN_PROTOCOL_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
