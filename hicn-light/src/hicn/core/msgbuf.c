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
 * \file msgbuf.c
 * \brief Implementation hICN message buffer
 */

#include "msgbuf.h"
#include "../strategies/probe_generator.h"

int msgbuf_initialize(msgbuf_t *msgbuf) {
  /*
   * We define the format and the storage area of the packet buffer we
   * manipulate
   */
  hicn_packet_buffer_t *pkbuf = msgbuf_get_pkbuf(msgbuf);
  hicn_packet_set_buffer(pkbuf, msgbuf->packet, MTU, 0);
  hicn_packet_init_header(pkbuf, 0);
  return 0;
}

int msgbuf_initialize_from_packet(msgbuf_t *msgbuf) {
  hicn_packet_set_buffer(msgbuf_get_pkbuf(msgbuf), msgbuf->packet, MTU,
                         msgbuf_get_len(msgbuf));
  return 0;
}

bool msgbuf_is_command(const msgbuf_t *msgbuf) {
  return (*msgbuf->packet == REQUEST_LIGHT);
}

bool msgbuf_is_probe(const msgbuf_t *msgbuf) {
  hicn_name_t name;
  hicn_name_suffix_t suffix;

  assert(msgbuf_get_type(msgbuf) == HICN_PACKET_TYPE_DATA);

  const hicn_packet_buffer_t *pkbuf = msgbuf_get_pkbuf(msgbuf);
  hicn_data_get_name(pkbuf, &name);
  suffix = hicn_name_get_suffix(&name);
  return (suffix >= MIN_PROBE_SUFFIX && suffix <= MAX_PROBE_SUFFIX);
}
