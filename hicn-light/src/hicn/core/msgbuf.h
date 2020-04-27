/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 * \file msgbuf.h
 * \brief hICN message buffer
 */

#ifndef HICN_MSGBUF
#define HICN_MSGBUF

#include <hicn/core/name.h>
#include <hicn/core/ticks.h>
#include <hicn/core/messageHandler.h>

typedef struct {
  Ticks receiveTime;
  unsigned connection_id;
  Name *name;
  uint8_t *messageHead;
  unsigned length;
  uint8_t packetType;
} msgbuf_t;

#define msgbuf_from_packet(MSGBUF, PACKET, LENGTH, TYPE, CONNID, RECV_TIME)     \
do {                                                                            \
  *MSGBUF = (msgbuf_t) {                                                        \
    .receiveTime = (RECV_TIME),                                                 \
    .connection_id = (CONNID),                                                  \
    .messageHead = (PACKET),                                                    \
    .length = (LENGTH),                                                         \
    .packetType = (TYPE),                                                       \
    .name = (TYPE != MESSAGE_TYPE_WLDR_NOTIFICATION                             \
        ? name_CreateFromPacket((PACKET), (TYPE))                               \
        : NULL),                                                                \
  };                                                                            \
} while(0)

#define msgbuf_get_name(M) ((M)->name)
#define msgbuf_get_connection_id(M) ((M)->connection_id)
#define msgbuf_get_type(M) ((M)->packetType)
#define msgbuf_has_wldr(M) (messageHandler_HasWldr((M)->messageHead))
#define msgbuf_get_len(M) ((M)->length)
#define msgbuf_get_packet(M) ((M)->messageHead)

// XXX TODO EXPLAIN THE CONSTANT
#define msgbuf_get_interest_lifetime(M) (NSEC_TO_TICKS(messageHandler_GetInterestLifetime((M)->messageHead) * 1000000ULL))

#define msgbuf_is_probe(M) messageHandler_IsAProbe((M)->messageHead)

/* Path label */

#define msgbuf_get_pathlabel(M) (messageHandler_GetPathLabel((M)->messageHead))
#define msgbuf_set_pathlabel(M, label) (messageHandler_SetPathLabel((M)->messageHead, label))
#define msgbuf_update_pathlabel(M, outface) (messageHandler_SetPathLabel((M)->messageHead, outface))
#define msgbuf_reset_pathlabel(M) (messageHandler_ResetPathLabel((M)->messageHead))

/* WLDR */

#define msgbuf_reset_wldr_label(M) (messageHandler_ResetWldrLabel((M)->messageHead))
#define msgbuf_get_wldr_label(M) (messageHandler_GetWldrLabel((M)->messageHead))
#define msgbuf_get_wldr_expected_label(M) (messageHandler_GetWldrExpectedLabel((M)->messageHead))
#define msgbuf_get_wldr_last_received(M) (messageHandler_GetWldrLastReceived((M)->messageHead))
#define msgbuf_set_wldr_label(M, label) (messageHandler_GetWldrLabel((M)->messageHead, label))

#endif /* HICN_MSGBUF */


