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

#define msgbuf_from_packet(msgbuf, packet, length, type, connid, recv_time)             \
do {                                                                            \
  *msgbuf = (msgbuf_t) {                                                        \
    .receiveTime = (recv_time),                                                 \
    .connection_id = (connid),                                                  \
    .messageHead = (packet),                                                    \
    .length = (length),                                                         \
    .packetType = (type),                                                       \
    .name = (type != MESSAGE_TYPE_WLDR_NOTIFICATION                         \
        ? name_CreateFromPacket((packet), (type))                               \
        : NULL),                                                                \
  };                                                                            \
} while(0)

#define msgbuf_get_name(msgbuf) ((msgbuf)->name)
#define msgbuf_get_connection_id(msgbuf) ((msgbuf)->connection_id)
#define msgbuf_get_type(msgbuf) ((msgbuf)->packetType)
#define msgbuf_has_wldr(msgbuf) (messageHandler_HasWldr((msgbuf)->messageHead))
#define msgbuf_get_len(msgbuf) ((msgbuf)->length)
#define msgbuf_get_packet(msgbuf) ((msgbuf)->messageHead)

// XXX TODO EXPLAIN THE CONSTANT
#define msgbuf_get_interest_lifetime(msgbuf) (NSEC_TO_TICKS(messageHandler_GetInterestLifetime((msgbuf)->messageHead) * 1000000ULL))

#define msgbuf_is_probe(msgbuf) messageHandler_IsAProbe(msgbuf->messageHead)

/* Path label */

#define msgbuf_get_pathlabel(msgbuf) (messageHandler_GetPathLabel(msgbuf->messageHead))
#define msgbuf_set_pathlabel(msgbuf, label) (messageHandler_SetPathLabel(msgbuf->messageHead, label))
#define msgbuf_update_pathlabel(msgbuf, outface) (messageHandler_SetPathLabel(msgbuf->messageHead, outface))
#define msgbuf_reset_pathlabel(msgbuf) (messageHandler_ResetPathLabel(msgbuf->messageHead))

/* WLDR */

#define msgbuf_reset_wldr_label(msgbuf) (messageHandler_ResetWldrLabel(msgbuf->messageHead))
#define msgbuf_get_wldr_label(msgbuf) (messageHandler_GetWldrLabel(msgbuf->messageHead))
#define msgbuf_get_wldr_expected_label(msgbuf) (messageHandler_GetWldrExpectedLabel(msgbuf->messageHead))
#define msgbuf_get_wldr_last_received(msgbuf) (messageHandler_GetWldrLastReceived(msgbuf->messageHead))
#define msgbuf_set_wldr_label(msgbuf, label) (messageHandler_GetWldrLabel(msgbuf->messageHead, label))

#endif /* HICN_MSGBUF */


