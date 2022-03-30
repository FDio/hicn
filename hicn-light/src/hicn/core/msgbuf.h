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
 * \file msgbuf.h
 * \brief hICN message buffer
 */

#ifndef HICNLIGHT_MSGBUF
#define HICNLIGHT_MSGBUF

#include "name.h"
#include "ticks.h"
#include "messageHandler.h"
#include <hicn/ctrl/hicn-light-ng.h>

#define MTU 1500
#define INVALID_MSGBUF_ID ~0ul

#define msgbuf_id_is_valid(msgbuf_id) \
  ((unsigned long)msgbuf_id != INVALID_MSGBUF_ID)

#define foreach_msg_type \
  _(UNDEFINED)           \
  _(INTEREST)            \
  _(DATA)                \
  _(WLDR_NOTIFICATION)   \
  _(MAPME)               \
  _(COMMAND)             \
  _(N)

typedef enum {
#define _(x) MSGBUF_TYPE_##x,
  foreach_msg_type
#undef _
} msgbuf_type_t;
#undef foreach_msg_type

typedef struct {
  unsigned length;
  msgbuf_type_t type;
  unsigned connection_id;
  Ticks recv_ts;
  unsigned refs;
  unsigned path_label;
  union {
    /* Interest or data packet */
    struct {
      Name name;
    } id;
    /* Command packet */
    struct {
      command_type_t type;
    } command;
  };
  uint8_t packet[MTU];
} msgbuf_t;

#define msgbuf_get_name(M) (&((M)->id.name))
#define msgbuf_get_connection_id(M) ((M)->connection_id)
#define msgbuf_get_type(M) ((M)->type)
#define msgbuf_has_wldr(M) (messageHandler_HasWldr((M)->packet))
#define msgbuf_get_len(M) ((M)->length)
#define msgbuf_get_packet(M) ((M)->packet)
#define msgbuf_get_command_type(M) ((M)->command.type)

// XXX TODO EXPLAIN THE CONSTANT
#define msgbuf_get_lifetime(M) \
  (NSEC_TO_TICKS(messageHandler_GetInterestLifetime((M)->packet) * 1000000ULL))

// Lifetimes/expiry times in milliseconds
#define msgbuf_get_interest_lifetime(M) \
  (messageHandler_GetInterestLifetime((M)->packet))
#define msgbuf_get_data_expiry_time(M) \
  (messageHandler_GetContentExpiryTime((M)->packet))

static inline bool msgbuf_set_interest_lifetime(msgbuf_t *msgbuf,
                                                u32 lifetime) {
  return messageHandler_SetInterestLifetime(msgbuf->packet, lifetime);
}
static inline bool msgbuf_set_data_expiry_time(msgbuf_t *msgbuf, u32 lifetime) {
  return messageHandler_SetDataExpiryTime(msgbuf->packet, lifetime);
}

#define msgbuf_is_probe(M) messageHandler_IsAProbe((M)->packet)

/* Path label */

#define msgbuf_init_pathlabel(M) \
  ((M)->path_label = messageHandler_GetPathLabel((M)->packet))
#define msgbuf_update_pathlabel(M, outface)                               \
  {                                                                       \
    messageHandler_SetPathLabel((M)->packet,                              \
                                messageHandler_GetPathLabel((M)->packet), \
                                (M)->path_label);                         \
    messageHandler_UpdatePathLabel((M)->packet, outface);                 \
  }
#define msgbuf_reset_pathlabel(M)               \
  {                                             \
    (M)->path_label = 0;                        \
    messageHandler_ResetPathLabel((M)->packet); \
  }

/* WLDR */

#define msgbuf_reset_wldr_label(M) (messageHandler_ResetWldrLabel((M)->packet))
#define msgbuf_get_wldr_label(M) (messageHandler_GetWldrLabel((M)->packet))
#define msgbuf_get_wldr_expected_label(M) \
  (messageHandler_GetWldrExpectedLabel((M)->packet))
#define msgbuf_get_wldr_last_received(M) \
  (messageHandler_GetWldrLastReceived((M)->packet))
#define msgbuf_set_wldr_label(M, label) \
  (messageHandler_GetWldrLabel((M)->packet, label))

#endif /* HICNLIGHT_MSGBUF */
