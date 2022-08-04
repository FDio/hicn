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
 * \file msgbuf.h
 * \brief hICN message buffer
 */

#ifndef HICNLIGHT_MSGBUF
#define HICNLIGHT_MSGBUF

#include <hicn/name.h>
#include "ticks.h"
#include <hicn/hicn.h>
#include <hicn/ctrl/hicn-light.h>

#define MTU 1500
#define INVALID_MSGBUF_ID ~0ul

#define msgbuf_id_is_valid(msgbuf_id) \
  ((unsigned long)msgbuf_id != INVALID_MSGBUF_ID)

typedef struct {
  hicn_packet_buffer_t pkbuf;
  unsigned connection_id;  // ingress
  Ticks recv_ts;           // timestamp
  unsigned refs;           // refcount
  unsigned path_label;     // XXX what is this ?

  // XXX Cache storage
  union {
    /* Interest or data packet */
    struct {
      hicn_name_t name;
      u32 name_hash;  // XXX should be always populate when name is assigned
    } id;
    /* Command packet */
    struct {
      command_type_t type;
    } command;
  };
  uint8_t packet[MTU];
} msgbuf_t;

int msgbuf_initialize(msgbuf_t *msgbuf);
int msgbuf_initialize_from_packet(msgbuf_t *msgbuf);

#define msgbuf_get_pkbuf(M) (&(M)->pkbuf)

static inline hicn_packet_type_t msgbuf_get_type(const msgbuf_t *msgbuf) {
  return hicn_packet_get_type(msgbuf_get_pkbuf(msgbuf));
}

static inline void msgbuf_set_type(msgbuf_t *msgbuf, hicn_packet_type_t type) {
  hicn_packet_set_type(msgbuf_get_pkbuf(msgbuf), type);
}

static inline const hicn_name_t *msgbuf_get_name(const msgbuf_t *msgbuf) {
  hicn_packet_type_t type = msgbuf_get_type(msgbuf);
  assert(type == HICN_PACKET_TYPE_INTEREST || type == HICN_PACKET_TYPE_DATA);
  (void)type;

  return &msgbuf->id.name;
}

#define msgbuf_get_connection_id(M) ((M)->connection_id)
#define msgbuf_get_packet(M) ((M)->packet)
#define msgbuf_get_command_type(M) ((M)->command.type)
#if WITH_WLDR
#define msgbuf_has_wldr(M) (messageHandler_HasWldr((M)->packet))
#endif

static inline void msgbuf_set_name(msgbuf_t *msgbuf, const hicn_name_t *name) {
  msgbuf->id.name = *name;
}

static inline size_t msgbuf_get_len(const msgbuf_t *msgbuf) {
  return hicn_packet_get_len(msgbuf_get_pkbuf(msgbuf));
}

static inline void msgbuf_set_len(msgbuf_t *msgbuf, size_t len) {
  int rc = hicn_packet_set_len(msgbuf_get_pkbuf(msgbuf), len);
  assert(rc == HICN_LIB_ERROR_NONE);  // XXX
  _unused(rc);
}

static inline u32 msgbuf_get_name_hash(const msgbuf_t *msgbuf) {
  hicn_packet_type_t type = msgbuf_get_type(msgbuf);
  assert(type == HICN_PACKET_TYPE_INTEREST || type == HICN_PACKET_TYPE_DATA);
  _unused(type);
  return msgbuf->id.name_hash;
}

// Lifetimes/expiry times in milliseconds
static inline u32 msgbuf_get_interest_lifetime(const msgbuf_t *msgbuf) {
  u32 lifetime;
  int rc = hicn_interest_get_lifetime(msgbuf_get_pkbuf(msgbuf), &lifetime);
  assert(rc == HICN_LIB_ERROR_NONE);  // XXX
  _unused(rc);
  return lifetime;
}

//#define msgbuf_get_lifetime(M)
//  (NSEC_TO_TICKS(messageHandler_GetInterestLifetime((M)->packet) *
//  1000000ULL))
#define msgbuf_get_lifetime msgbuf_get_interest_lifetime

static inline bool msgbuf_set_interest_lifetime(msgbuf_t *msgbuf,
                                                u32 lifetime) {
  int rc = hicn_interest_set_lifetime(msgbuf_get_pkbuf(msgbuf), lifetime);
  return (rc == HICN_LIB_ERROR_NONE);
}

static inline u32 msgbuf_get_data_expiry_time(const msgbuf_t *msgbuf) {
  u32 lifetime;
  int rc = hicn_data_get_expiry_time(msgbuf_get_pkbuf(msgbuf), &lifetime);
  assert(rc == HICN_LIB_ERROR_NONE);  // XXX
  _unused(rc);
  return lifetime;
}

static inline bool msgbuf_set_data_expiry_time(msgbuf_t *msgbuf, u32 lifetime) {
  int rc = hicn_data_set_expiry_time(msgbuf_get_pkbuf(msgbuf), lifetime);
  return (rc == HICN_LIB_ERROR_NONE);
}

/* Path label */

static inline void msgbuf_init_pathlabel(msgbuf_t *msgbuf) {
  hicn_path_label_t pl;
  int rc = hicn_data_get_path_label(msgbuf_get_pkbuf(msgbuf), &pl);
  assert(rc == HICN_LIB_ERROR_NONE);
  _unused(rc);
  msgbuf->path_label = pl;
}

static inline int msgbuf_get_path_label(const msgbuf_t *msgbuf,
                                        hicn_path_label_t *pl) {
  assert(msgbuf_get_type(msgbuf) == HICN_PACKET_TYPE_DATA);
  return hicn_data_get_path_label(msgbuf_get_pkbuf(msgbuf), pl);
}

static inline int msgbuf_set_path_label(msgbuf_t *msgbuf,
                                        hicn_path_label_t pl) {
  assert(msgbuf_get_type(msgbuf) == HICN_PACKET_TYPE_DATA);
  return hicn_data_set_path_label(msgbuf_get_pkbuf(msgbuf), pl);
}

static inline int msgbuf_update_pathlabel(msgbuf_t *msgbuf,
                                          hicn_faceid_t outface) {
  assert(msgbuf_get_type(msgbuf) == HICN_PACKET_TYPE_DATA);

  hicn_path_label_t pl, newpl;
  if (msgbuf_get_path_label(msgbuf, &pl) < 0) return -1;

  update_path_label(pl, outface, &newpl);

  return msgbuf_set_path_label(msgbuf, newpl);
}

static inline void msgbuf_reset_pathlabel(msgbuf_t *msgbuf) {
  msgbuf->path_label = 0;
  hicn_data_set_path_label(msgbuf_get_pkbuf(msgbuf), 0);
  // ERROR ?
}

static inline void msgbuf_modify_suffix(msgbuf_t *msgbuf, uint32_t new_suffix) {
  hicn_name_t name;
  assert(msgbuf_get_type(msgbuf) == HICN_PACKET_TYPE_INTEREST);
  hicn_interest_get_name(msgbuf_get_pkbuf(msgbuf), &name);
  hicn_name_set_suffix(&name, new_suffix);
  hicn_interest_set_name(msgbuf_get_pkbuf(msgbuf), &name);
}

bool msgbuf_is_command(const msgbuf_t *msgbuf);
bool msgbuf_is_probe(const msgbuf_t *msgbuf);

/* WLDR */

#if 0
#define msgbuf_reset_wldr_label(M) (messageHandler_ResetWldrLabel((M)->packet))
#define msgbuf_get_wldr_label(M) (messageHandler_GetWldrLabel((M)->packet))
#define msgbuf_get_wldr_expected_label(M) \
  (messageHandler_GetWldrExpectedLabel((M)->packet))
#define msgbuf_get_wldr_last_received(M) \
  (messageHandler_GetWldrLastReceived((M)->packet))
#define msgbuf_set_wldr_label(M, label) \
  (messageHandler_GetWldrLabel((M)->packet, label))
#endif

#endif /* HICNLIGHT_MSGBUF */
