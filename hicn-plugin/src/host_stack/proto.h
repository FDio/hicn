/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __included_hicn_hs_proto__
#define __included_hicn_hs_proto__

#define PROTO_DATA_SIZE 32

typedef enum hicn_hs_proto_event_
{
  PROTO_N_EVENT,
} hicn_hs_proto_event_t;

struct hicn_hs_proto_
{
  u32 (*init) (hicn_hs_ctx_t * hc);
  u32 (*rcv_data) (hicn_hs_ctx_t * hc);
  u32 (*rcv_interest) (hicn_hs_ctx_t * hc);
  u32 (*on_interest_timeout) (hicn_hs_ctx_t *hc);
  u32 (*event) (hicn_hs_ctx_t *hc, hicn_hs_proto_event_t event);
  u32 (*next_seq_number) (hicn_hs_ctx_t *hc);
  u8 proto_data[PROTO_DATA_SIZE];
};

typedef struct hicn_hs_proto_ hicn_hs_proto_t;

always_inline void *
hicn_hs_proto_data(hicn_hs_proto_t *proto)
{
  return (void*)(proto->proto_data);
}

always_inline u32
hicn_hs_proto_init ();

#enfif /* __included_hicn_hs_proto__ */