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

#include "hicn_hs.h"

#define WINDOW_SIZE 50

typedef struct hicn_hs_cbr_proto_data_
{
  u32 next_seq_number;
  u16 window_size;
  u16 in_flight_interests;
} hicn_hs_cbr_proto_data_t;

#define proto_data(ctx) ((hicn_hs_cbr_proto_data_t *) (ctx->hs_proto_data))

static void
reset_protocol (hicn_hs_cbr_proto_data_t *proto_data)
{
  proto_data->in_flight_interests = 0;
  proto_data->window_size = WINDOW_SIZE;
  proto_data->next_seq_number = 0;
}

static void
schedule_next_interests (hicn_hs_ctx_t *ctx)
{
  hicn_hs_cbr_proto_data_t *data = proto_data (ctx);
  u32 scheduled_interests = 0;

  if (data->in_flight_interests < data->window_size)
    scheduled_interests = hicn_hs_send_interests(ctx, data->next_seq_number,
    						 data->window_size - data->in_flight_interests);

  data->in_flight_interests += scheduled_interests;
  data->next_seq_number += scheduled_interests;
}

u32 cbr_proto_init (hicn_hs_ctx_t *ctx)
{
  if (ctx->running)
    return -1;

  hicn_hs_cbr_proto_data_t *data = proto_data (ctx);

  reset_protocol(data);
  schedule_next_interests (ctx);
  ctx->running = 1;

  return 0;
}

u32 cbr_proto_on_data (hicn_hs_ctx_t *ctx, u16 n_data)
{
  hicn_hs_cbr_proto_data_t *data = proto_data (ctx);
  data->in_flight_interests -= n_data;
  schedule_next_interests (ctx);
  return 0;
}

u32 cbr_proto_on_interest (hicn_hs_ctx_t *ctx)
{
  return 0;
}

u32 cbr_proto_interest_timeout (hicn_hs_ctx_t *ctx)
{
  return 0;
}

u32 cbr_proto_event (hicn_hs_ctx_t *ctx, hicn_hs_proto_event_t event)
{
  return 0;
}

hicn_hs_proto_t cbr_proto = {
  .init = cbr_proto_init,
  .rcv_data = cbr_proto_on_data,
  .rcv_interest = cbr_proto_on_interest,
  .on_interest_timeout = cbr_proto_interest_timeout,
  .event = cbr_proto_event,
  .options = {
    .is_stream = 1
  }
};