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

static void
reset_protocol (hicn_hs_ctx_t *ctx)
{
  return;
}

static void
schedule_next_interests (hicn_hs_ctx_t *ctx, u8 is_first)
{
  if (is_first)
    hicn_hs_send_interest(ctx);
}

u32 cbr_proto_init (hicn_hs_ctx_t *ctx)
{
  if (ctx->running)
    return -1;

  reset_protocol(ctx);
  schedule_next_interests (ctx, 1);
  ctx->running = 1;

  return 0;
}

u32 cbr_proto_on_data (hicn_hs_ctx_t *ctx)
{
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
};