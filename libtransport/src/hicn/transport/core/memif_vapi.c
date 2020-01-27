/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
#include <hicn/transport/config.h>

#ifdef __vpp__

#include <vapi/vapi_safe.h>
#include <vppinfra/clib.h>
#include <hicn/transport/core/memif_vapi.h>
#include <fcntl.h>
#include <inttypes.h>
#include <semaphore.h>
#include <string.h>
#include <sys/stat.h>

DEFINE_VAPI_MSG_IDS_MEMIF_API_JSON

static vapi_error_e memif_details_cb(vapi_ctx_t ctx,
                                     void *callback_ctx,
                                     vapi_error_e rv,
                                     bool is_last,
                                     vapi_payload_memif_details *reply) {
  uint32_t *last_memif_id = (uint32_t *)callback_ctx;
  uint32_t current_memif_id = 0;
  if (reply != NULL) {
    current_memif_id = reply->id;
  }
  else {
    return rv;
  }

  if (current_memif_id >= *last_memif_id) {
    *last_memif_id = current_memif_id + 1;
  }

  return rv;
}

int memif_vapi_get_next_memif_id(vapi_ctx_t ctx,
                                uint32_t *memif_id) {
  vapi_lock();
  vapi_msg_memif_dump * msg = vapi_alloc_memif_dump(ctx);
  int ret = vapi_memif_dump(ctx, msg, memif_details_cb, memif_id);
  vapi_unlock();
  return ret;
}

static vapi_error_e memif_create_cb(vapi_ctx_t ctx,
                              void *callback_ctx,
                              vapi_error_e rv,
                              bool is_last,
                              vapi_payload_memif_create_reply *reply) {
  memif_output_params_t *output_params = (memif_output_params_t *)callback_ctx;

  if (reply == NULL)
    return rv;

  output_params->sw_if_index = reply->sw_if_index;

  return rv;
}

int memif_vapi_create_memif(vapi_ctx_t ctx,
                            memif_create_params_t *input_params,
                            memif_output_params_t *output_params) {
  vapi_lock();
  vapi_msg_memif_create * msg = vapi_alloc_memif_create(ctx);

  int ret = 0;
  if (input_params->socket_id == ~0) {
    // invalid socket-id
    ret = -1;
    goto END;
  }

  if (!is_pow2(input_params->ring_size)) {
    // ring size must be power of 2
    ret = -1;
    goto END;
  }

  if (input_params->rx_queues > 255 || input_params->rx_queues < 1) {
    // rx queue must be between 1 - 255
    ret = -1;
    goto END;
  }

  if (input_params->tx_queues > 255 || input_params->tx_queues < 1) {
    // tx queue must be between 1 - 255
    ret = -1;
    goto END;
  }

  msg->payload.role = input_params->role;
  msg->payload.mode = input_params->mode;
  msg->payload.rx_queues = input_params->rx_queues;
  msg->payload.tx_queues = input_params->tx_queues;
  msg->payload.id = input_params->id;
  msg->payload.socket_id = input_params->socket_id;
  msg->payload.ring_size = input_params->ring_size;
  msg->payload.buffer_size = input_params->buffer_size;

  ret = vapi_memif_create(ctx, msg, memif_create_cb, output_params);
 END:
  vapi_unlock();
  return ret;
}

static vapi_error_e memif_delete_cb(vapi_ctx_t ctx,
                              void *callback_ctx,
                              vapi_error_e rv,
                              bool is_last,
                              vapi_payload_memif_delete_reply *reply) {
  if(reply == NULL)
    return rv;
  
  return reply->retval;
}

int memif_vapi_delete_memif(vapi_ctx_t ctx,
                                  uint32_t sw_if_index) {
  vapi_lock();
  vapi_msg_memif_delete * msg = vapi_alloc_memif_delete(ctx);

  msg->payload.sw_if_index = sw_if_index;

  int ret = vapi_memif_delete(ctx, msg, memif_delete_cb, NULL);
  vapi_unlock();
  return ret;
}

#endif  // __vpp__
