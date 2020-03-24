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

#ifndef __included_hicn_hs_h__
#define __included_hicn_hs_h__

#include <vnet/session/application_interface.h>
#include <vnet/session/transport.h>

#include <vppinfra/lock.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>
#include <vppinfra/bihash_16_8.h>
#include <vnet/crypto/crypto.h>
#include <vppinfra/lock.h>

#ifndef HICN_VPP_PLUGIN
#define HICN_VPP_PLUGIN
#define ip_address_t hicn_ip_address_t
#define ip_address_cmp hicn_ip_address_cmp
#define ip_prefix_t hicn_ip_prefix_t
#define ip_prefix_cmp hicn_ip_prefix_cmp
#undef ip_prefix_len
#define ip_prefix_len hicn_ip_prefix_len
#include <hicn/hicn.h>
#include <hicn/compat.h>
#undef ip_address_t
#undef ip_address_cmp
#undef ip_prefix_t
#undef ip_prefix_cmp
#undef ip_prefix_len
#define ip_prefix_len(_a) (_a)->len
#endif

/* Log levels
 * 1 - errors
 * 2 - connection/stream events
 * 3 - packet events
 * 4 - timer events
 **/

#define HICN_HS_DEBUG               1
#define HICN_HS_TSTAMP_RESOLUTION  0.001	/* HICN_HS tick resolution (1ms) */
#define HICN_HS_TIMER_HANDLE_INVALID ((u32) ~0)
#define HICN_HS_SESSION_INVALID ((u32) ~0 - 1)
#define HICN_HS_MAX_PACKET_SIZE 1280

#define HICN_HS_INT_MAX  0x3FFFFFFFFFFFFFFF
#define HICN_HS_DEFAULT_FIFO_SIZE (64 << 10)
#define HICN_HS_DEFAULT_CONN_TIMEOUT (30 * 1000)	/* 30 seconds */
#define HICN_HS_SEND_PACKET_VEC_SIZE 16
#define HICN_HS_IV_LEN 17

#define HICN_HS_INPUT4_NODE_NAME "hicn_hs-input4"
#define HICN_HS_OUTPUT4_NODE_NAME "hicn_hs-output4"

#define HICN_HS_INPUT6_NODE_NAME "hicn_hs-input6"
#define HICN_HS_OUTPUT6_NODE_NAME "hicn_hs-output6"

#define CONSUMER_PROTO_DATA_SIZE 32
#define PRODUCER_PROTO_DATA_SIZE 32

#if HICN_HS_DEBUG
#define HICN_HS_DBG(_lvl, _fmt, _args...)   \
  if (_lvl <= HICN_HS_DEBUG)                \
    clib_warning (_fmt, ##_args)
#else
#define HICN_HS_DBG(_lvl, _fmt, _args...)
#endif

#if CLIB_ASSERT_ENABLE
#define HICN_HS_ASSERT(truth) ASSERT (truth)
#else
#define HICN_HS_ASSERT(truth)                        	\
  do {                                            	\
    if (PREDICT_FALSE (! (truth)))                	\
      HICN_HS_ERR ("ASSERT(%s) failed", # truth);    	\
  } while (0)
#endif

#define HICN_HS_ERR(_fmt, _args...)                	\
  do {                                          	\
    clib_warning ("HICN_HS-ERR: " _fmt, ##_args);  	\
  } while (0)

extern vlib_node_registration_t hicn_hs_input_node;

typedef enum
{
#define hicn_hs_error(n,s) HICN_HS_ERROR_##n,
#include <plugins/hicn_hs/errors/hicn_hs.def>
#undef hicn_hs_error
  HICN_HS_N_ERROR,
} hicn_hs_error_t;

typedef struct hicn_hs_proto_ hicn_hs_proto_t;

typedef enum hicn_hs_proto_event_
{
  CONSUMER_N_EVENT,
} hicn_hs_proto_event_t;

typedef struct hicn_hs_ctx_
{
  transport_connection_t connection;
  u32 c_index;
  u32 timer_handle;
  hicn_hs_proto_t *hs_proto;
  u8 hs_proto_data[CONSUMER_PROTO_DATA_SIZE];

  // The hicn name for the consumer session
  hicn_name_t consumer_name;

  // The prefix for the producer names.
  /* XXX To be retrieved from a pool of names configured by the control protocol / network admin */
  hicn_prefix_t producer_prefix;

  u8 running;
} hicn_hs_ctx_t;

typedef struct {
  u32 ctx_index;
} hicn_hs_buffer_t;

#define hicn_hs_buffer(b) ((hicn_hs_buffer_t *) (b)->opaque2)

always_inline void *
hicn_hs_proto_data(hicn_hs_ctx_t *ctx)
{
  return (void*)(ctx->hs_proto_data);
}

struct hicn_hs_proto_
{
  u32 (*init) (hicn_hs_ctx_t * hc);
  u32 (*rcv_data) (hicn_hs_ctx_t * hc);
  u32 (*rcv_interest) (hicn_hs_ctx_t * hc);
  u32 (*on_interest_timeout) (hicn_hs_ctx_t *hc);
  u32 (*event) (hicn_hs_ctx_t *hc, hicn_hs_proto_event_t event);
};

typedef struct hicn_hs_worker_ctx_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  hicn_hs_ctx_t *hicn_ctxs;		   	   /**< worker's pool of hicn context */
  int64_t time_now;				   /**< worker time */
  tw_timer_wheel_1t_3w_1024sl_ov_t timer_wheel;	   /**< worker timer wheel */
  vlib_main_t *vm;				   /**< pointer to thread's vlib main*/
} hicn_hs_worker_t;

typedef struct hicn_hs_main_
{
  u32 app_index;
  hicn_hs_worker_t *workers;
  clib_bihash_16_8_t connection_hash;	/**< connection id -> conn handle */
  f64 tstamp_ticks_per_clock;

  // The new registered transport ID
  transport_proto_t transport_protocol_id;

  // Input/Output nodes information
  u32 hicn_hs_in4_idx;
  u32 hicn_hs_on4_idx;
  u32 hicn_hs_in6_idx;
  u32 hicn_hs_on6_idx;

  // Enabled/Disabled
  u8 enabled;

  u32 udp_fifo_size;
  u32 udp_fifo_prealloc;
  u32 connection_timeout;
} hicn_hs_main_t;

extern hicn_hs_main_t hicn_hs_main;
extern vlib_node_registration_t hicn_hs_input4_node;
extern vlib_node_registration_t hicn_hs_output4_node;
extern vlib_node_registration_t hicn_hs_input6_node;
extern vlib_node_registration_t hicn_hs_output6_node;

// Protocols
extern hicn_hs_proto_t cbr_proto;

always_inline
hicn_hs_main_t *hicn_hs_get_main ()
{
  return &hicn_hs_main;
}

always_inline
transport_proto_t hicn_hs_get_protocol_id()
{
  hicn_hs_main_t *hm = hicn_hs_get_main ();
  return hm->transport_protocol_id;
}

clib_error_t * hicn_hs_enable_disable(vlib_main_t * vm, u8 is_en);

void hicn_hs_send_interest(hicn_hs_ctx_t *ctx);

always_inline hicn_hs_worker_t *
hicn_hs_get_worker_by_context (hicn_hs_ctx_t *ctx)
{
  hicn_hs_main_t *hmm = hicn_hs_get_main ();
  return &hmm->workers[ctx->c_thread_index];
}

always_inline hicn_hs_worker_t *
hicn_hs_get_worker_by_thread (u32 thread_idx)
{
  hicn_hs_main_t *hmm = hicn_hs_get_main ();
  return &hmm->workers[thread_idx];
}

always_inline hicn_hs_ctx_t *
hicn_hs_wrk_get_ctx(hicn_hs_worker_t *wrk, u32 index)
{
  return pool_elt_at_index (wrk->hicn_ctxs, index);
}

always_inline hicn_hs_ctx_t *
hicn_hs_get_ctx_by_index (u32 ctx_index, u32 thread_index)
{
  hicn_hs_worker_t *wrk = hicn_hs_get_worker_by_thread(thread_index);
  return hicn_hs_wrk_get_ctx(wrk, ctx_index);
}

always_inline hicn_name_t*
hicn_hs_ctx_get_consumer_name(hicn_hs_ctx_t *ctx)
{
  return &ctx->consumer_name;
}

#endif /* __included_hicn_hs_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
