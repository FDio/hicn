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

#include <sys/socket.h>

#include <vnet/session/application.h>
#include <vnet/session/transport.h>
#include <vnet/session/session.h>
#include <vlib/unix/plugin.h>
#include <vppinfra/lock.h>

#include "error.h"
#include "host_stack.h"
#include "inlines.h"

#include "utils.h"
#include "route.h"

#define _IPV6 0

char *hicn_hs_error_strings[] = {
#define hicn_hs_error(n,s) s,
#include "errors/hicn_hs.def"
#undef hicn_hs_error
};

// Main hicn struct
hicn_hs_main_t hicn_hs_main;

/**
 * Initiate the connection to rmt, which is actually a content.
 * Send first interest and program rtx.
 */
int
hicn_hs_connect (transport_endpoint_cfg_t * rmt)
{
  hicn_hs_main_t *hmm = hicn_hs_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u32 thread_index = vm->thread_index;
  int rv;
  session_endpoint_cfg_t *sep;
  hicn_hs_ctx_t *hc;
  app_worker_t *app_wrk;
  session_handle_t sh;
  session_t *s;
  u32 hc_index;
  char name[128];
  
  hicn_ip_prefix_t ip_address;
  hicn_name_t *cons_name;

  CLIB_UNUSED (u32 node_index);

  /* We don't poll main thread if we have workers */
  if (vlib_num_workers ())
    thread_index = 1;

  sep = (session_endpoint_cfg_t *)(rmt);

  /* XXX Here we alloc a new ctx. Not clear yet how to trigger the consumer protocol
     from the session layer. TBD */
  hc_index = hicn_hs_ctx_alloc (thread_index);
  hc = hicn_hs_get_ctx_by_index(hc_index, thread_index);

  ip_copy (&hc->connection.rmt_ip, &rmt->ip, rmt->is_ip4);
  ip_copy ((ip46_address_t*)(&ip_address.address), &rmt->ip, rmt->is_ip4);
  ip_address.family = rmt->is_ip4 ? AF_INET : AF_INET6;
  ip_address.len = 128;
  cons_name = hicn_hs_ctx_get_consumer_name(hc);

  hicn_name_create_from_ip_prefix(&ip_address, 0, cons_name);
  hicn_name_ntop(cons_name, name, 128);
  HICN_HS_DBG(1, "Set name %s through hicn connect()", name);

  hc->c_rmt_port = rmt->port;
  hc->c_is_ip4 = sep->is_ip4;
  hc->c_proto = hmm->transport_protocol_id;
  /*
    FixMe: Hardcoded fib index!
   */
  hc->c_fib_index = fib_table_find(hc->c_is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6, 10);
  hc->parent_app_wrk_id = sep->app_wrk_index;
  hc->c_s_index = HICN_HS_SESSION_INVALID;
  hc->c_c_index = hc_index;
  hc->c_flags |= TRANSPORT_CONNECTION_F_CLESS; 
  hc->client_opaque = sep->opaque;

  /* XXX Hardcoded CBR protocol for the moment */
  hc->hs_proto = &cbr_proto;
  hc->running = 0;
  hc->accepted = 0;
  hc->mss = hicn_hs_default_mtu (hmm, hc->c_is_ip4);
  hc->current_content_size = 0;
  hc->bytes_produced = 0;
  hc->download_content_size = ~0;
  vec_validate (hc->pending_interests, HICN_HS_PEND_INT_SIZE);
  
  /* Set context configuration */
  if (!hicn_hs_cfg.csum_offload)
    hc->cfg_flags |= HICN_HS_CFG_F_NO_CSUM_OFFLOAD;

  if (!hicn_hs_cfg.allow_tso)
    hc->cfg_flags |= HICN_HS_CFG_F_NO_TSO;

  /**
   * Connectionless session.
   */

  /**
   * Allocate session and fifos now.
   * XXX To check: Maybe it is better to allocate sessions and fifos
   * upon reception of first data.
   */
  s = session_alloc_for_connection (&hc->connection);
  s->app_wrk_index = hc->parent_app_wrk_id;
  app_wrk = app_worker_get (s->app_wrk_index);
//   app_worker_alloc_connects_segment_manager (app_wrk);

  s->session_state = SESSION_STATE_OPENED;
  if (app_worker_init_connected (app_wrk, s))
    {
      session_free (s);
      return -1;
    }

  sh = session_handle (s);
  session_lookup_add_connection (&hc->connection, sh);

  rv = app_worker_connect_notify (app_wrk, s, SESSION_E_NONE, hc_index);

  /* Initialize CBR protocol - consumer side */
  hc->hs_proto->init(hc);

  return rv;
}

void hicn_hs_proto_on_close (u32 conn_index, u32 thread_index)
{
  return;
}

/**
 * The port is used as prefix length
 */
static u32
hicn_hs_get_prefix_from_transport_endpoint(const ip46_address_t* ip, const u16 port, u8 is_ip4, fib_prefix_t *prefix)
{
  HICN_HS_ASSERT(port <= (is_ip4 ? IPV4_ADDR_LEN_BITS : IPV6_ADDR_LEN_BITS));
  fib_prefix_from_ip46_addr(ip, prefix);
  prefix->fp_len = port;

  return HICN_HS_ERROR_NONE;
}

/**
 * Start listen for interests belonging to prefix
 */
u32 hicn_hs_start_listen (u32 session_index, transport_endpoint_t * lcl)
{
//   hicn_hs_worker_t *wrk = hicn_hs_get_worker_by_thread(0);
  hicn_hs_ctx_t *ctx;
  u32 ctx_index;
  hicn_hs_main_t *hmm = hicn_hs_get_main ();

//   vnet_listen_args_t _bargs, *args = &_bargs;
//   session_handle_t udp_handle;
  session_endpoint_cfg_t *sep;
//   session_t *udp_listen_session;
  app_worker_t *app_wrk;
  CLIB_UNUSED(application_t *app);
//   u32 lctx_index;
//   int rv;
  
  sep = (session_endpoint_cfg_t *) lcl;
  app_wrk = app_worker_get (sep->app_wrk_index);

  app_worker_alloc_connects_segment_manager (app_wrk);
  app = application_get (app_wrk->app_index);
  HICN_HS_DBG (2, "Called hicn_hs_start_listen for app %d", app_wrk->app_index);

  /**
   * Choose a transport index.
   * hicn_hs_get_next_trasnport_index()..
   */
//   u32 ctx_index = hicn_hs_wrk_get_next_ctx_index(wrk);
  /* XXX Here we alloc a new ctx. Not clear yet how to trigger the consumer protocol
     from the session layer. TBD */
  ctx_index = hicn_hs_ctx_alloc (0);
  ctx = hicn_hs_get_ctx_by_index(ctx_index, 0);

  ip_copy (&ctx->connection.lcl_ip, &lcl->ip, lcl->is_ip4);
  ctx->c_lcl_port = clib_net_to_host_u16(lcl->port);
  ctx->c_is_ip4 = lcl->is_ip4;
  ctx->c_proto = hmm->transport_protocol_id;
  /* FixMe: Hardcoded Fib Index! */
  ctx->c_fib_index = fib_table_find(ctx->c_is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6, 10);
  ctx->c_c_index = ctx_index;
  ctx->session_index = session_index;
  ctx->mss = hicn_hs_default_mtu (hmm, ctx->c_is_ip4);
  ctx->current_content_size = 0;
  ctx->bytes_produced = 0;

  /* Init output buffer hash table */
  clib_bihash_init_24_8 (&ctx->output_buffer, "prod-output-buffer",
  			 /* 256 k */ 256 << 10, /* 8 MB */ 8 << 20);

  /* XXX Hardcoded CBR protocol for the moment */
  ctx->hs_proto = &cbr_proto;
  ctx->running = 0;
  ctx->accepted = 0;
  
  /* Set context configuration */
  if (!hicn_hs_cfg.csum_offload)
    ctx->cfg_flags |= HICN_HS_CFG_F_NO_CSUM_OFFLOAD;

  if (!hicn_hs_cfg.allow_tso)
    ctx->cfg_flags |= HICN_HS_CFG_F_NO_TSO;

  /**
   * Setup DPO
   */
  hicn_hs_dpo_create(ctx_index, lcl->is_ip4, &ctx->dpo);

  /**
   * Get prefix from transport_endpoint_t
   */
  hicn_hs_get_prefix_from_transport_endpoint(&ctx->c_lcl_ip, ctx->c_lcl_port, ctx->c_is_ip4, &ctx->producer_prefix);

  /**
   * Set prefix in fib
   */
  hicn_hs_route_add(&ctx->producer_prefix, &ctx->dpo);

  /**
   * Check if hicn_hs input node recives interests
   */

  return ctx_index;
}

u32 hicn_hs_stop_listen (u32 conn_index)
{
  return 0;
}

transport_connection_t *hicn_hs_connection_get (u32 conn_idx, u32 thread_idx)
{
  hicn_hs_ctx_t *ctx = hicn_hs_get_ctx_by_index(conn_idx, thread_idx);
  return &ctx->connection;
}

transport_connection_t *hicn_hs_listener_get (u32 conn_index)
{
  hicn_hs_ctx_t *ctx = hicn_hs_get_ctx_by_index(conn_index, 0);
  return &ctx->connection;
}

int hicn_hs_send_params (transport_connection_t * tconn,
			 transport_send_params_t *sp)
{
  hicn_hs_ctx_t *ctx = (hicn_hs_ctx_t *) (tconn);
  sp->snd_space = ~0;

  /* TODO: figure out MTU of output interface! */
  sp->snd_mss = ctx->mss;
  sp->tx_offset = 0;
  sp->flags = 0;
  return 0;
}

/**
 * Push hicn header on data packet.
 * This function is not called for interests, which are rather crafted
 * directly in the transport layer.
 */
u32 hicn_hs_push_header (transport_connection_t * tconn, vlib_buffer_t * b)
{
  hicn_hs_ctx_t *ctx = (hicn_hs_ctx_t *) (tconn);
  hicn_hs_worker_t * wrk = hicn_hs_get_worker_by_context (ctx);
  u32 index;
  int rv;

  hicn_name_t *name = &ctx->current_production_name;
  hicn_hs_buffer(b)->is_interest = 0;
  hicn_hs_buffer(b)->ctx_index = ctx->c_c_index;
  hicn_hs_buffer(b)->flush = 0;
  vlib_buffer_push_hicn(ctx, b, HF_INET6_TCP, name, ctx->snd_nxt, 0);
  
  index = vlib_get_buffer_index (wrk->vm, b);
  obuffer_kv4_t kv;
  make_obuffer_kv (&kv, &ctx->current_production_name.prefix, ctx->snd_nxt++, index);
  rv = clib_bihash_add_del_24_8 (&ctx->output_buffer, &kv, 2);
  
  if (PREDICT_FALSE (rv < 0))
    {
      /* We tried to overwrite something already in the table. */
      obuffer_kv4_t kv_ret;
      rv = clib_bihash_search_inline_2_24_8 (&ctx->output_buffer, &kv, &kv_ret);
      if (!rv)
        {
	  hicn_header_t *interest, *data;
	  vlib_buffer_t *buffer;
	  hicn_hs_buffer(b)->flush = 1;
	  clib_bihash_add_del_24_8 (&ctx->output_buffer, &kv, 1);

	  buffer = vlib_get_buffer (wrk->vm, kv_ret.value);
	  interest = vlib_buffer_get_current (buffer);
	  data = vlib_buffer_get_current (b);
	  data->v6.ip.daddr = interest->v6.ip.saddr;

	  vlib_buffer_free_one (wrk->vm, kv_ret.value);
	}
    }

  return 0;
}

void hicn_hs_update_time (f64 time_now, u8 thread_index)
{
  return;
}

int hicn_hs_custom_app_rx_callback (transport_connection_t *tconn)
{
  return 0;
}

int hicn_hs_custom_tx_callback (void *session, transport_send_params_t *sp)
{
  return 0;
}

u8 *format_hicn_hs_connection (u8 * s, va_list * args)
{
  return NULL;
}

u8 *format_hicn_hs_half_open (u8 * s, va_list * args)
{
  return NULL;
}

u8 *format_hicn_hs_listener (u8 * s, va_list * args)
{
  return NULL;
}

void hicn_hs_get_transport_endpoint (u32 conn_index, u32 thread_index,
        			     transport_endpoint_t *tep, u8 is_lcl)
{
  return;
}

void hicn_hs_get_transport_listener_endpoint (u32 conn_index,
               				 transport_endpoint_t *tep,
               				 u8 is_lcl)
{
  return;
}

static void
hicn_hs_expired_timers_dispatch (u32 * expired_timers)
{
  HICN_HS_DBG(1, "Timer expired.");
}

static const transport_proto_vft_t hicn_hs_proto = {
  .connect = hicn_hs_connect,
  .close = hicn_hs_proto_on_close,
  .start_listen = hicn_hs_start_listen,
  .stop_listen = hicn_hs_stop_listen,
  .get_connection = hicn_hs_connection_get,
  .get_listener = hicn_hs_listener_get,
  .update_time = hicn_hs_update_time,
  .app_rx_evt = hicn_hs_custom_app_rx_callback,
  .custom_tx = hicn_hs_custom_tx_callback,
  .send_params = hicn_hs_send_params,
  .push_header = hicn_hs_push_header,
  .format_connection = format_hicn_hs_connection,
  .format_half_open = format_hicn_hs_half_open,
  .format_listener = format_hicn_hs_listener,
  .get_transport_endpoint = hicn_hs_get_transport_endpoint,
  .get_transport_listener_endpoint = hicn_hs_get_transport_listener_endpoint,
  .transport_options = {
	  /* Used by session_register_transport to select the tx function.
	     TRANSPORT_TX_INTERNAL will delegate the transmission to the transport
	     protocol itself, throught he function hicn_hs_custom_tx_callback. Magic. */
    .tx_type = TRANSPORT_TX_DEQUEUE,
    .service_type = TRANSPORT_SERVICE_APP,
    .name = "hicn",
    .short_name = "H"
  },
};

/**
 * Initialize default values for tcp parameters
 */
static void
hicn_hs_configuration_init (void)
{
  hicn_hs_cfg.max_rx_fifo = 32 << 20;
  hicn_hs_cfg.min_rx_fifo = 4 << 10;

  hicn_hs_cfg.default_mtu = 1500;
  hicn_hs_cfg.enable_tx_pacing = 0;
  hicn_hs_cfg.allow_tso = 0;
  hicn_hs_cfg.csum_offload = 1;

  /* Time constants defined as timer tick (100ms) multiples */
  hicn_hs_cfg.closewait_time = 20;	/* 2s */
  hicn_hs_cfg.cleanup_time = 0.1;	/* 100ms */
}

clib_error_t *
hicn_hs_enable (vlib_main_t * vm)
{
  HICN_HS_DBG (1, "Function called (%p).", &hicn_hs_proto);

  hicn_hs_main_t *hm = &hicn_hs_main;

  hicn_hs_configuration_init ();

  // Register hicn_hs DPO
  hicn_hs_dpo_module_init();

  // Init route module
  hicn_hs_route_init();
  
  hm->enabled = 1;
  return 0;
}

clib_error_t *
hicn_hs_enable_disable(vlib_main_t * vm, u8 is_en)
{
  if (is_en)
    {  
       if (session_main_is_enabled())
         return hicn_hs_enable (vm);
       else
         return clib_error_return (0, "Session not enabled, so hicn hoststack not enabled.");
    }

  return 0;
}

static clib_error_t *
hicn_hs_init (vlib_main_t * vm)
{
  HICN_HS_DBG(1, "Function called");
  hicn_hs_main_t *hm = &hicn_hs_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 i, num_threads = 1 /* main thread */  + vtm->n_threads;
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;

  hm->app_index = 0;
  vec_validate_aligned (hm->workers, num_threads - 1, CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < num_threads; i++)
    {
      tw = &hm->workers[i].timer_wheel;
      tw_timer_wheel_init_1t_3w_1024sl_ov (tw, hicn_hs_expired_timers_dispatch,
					   1e-3 /* timer period 1ms */ , ~0);
      tw->last_run_time = vlib_time_now (vlib_get_main ());
      hm->workers[i].vm = vlib_mains[i];
      hm->workers[i].next_hicn_ctx = 0;
    }

  hm->tstamp_ticks_per_clock = vm->clib_time.seconds_per_clock / HICN_HS_TSTAMP_RESOLUTION;

  hm->hicn_hs_in4_idx = hicn_hs_input4_node.index;
  hm->hicn_hs_on4_idx = hicn_hs_output4_node.index;

  hm->hicn_hs_in6_idx = hicn_hs_input6_node.index;
  hm->hicn_hs_on6_idx = hicn_hs_output6_node.index;

  // Not enabled by default
  hm->enabled = 0;

    // Register new protocol
  hm->transport_protocol_id = transport_register_new_protocol(&hicn_hs_proto,
			       				     FIB_PROTOCOL_IP6,
							     hm->hicn_hs_on6_idx);
  transport_register_protocol (hm->transport_protocol_id, &hicn_hs_proto,
			       FIB_PROTOCOL_IP4, hm->hicn_hs_on4_idx);
}

/* *INDENT-ON* */

static clib_error_t *
hicn_hs_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  HICN_HS_DBG(1, "Function called early.");
  return 0;
}

static clib_error_t *
hicn_hs_config2_fn (vlib_main_t * vm, unformat_input_t * input)
{
  HICN_HS_DBG(1, "Function called.");
  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (hicn_hs_config_fn, "hicn_hs");
VLIB_CONFIG_FUNCTION (hicn_hs_config2_fn, "hicn_hs");
