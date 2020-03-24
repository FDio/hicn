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
#include <vpp/app/version.h>

#include <hicn_hs/error.h>
#include <hicn_hs/hicn_hs.h>

#include <hicn_hs/hicn_hs_utils.h>
#include <hicn_hs/hicn_hs_route.h>

#include <vppinfra/lock.h>

#define _IPV6 0

char *hicn_hs_error_strings[] = {
#define hicn_hs_error(n,s) s,
#include "errors/hicn_hs.def"
#undef hicn_hs_error
};

// Main hicn struct
hicn_hs_main_t hicn_hs_main;

always_inline u32
hicn_hs_ctx_alloc(u32 thread_index)
{
  hicn_hs_worker_t *wrk = hicn_hs_get_worker_by_thread(thread_index);
  hicn_hs_ctx_t *ctx;

  pool_get (wrk->hicn_ctxs, ctx);

  clib_memset (ctx, 0, sizeof (hicn_hs_ctx_t));
  ctx->c_thread_index = thread_index;
  ctx->timer_handle = HICN_HS_TIMER_HANDLE_INVALID;
  HICN_HS_DBG (3, "Allocated hicn_hs_ctx_t %u on thread %u",
	       ctx - wrk->hicn_ctxs, thread_index);
  
  return ctx - wrk->hicn_ctxs;
}

always_inline void
hicn_hs_make_interest(hicn_hs_ctx_t * ctx, vlib_buffer_t *b)
{
   hicn_format_t format = HF_INET6_TCP;
   hicn_header_t * header = vlib_buffer_get_current(b);
   hicn_name_t *name = hicn_hs_ctx_get_consumer_name(ctx);

  if (hicn_packet_init_header(format, header) < 0)
  {
    HICN_HS_DBG (1, "hicn header initialization failed");
    return;
  }

  if (hicn_interest_set_name(format, header, name) < 0)
  {
    HICN_HS_DBG (1, "Failed to copy name into interest packet");
    return;
  }

  header->v6.tcp.csum = hicn_hs_compute_checksum (ctx, b);
  return;
}

always_inline void*
hicn_hs_init_buffer(hicn_hs_ctx_t *ctx, vlib_buffer_t *b)
{
  ASSERT ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->total_length_not_including_first_buffer = 0;
  b->current_data = 0;
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
  hicn_hs_buffer(b)->ctx_index = ctx->c_index;
  /* Leave enough space for headers */
  return vlib_buffer_make_headroom (b, TRANSPORT_MAX_HDRS_LEN);
}

always_inline void
hicn_hs_enqueue_to_output (vlib_main_t *vm, vlib_buffer_t * b, u32 bi, u8 is_ip4)
{
  session_type_t st;
  hicn_hs_main_t *hm = hicn_hs_get_main();
  transport_proto_t proto = hm->transport_protocol_id;

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->error = 0;

  st = session_type_from_proto_and_ip (proto, is_ip4);
  session_add_pending_tx_buffer (st, vm->thread_index, bi);
}


void
hicn_hs_send_interest (hicn_hs_ctx_t * ctx)
{
  hicn_hs_worker_t *wrk = hicn_hs_get_worker_by_context (ctx);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b;
  u32 bi;

  if (PREDICT_FALSE (!vlib_buffer_alloc (vm, &bi, 1)))
    {
      HICN_HS_DBG (1, "Vlib buffer alloc failed.");
      return;
    }
  b = vlib_get_buffer (vm, bi);
  hicn_hs_init_buffer (ctx, b);
  hicn_hs_make_interest (ctx, b);
  hicn_hs_enqueue_to_output (vm, b, bi, ctx->c_is_ip4);
}

/*
 *************************************************************
 **************        SESSION CALLBACKS     *****************
 *************************************************************
 */
int hicn_hs_session_accepted_callback (session_t *new_session)
{
  return 0;
}

void hicn_hs_session_disconnect_callback (session_t *session)
{
  return;
}

int hicn_hs_session_connected_callback (u32 app_wrk_index, u32 opaque,
				       session_t * s, u8 code)
{
  HICN_HS_DBG(1, "Function called.");
  return 0;
}

void hicn_hs_session_reset_callback (session_t *session)
{
  return;
}

void hicn_hs_session_migrate_callback (session_t * s, session_handle_t new_sh)
{
  return;
}

int hicn_hs_add_segment_callback (u32 app_wrk_index, u64 segment_handle)
{
  return 0;
}

int hicn_hs_del_segment_callback (u32 app_wrk_index, u64 segment_handle)
{
  return 0;
}

int hicn_hs_session_rx_callback (session_t * session)
{
  return 0;
}

void hicn_hs_session_cleanup_callback (session_t * s, session_cleanup_ntf_t ntf)
{
  return;
}

int hicn_hs_app_cert_key_pair_delete_callback (app_cert_key_pair_t * ckpair)
{
  return 0;
}

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
  hicn_hs_ctx_t *hc;
  u32 hc_index;
  char name[128];
  
  hicn_ip_prefix_t ip_address;
  hicn_name_t *cons_name;

  CLIB_UNUSED (u32 node_index);

  /* We don't poll main thread if we have workers */
  if (vlib_num_workers ())
    thread_index = 1;

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
  hc->c_is_ip4 = rmt->is_ip4;
  hc->c_proto = hmm->transport_protocol_id;
  hc->c_fib_index = rmt->fib_index;
  hc->c_index = hc_index;

  /* XXX Hardcoded CBR protocol for the moment */
  hc->hs_proto = &cbr_proto;
  hc->running = 0;
  
  /* Set context configuration */
  if (!hicn_hs_cfg.csum_offload)
    hc->cfg_flags |= HICN_HS_CFG_F_NO_CSUM_OFFLOAD;

  if (!hicn_hs_cfg.allow_tso)
    hc->cfg_flags |= HICN_HS_CFG_F_NO_TSO;

  /* Initialize CBR protocol - consumer side */
  hc->hs_proto->init(hc);

  return hc_index;
}

void hicn_hs_proto_on_close (u32 conn_index, u32 thread_index)
{
  return;
}

/**
 * The port is used as prefix length
 */
static u32
hicn_hs_get_prefix_from_transport_endpoint(const transport_endpoint_t * tep, fib_prefix_t *prefix)
{
  HICN_HS_ASSERT(tep->port <= (tep->is_ip4 ? IPV4_ADDR_LEN_BITS : IPV6_ADDR_LEN_BITS));
  fib_prefix_from_ip46_addr(&tep->ip, prefix);
  prefix->fp_len = tep->port;

  return HICN_HS_ERROR_NONE;
}

/**
 * Start listen for interests belonging to prefix
 */
u32 hicn_hs_start_listen (u32 session_index, transport_endpoint_t * lcl)
{
  hicn_hs_worker_t *wrk = hicn_hs_get_worker_by_thread(0);
  hicn_hs_ctx_t *ctx;

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
  /* We need to call this because we call app_worker_init_connected in
   * quic_accept_stream, which assumes the connect segment manager exists */
  app_worker_alloc_connects_segment_manager (app_wrk);
  app = application_get (app_wrk->app_index);
  HICN_HS_DBG (2, "Called hicn_hs_start_listen for app %d", app_wrk->app_index);

  /**
   * Choose a transport index.
   * hicn_hs_get_next_trasnport_index()..
   */
  u32 ctx_index = hicn_hs_wrk_get_next_ctx_index(wrk);
  ctx = hicn_hs_get_ctx_by_index(ctx_index, 0);

  /**
   * Setup DPO
   */
  hicn_hs_dpo_create(ctx_index, lcl->is_ip4, &ctx->dpo);

  /**
   * Get prefix from transport_endpoint_t
   */
  hicn_hs_get_prefix_from_transport_endpoint(lcl, &ctx->producer_prefix);

  /**
   * Set prefix in fib
   */
  hicn_hs_route_add(&ctx->producer_prefix, &ctx->dpo);
  

  /**
   * Check if hicn_hs input node recives interests
   */

  return 0;
}

u32 hicn_hs_stop_listen (u32 conn_index)
{
  return 0;
}

transport_connection_t *hicn_hs_connection_get (u32 conn_idx, u32 thread_idx)
{
  return NULL;
}

transport_connection_t *hicn_hs_listener_get (u32 conn_index)
{
  return NULL;
}

void hicn_hs_update_time (f64 time_now, u8 thread_index)
{
  return;
}

int hicn_hs_custom_app_rx_callback (transport_connection_t *tconn)
{
  return 0;
}

int hicn_hs_custom_tx_callback (void *session, u32 max_burst_size)
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

/* *INDENT-OFF* */
static session_cb_vft_t hicn_hs_app_cb_vft = {
  .session_accept_callback = hicn_hs_session_accepted_callback,
  .session_disconnect_callback = hicn_hs_session_disconnect_callback,
  .session_connected_callback = hicn_hs_session_connected_callback,
  .session_reset_callback = hicn_hs_session_reset_callback,
  .session_migrate_callback = hicn_hs_session_migrate_callback,
  .add_segment_callback = hicn_hs_add_segment_callback,
  .del_segment_callback = hicn_hs_del_segment_callback,
  .builtin_app_rx_callback = hicn_hs_session_rx_callback,
  .session_cleanup_callback = hicn_hs_session_cleanup_callback,
  .app_cert_key_pair_delete_callback = hicn_hs_app_cert_key_pair_delete_callback,
};

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
  .format_connection = format_hicn_hs_connection,
  .format_half_open = format_hicn_hs_half_open,
  .format_listener = format_hicn_hs_listener,
  .get_transport_endpoint = hicn_hs_get_transport_endpoint,
  .get_transport_listener_endpoint = hicn_hs_get_transport_listener_endpoint,
  .transport_options = {
	  /* Used by session_register_transport to select the tx function.
	     TRANSPORT_TX_INTERNAL will delegate the transmission to the transport
	     protocol itself, throught he function hicn_hs_custom_tx_callback. Magic. */
    .tx_type = TRANSPORT_TX_INTERNAL,
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

  u32 segment_size = 256 << 20;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  hicn_hs_main_t *hm = &hicn_hs_main;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->session_cb_vft = &hicn_hs_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "hicn_hs");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = HICN_HS_DEFAULT_FIFO_SIZE;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = HICN_HS_DEFAULT_FIFO_SIZE;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 0;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach hicn host stack");
      return clib_error_return (0, "failed to attach hicn host stack");
    }

  // Register new protocol
  hm->transport_protocol_id = transport_register_new_protocol(&hicn_hs_proto,
			       				     FIB_PROTOCOL_IP6,
							     hm->hicn_hs_on6_idx);
  transport_register_protocol (hm->transport_protocol_id, &hicn_hs_proto,
			       FIB_PROTOCOL_IP4, hm->hicn_hs_on4_idx);

  hicn_hs_configuration_init ();

  // Register hicn_hs DPO
  hicn_hs_dpo_module_init();

  // Init route module
  hicn_hs_route_init();
  
  hm->enabled = 1;
  hm->app_index = a->app_index;
  vec_free (a->name);
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
  vec_validate (hm->workers, num_threads - 1);

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
  hm->transport_protocol_id = TRANSPORT_PROTO_INVALID;
  
  return 0;
}

VLIB_INIT_FUNCTION (hicn_hs_init);

VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Hicn hs session/transport layer"
//   .default_disabled = 1,
};
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
