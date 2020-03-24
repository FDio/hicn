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

always_inline void
make_obuffer_kv (obuffer_kv4_t * kv, ip46_address_t * prefix, u32 suffix, u32 bi)
{
  kv->key[0] = prefix->as_u64[0];
  kv->key[1] = prefix->as_u64[1];
  kv->key[2] = suffix;
  kv->value = bi;
}

always_inline u16
hicn_hs_default_mtu (hicn_hs_main_t * hm, u8 is_ip4)
{
  u16 hicn_hlen = is_ip4 ? HICN_V4_TCP_HDRLEN : HICN_V6_TCP_HDRLEN;
  return (hicn_hs_cfg.default_mtu - hicn_hlen);
}

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

always_inline void*
vlib_buffer_push_hicn (hicn_hs_ctx_t *ctx, vlib_buffer_t *b, hicn_format_t format,
		       hicn_name_t* name, u32 seq_number, u8 is_interest)
{
  hicn_header_t *hicn_header;
  u16 current_length = b->current_length;
  u16 payload_len = sizeof (tcp_header_t) + current_length;
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID))
    payload_len += b->total_length_not_including_first_buffer;

  if (PREDICT_FALSE (ctx->current_bytes_produced == ctx->current_production_size && !is_interest))
    {
      // Last packet
      hicn_packet_set_rst (hicn_header);
    }

  hicn_header = vlib_buffer_push_uninit (b, HICN_V6_TCP_HDRLEN);
  hicn_packet_init_header(format, hicn_header);
  hicn_name_set_seq_number(name, seq_number);

  if (is_interest)
    hicn_interest_set_name(format, hicn_header, name);
  else
    hicn_data_set_name(format, hicn_header, name);
  
  hicn_header->v6.tcp.csum = hicn_hs_compute_checksum (ctx, b);

  vnet_buffer (b)->l4_hdr_offset = (u8 *) hicn_header - b->data;
  b->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;

  ctx->current_bytes_produced += current_length;

  return hicn_header;
}

always_inline u32
hicn_hs_make_interest (hicn_hs_ctx_t * ctx, vlib_buffer_t *b,
		       hicn_format_t format, hicn_name_t *name,
		       u32 seq_number)
{
  vlib_buffer_push_hicn(ctx, b, format, name, seq_number, 1);
  return 1;
}

always_inline void
hicn_hs_enqueue_to_output (vlib_main_t *vm, session_main_t *smm,
			   vlib_buffer_t * b, u32 bi, u8 is_ip4,
			   session_type_t st)
{
  session_add_pending_tx_buffer (vm->thread_index, bi, smm->session_type_to_next[st]);
}

always_inline u32
hicn_hs_send_interests_i (vlib_main_t *vm, hicn_hs_ctx_t *ctx, vlib_buffer_t **b, u32 *bi, u32 offset, u32 count)
{
  int ret;
  hicn_format_t format = HF_INET6_TCP;
  hicn_name_t *name = hicn_hs_ctx_get_consumer_name(ctx);
  session_type_t st;
  hicn_hs_main_t *hm = hicn_hs_get_main();
  session_main_t *smm = vnet_get_session_main ();
  transport_proto_t proto = hm->transport_protocol_id;

  st = session_type_from_proto_and_ip (proto, ctx->c_is_ip4);

  while (count >= 8)
    {
      {
	vlib_prefetch_buffer_header (b[4], STORE);
	CLIB_PREFETCH (b[4]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);

	vlib_prefetch_buffer_header (b[5], STORE);
	CLIB_PREFETCH (b[5]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);

	vlib_prefetch_buffer_header (b[6], STORE);
	CLIB_PREFETCH (b[6]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);

	vlib_prefetch_buffer_header (b[7], STORE);
	CLIB_PREFETCH (b[7]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);
      }

      ASSERT ((b[0]->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
      b[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      b[0]->total_length_not_including_first_buffer = 0;
      b[0]->current_data = 0;
      b[0]->error = 0;
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      hicn_hs_buffer(b[0])->ctx_index = ctx->c_c_index;
      hicn_hs_buffer(b[0])->is_interest = 1;
      /* Leave enough space for headers */
      vlib_buffer_make_headroom (b[0], TRANSPORT_MAX_HDRS_LEN);
      ret += hicn_hs_make_interest (ctx, b[0], format, name, offset++);
      hicn_hs_enqueue_to_output (vm, smm, b[0], bi[0], ctx->c_is_ip4, st);

      ASSERT ((b[1]->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
      b[1]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      b[1]->total_length_not_including_first_buffer = 0;
      b[1]->current_data = 0;
      b[1]->error = 0;
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      hicn_hs_buffer(b[1])->ctx_index = ctx->c_c_index;
      hicn_hs_buffer(b[1])->is_interest = 1;
      /* Leave enough space for headers */
      vlib_buffer_make_headroom (b[1], TRANSPORT_MAX_HDRS_LEN);
      ret += hicn_hs_make_interest (ctx, b[1], format, name, offset++);
      hicn_hs_enqueue_to_output (vm, smm, b[1], bi[1], ctx->c_is_ip4, st);

      ASSERT ((b[2]->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
      b[2]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      b[2]->total_length_not_including_first_buffer = 0;
      b[2]->current_data = 0;
      b[2]->error = 0;
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      hicn_hs_buffer(b[2])->ctx_index = ctx->c_c_index;
      hicn_hs_buffer(b[2])->is_interest = 1;
      /* Leave enough space for headers */
      vlib_buffer_make_headroom (b[2], TRANSPORT_MAX_HDRS_LEN);
      ret += hicn_hs_make_interest (ctx, b[2], format, name, offset++);
      hicn_hs_enqueue_to_output (vm, smm, b[2], bi[2], ctx->c_is_ip4, st);

      ASSERT ((b[3]->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
      b[3]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      b[3]->total_length_not_including_first_buffer = 0;
      b[3]->current_data = 0;
      b[3]->error = 0;
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);
      hicn_hs_buffer(b[3])->ctx_index = ctx->c_c_index;
      hicn_hs_buffer(b[3])->is_interest = 1;
      /* Leave enough space for headers */
      vlib_buffer_make_headroom (b[3], TRANSPORT_MAX_HDRS_LEN);
      ret += hicn_hs_make_interest (ctx, b[3], format, name, offset++);
      hicn_hs_enqueue_to_output (vm, smm, b[3], bi[3], ctx->c_is_ip4, st);

      b += 4;
      count -= 4;
    }
  while (count)
    {
      if (count > 1)
        {
	  vlib_prefetch_buffer_header (b[1], STORE);
	  CLIB_PREFETCH (b[1]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);
        }
      ASSERT ((b[0]->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
      b[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      b[0]->total_length_not_including_first_buffer = 0;
      b[0]->current_data = 0;
      b[0]->error = 0;
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      hicn_hs_buffer(b[0])->ctx_index = ctx->c_c_index;
      hicn_hs_buffer(b[0])->is_interest = 1;
      /* Leave enough space for headers */
      vlib_buffer_make_headroom (b[0], TRANSPORT_MAX_HDRS_LEN);
      ret += hicn_hs_make_interest (ctx, b[0], format, name, offset++);
      hicn_hs_enqueue_to_output (vm, smm, b[0], bi[0], ctx->c_is_ip4, st);

      b += 1;
      count -= 1;
    }

  return ret;
}

u32
hicn_hs_send_interests (hicn_hs_ctx_t * ctx, u32 start_offset, u32 n_interest)
{
  hicn_hs_worker_t *wrk = hicn_hs_get_worker_by_context (ctx);
  vlib_main_t *vm = wrk->vm;
  vlib_buffer_t *b[VLIB_FRAME_SIZE];
  u32 bi[VLIB_FRAME_SIZE];

  if (PREDICT_FALSE (!vlib_buffer_alloc (vm, bi, n_interest)))
    {
      HICN_HS_DBG (1, "Vlib buffer alloc failed.");
      return 0;
    }
  vlib_get_buffers (vm, bi, b, n_interest);
  return hicn_hs_send_interests_i (vm, ctx, b, bi, start_offset, n_interest);
}

/* Modulo arithmetic for TCP sequence numbers */
#define seq_lt(_s1, _s2) ((i32)((_s1)-(_s2)) < 0)
#define seq_leq(_s1, _s2) ((i32)((_s1)-(_s2)) <= 0)
#define seq_gt(_s1, _s2) ((i32)((_s1)-(_s2)) > 0)
#define seq_geq(_s1, _s2) ((i32)((_s1)-(_s2)) >= 0)
#define seq_max(_s1, _s2) (seq_gt((_s1), (_s2)) ? (_s1) : (_s2))

/** Enqueue data for delivery to application */
static int
hicn_hs_enqueue_data (hicn_hs_ctx_t * ctx, vlib_buffer_t * b,
		      u16 data_len)
{
  int written, error = HICN_HS_ERROR_ENQUEUED;

  ASSERT (seq_geq (hicn_hs_buffer (b)->tcp.seq_number, tc->rcv_nxt));
  ASSERT (data_len);
  written = session_enqueue_stream_connection (&tc->connection, b, 0,
					       1 /* queue event */ , 1);
  tc->bytes_in += written;

  TCP_EVT (TCP_EVT_INPUT, tc, 0, data_len, written);

  /* Update rcv_nxt */
  if (PREDICT_TRUE (written == data_len))
    {
      tc->rcv_nxt += written;
    }
  /* If more data written than expected, account for out-of-order bytes. */
  else if (written > data_len)
    {
      tc->rcv_nxt += written;
      TCP_EVT (TCP_EVT_CC_INPUT, tc, data_len, written);
    }
  else if (written > 0)
    {
      /* We've written something but FIFO is probably full now */
      tc->rcv_nxt += written;
      error = TCP_ERROR_PARTIALLY_ENQUEUED;
    }
  else
    {
      /* Packet made it through for ack processing */
      if (tc->rcv_wnd < tc->snd_mss)
	return TCP_ERROR_ZERO_RWND;

      return TCP_ERROR_FIFO_FULL;
    }

  /* Update SACK list if need be */
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      /* Remove SACK blocks that have been delivered */
      tcp_update_sack_list (tc, tc->rcv_nxt, tc->rcv_nxt);
    }

  return error;
}

static int
hicn_hs_rcv_stream (hicn_hs_worker_t * wrk, hicn_hs_ctx_t * ctx,
		    vlib_buffer_t * b)
{
  u32 error, n_bytes_to_drop, n_data_bytes;
  hicn_hs_buffer *b = hicn_hs_buffer (b);
  hicn_header_t *hicn_header;
  int rv;
  u8 *payload;
  hicn_format_t format = b->is_ip4 ? HF_INET4_TCP : INET6_TCP;
  
  /* XXX Assuming no signature for now. */
  hicn_header = vlib_buffer_get_current (b);
  rv = hicn_packet_get_payload (format, hicn_header, &payload, &n_data_bytes, 0);

  if (PREDICT_FALSE(rv < 0))
    {
      error = HICN_HS_ERROR_FORMAT;
      goto done;
    }
	
  ASSERT (n_data_bytes);

  /* Handle out-of-order data */
  if (PREDICT_FALSE (vnet_buffer (b)->tcp.seq_number != tc->rcv_nxt))
    {
      /* Old sequence numbers allowed through because they overlapped
       * the rx window */
      if (seq_lt (vnet_buffer (b)->tcp.seq_number, tc->rcv_nxt))
	{
	  /* Completely in the past (possible retransmit). Ack
	   * retransmissions since we may not have any data to send */
	  if (seq_leq (vnet_buffer (b)->tcp.seq_end, tc->rcv_nxt))
	    {
	      tcp_program_dupack (tc);
	      tc->errors.below_data_wnd++;
	      error = TCP_ERROR_SEGMENT_OLD;
	      goto done;
	    }

	  /* Chop off the bytes in the past and see if what is left
	   * can be enqueued in order */
	  n_bytes_to_drop = tc->rcv_nxt - vnet_buffer (b)->tcp.seq_number;
	  n_data_bytes -= n_bytes_to_drop;
	  vnet_buffer (b)->tcp.seq_number = tc->rcv_nxt;
	  if (tcp_buffer_discard_bytes (b, n_bytes_to_drop))
	    {
	      error = TCP_ERROR_SEGMENT_OLD;
	      goto done;
	    }
	  goto in_order;
	}

      /* RFC2581: Enqueue and send DUPACK for fast retransmit */
      error = tcp_session_enqueue_ooo (tc, b, n_data_bytes);
      tcp_program_dupack (tc);
      TCP_EVT (TCP_EVT_DUPACK_SENT, tc, vnet_buffer (b)->tcp);
      tc->errors.above_data_wnd += seq_gt (vnet_buffer (b)->tcp.seq_end,
					   tc->rcv_las + tc->rcv_wnd);
      goto done;
    }

in_order:

  /* In order data, enqueue. Fifo figures out by itself if any out-of-order
   * segments can be enqueued after fifo tail offset changes. */
  error = tcp_session_enqueue_data (tc, b, n_data_bytes);
  if (tcp_can_delack (tc))
    {
      if (!tcp_timer_is_active (tc, TCP_TIMER_DELACK))
	tcp_timer_set (&wrk->timer_wheel, tc, TCP_TIMER_DELACK,
		       tcp_cfg.delack_time);
      goto done;
    }

  tcp_program_ack (tc);

done:
  return error;
}

void hicn_hs_process_incoming_interest (hicn_hs_ctx_t *ctx, vlib_buffer_t* interest)
{
  hicn_hs_buffer_t *buffer;
  vlib_buffer_t *data_packet;
  hicn_hs_worker_t *wrk = hicn_hs_get_worker_by_context (ctx);
  session_main_t *smm = vnet_get_session_main ();
  hicn_hs_main_t *hm = hicn_hs_get_main ();
  vlib_main_t *vm = wrk->vm;
  obuffer_kv4_t kv;
  int rv;
  session_type_t st;

  transport_proto_t proto = hm->transport_protocol_id;
  st = session_type_from_proto_and_ip (proto, ctx->c_is_ip4);

  buffer = hicn_hs_buffer (interest);

  if (!ctx->accepted)
    {
      session_stream_accept(&ctx->connection, ctx->session_index, 0, 1);
      ctx->accepted = 1;
    }

  // Check for match in local output buffer
  if (buffer->is_ip4)
    {
      // Handle ip4 case
      return;
    }
  else
  {
    ip6_header_t *ip6 = vlib_buffer_get_current (interest);
    tcp_header_t *tcp = ip6_next_header (ip6);
    make_obuffer_kv(&kv, (ip46_address_t *)&ip6->dst_address, tcp->seq_number, ~0);
    rv = clib_bihash_search_inline_24_8(&ctx->output_buffer, &kv);
    if (!rv)
      {
	u32 bi = (u32) kv.value;
	// Retrieve corresponding data packet
	data_packet = vlib_get_buffer(vm, bi);
	hicn_hs_enqueue_to_output (vm, smm, data_packet, bi, 0, st);
      }
    else
      {
	/**
	 * What it is better to do here is allocate connection upon
	 * interest reception, once. This will allow to get the thread index,
	 * the one which received the interest. The idea is that all interests
	 * for same content should be processed by same thread. We cannot use
	 * RSS hashing, since the source address will change..
	 * Solutions:
	 *   - Dispatcher node BEFORE hicn network plugin, doing exactly the same of RSS hashing
	 *   - Configure hashing function in order to consider hICN-meaningful part of the packet
	 */
	session_t *s;
	// Signal this cache miss to parent app.
	// session_enqueue_dgram_connection(ctx->c_s_index, )
	ip46_address_copy((ip46_address_t *) (&ctx->current_production_name.ip46),
			  (ip46_address_t *) (&ip6->dst_address));

	s = session_get(ctx->c_s_index, 0);
	session_enqueue_notify(s);
      }
  }
}

void hicn_hs_process_incoming_data(hicn_hs_ctx_t *ctx, vlib_buffer_t* data)
{
  hicn_hs_buffer_t *buffer;
  vlib_buffer_t *data_packet;
  hicn_hs_worker_t *wrk = hicn_hs_get_worker_by_context (ctx);
  session_main_t *smm = vnet_get_session_main ();
  hicn_hs_main_t *hm = hicn_hs_get_main ();
  vlib_main_t *vm = wrk->vm;
  obuffer_kv4_t kv;
  int rv;
  session_type_t st;

  transport_proto_t proto = hm->transport_protocol_id;
  st = session_type_from_proto_and_ip (proto, ctx->c_is_ip4);

  buffer = hicn_hs_buffer (data);

  // Pass data packet to transport
  ctx->hs_proto->rcv_data(ctx);

  /**
   * If stream connection, tcp seq number in data packet stores
   * the byte number of the first byte of data in the TCP packet sent.
   */
  
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
  hc->c_fib_index = rmt->fib_index;
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
  hc->current_bytes_produced = 0;
  
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
  /* We need to call this because we call app_worker_init_connected in
   * quic_accept_stream, which assumes the connect segment manager exists */
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
  ctx->c_fib_index = lcl->fib_index;
  ctx->c_c_index = ctx_index;
  ctx->session_index = session_index;
  ctx->mss = hicn_hs_default_mtu (hmm, ctx->c_is_ip4);
  ctx->current_content_size = 0;
  ctx->current_bytes_produced = 0;

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
  hicn_name_t *name = &ctx->current_production_name;
  vlib_buffer_push_hicn(ctx, b, HF_INET6_TCP, name, ctx->current_bytes_produced, 0);
  hicn_hs_buffer(b)->is_interest = 0;

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

    // Register new protocol
  hm->transport_protocol_id = transport_register_new_protocol(&hicn_hs_proto,
			       				     FIB_PROTOCOL_IP6,
							     hm->hicn_hs_on6_idx);
  transport_register_protocol (hm->transport_protocol_id, &hicn_hs_proto,
			       FIB_PROTOCOL_IP4, hm->hicn_hs_on4_idx);
  
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
