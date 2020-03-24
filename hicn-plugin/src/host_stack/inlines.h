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

#ifndef __included_hicn_hs_inlines_h__
#define __included_hicn_hs_inlines_h__

#include "host_stack.h"
#include "utils.h"

always_inline void
make_obuffer_kv (obuffer_kv4_t * kv, ip46_address_t * prefix, u32 suffix, u32 bi)
{
  kv->key[0] = prefix->as_u64[0];
  kv->key[1] = prefix->as_u64[1];
  kv->key[2] = suffix;
  kv->value = bi;
}

always_inline void
hicn_hs_app_notify_rx (hicn_hs_ctx_t *ctx)
{
  session_t *s;	
  s = session_get(ctx->c_s_index, 0);
  session_enqueue_notify(s);
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

  u8 will_expand;
  pool_get_aligned_will_expand (wrk->hicn_ctxs, will_expand,
			       CLIB_CACHE_LINE_BYTES);
  /* If we have peekers, let them finish */
  if (PREDICT_FALSE (will_expand && vlib_num_workers ()))
    {
      clib_rwlock_writer_lock (&wrk->peekers_rw_locks);
      pool_get_aligned (wrk->hicn_ctxs, ctx, CLIB_CACHE_LINE_BYTES);
      clib_rwlock_writer_unlock (&wrk->peekers_rw_locks);
    }
  else
    {
      pool_get_aligned (wrk->hicn_ctxs, ctx, CLIB_CACHE_LINE_BYTES);
    }

  clib_memset (ctx, 0, sizeof (hicn_hs_ctx_t));
  ctx->c_thread_index = thread_index;
  ctx->timer_handle = HICN_HS_TIMER_HANDLE_INVALID;
  HICN_HS_DBG (3, "Allocated hicn_hs_ctx_t %u on thread %u",
	       ctx - wrk->hicn_ctxs, thread_index);
  
  return ctx - wrk->hicn_ctxs;
}

always_inline void*
vlib_buffer_push_hicn (hicn_hs_ctx_t *ctx, vlib_buffer_t *b,
		       hicn_name_t* name, u32 seq_number, u8 is_interest)
{
  hicn_header_t *hicn_header;
  hicn_hs_buffer_t *buffer = hicn_hs_buffer (b);
  int rv;
  u16 current_length = b->current_length;
  u16 payload_len = current_length;
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID))
    payload_len += b->total_length_not_including_first_buffer;

  hicn_header = vlib_buffer_push_uninit (b, HICN_V6_TCP_HDRLEN);
  buffer->type.l4 = IPPROTO_NONE;
  buffer->type.l3 = IPPROTO_NONE;
  buffer->type.l2 = IPPROTO_TCP;
  buffer->type.l1 = IPPROTO_IPV6;

  buffer->flush = 0;

  name->suffix = seq_number;

  rv = hicn_ops_vft[buffer->type.l1]->init_packet_header(buffer->type, &hicn_header->protocol);
  rv += hicn_ops_vft[buffer->type.l1]->set_payload_length(buffer->type, &hicn_header->protocol, payload_len);

  if (is_interest)
    {
      rv += hicn_ops_vft[buffer->type.l1]->set_interest_name(buffer->type, &hicn_header->protocol, name);
      rv += hicn_ops_vft[buffer->type.l1]->mark_packet_as_interest(buffer->type, &hicn_header->protocol);
    }
  else
    {
      rv += hicn_ops_vft[buffer->type.l1]->set_data_name(buffer->type, &hicn_header->protocol, name);
      rv += hicn_ops_vft[buffer->type.l1]->mark_packet_as_data(buffer->type, &hicn_header->protocol);
    }

  ASSERT (!rv);
  
  hicn_header->v6.tcp.csum = hicn_hs_compute_checksum (ctx, b);

  vnet_buffer (b)->l4_hdr_offset = (u8 *) hicn_header - b->data;
  b->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;

  ctx->bytes_produced += current_length;

  if (PREDICT_FALSE (!is_interest && ctx->bytes_produced == ctx->current_content_size))
    {
      // Last packet
//       rv += hicn_packet_set_rst (hicn_header);
    }

  return hicn_header;
}

always_inline u32
hicn_hs_make_interest (hicn_hs_ctx_t * ctx, vlib_buffer_t *b,
		       hicn_name_t *name, u32 seq_number)
{
  vlib_buffer_push_hicn(ctx, b, name, seq_number, 1);
  hicn_hs_buffer (b)->flush = 1;
  b->ref_count = 1;
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
  int ret = 0;
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
      ret += hicn_hs_make_interest (ctx, b[0], name, offset++);
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
      ret += hicn_hs_make_interest (ctx, b[1], name, offset++);
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
      ret += hicn_hs_make_interest (ctx, b[2], name, offset++);
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
      ret += hicn_hs_make_interest (ctx, b[3], name, offset++);
      hicn_hs_enqueue_to_output (vm, smm, b[3], bi[3], ctx->c_is_ip4, st);

      b += 4;
      bi += 4;
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
      ret += hicn_hs_make_interest (ctx, b[0], name, offset++);
      hicn_hs_enqueue_to_output (vm, smm, b[0], bi[0], ctx->c_is_ip4, st);

      b += 1;
      bi += 1;
      count -= 1;
    }

  return ret;
}

always_inline u32
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
always_inline int
hicn_hs_enqueue_data (hicn_hs_ctx_t * ctx, vlib_buffer_t * b,
		      u16 data_len)
{
  int written, error = HICN_HS_ERROR_ENQUEUED;
  hicn_hs_buffer_t *buffer = hicn_hs_buffer (b);

  ASSERT (seq_geq (buffer->seq_number, ctx->rcv_nxt));
  ASSERT (data_len);

  written = session_enqueue_stream_connection (&ctx->connection, b, 0,
					       1 /* queue event */ , 1);
  ctx->bytes_in += written;

  /* Update rcv_nxt */
  if (PREDICT_TRUE (written == data_len))
    {
      ctx->rcv_nxt += written;
    }
  /* If more data written than expected, account for out-of-order bytes. */
  else if (written > data_len)
    {
      ctx->rcv_nxt += written;
    }
  else if (written > 0)
    {
      /* We've written something but FIFO is probably full now */
      ctx->rcv_nxt += written;
      error = HICN_HS_ERROR_PARTIALLY_ENQUEUED;
    }
  else
    {
      error = HICN_HS_ERROR_FIFO_FULL;
    }

  if (PREDICT_FALSE (ctx->rcv_nxt >= ctx->download_content_size))
    hicn_hs_app_notify_rx (ctx);

  return error;
}

always_inline int
hicn_hs_enqueue_ooo (hicn_hs_ctx_t * ctx, vlib_buffer_t * b,
		     u16 data_len)
{
  int rv, CLIB_UNUSED(offset);
  hicn_hs_buffer_t *buffer = hicn_hs_buffer (b);

  ASSERT (seq_gt (buffer->seq_number, ctx->rcv_nxt));
  ASSERT (data_len);

  /* Enqueue out-of-order data with relative offset */
  rv = session_enqueue_stream_connection (&ctx->connection, b,
					  buffer->seq_number - ctx->rcv_nxt,
					  0 /* queue event */ , 0);

  /* Nothing written */
  if (rv)
    {
      return HICN_HS_ERROR_FIFO_FULL;
    }

  ctx->bytes_in += data_len;

  return HICN_HS_ERROR_ENQUEUED_OOO;
}

always_inline int
hicn_hs_rcv_stream (hicn_hs_worker_t * wrk, hicn_hs_ctx_t * ctx,
		    vlib_buffer_t * b)
{
  u32 error;
  size_t n_data_bytes, skip;
  hicn_hs_buffer_t *buffer = hicn_hs_buffer (b);
  hicn_header_t *hicn_header;
  int rv;
  u8 rst;
  hicn_name_t data_name;
  
  /* XXX Assuming no signature for now. */
  hicn_header = vlib_buffer_get_current (b);

  rv = hicn_ops_vft[buffer->type.l1]->get_payload_length (buffer->type, &hicn_header->protocol, (size_t *)(&n_data_bytes));
  rv += hicn_ops_vft[buffer->type.l1]->get_header_length (buffer->type, &hicn_header->protocol, (size_t *)(&skip));
  rv += hicn_ops_vft[buffer->type.l1]->get_data_name (buffer->type, &hicn_header->protocol, &data_name);
  rv += hicn_name_compare (&ctx->consumer_name, &data_name, 0);

  vlib_buffer_advance (b, skip);

  if (PREDICT_FALSE(rv < 0))
    {
      error = HICN_HS_ERROR_FORMAT;
      return error;
    }
  
//   hicn_packet_test_rst (hicn_header, (bool *)(&rst));
  if (PREDICT_FALSE (rst))
    ctx->download_content_size = (buffer->seq_number - 1) * ctx->mss + n_data_bytes;
	
  ASSERT (n_data_bytes);

  /* Adjust seq number in order to represent byte number */
  buffer->seq_number *= ctx->mss;

  /* Handle out-of-order data */
  if (PREDICT_FALSE (buffer->seq_number != ctx->rcv_nxt))
    {
      rv = hicn_hs_enqueue_ooo (ctx, b, n_data_bytes);
    }
  else
    /* In order data, enqueue. Fifo figures out by itself if any out-of-order
     * segments can be enqueued after fifo tail offset changes. */
    rv = hicn_hs_enqueue_data (ctx, b, n_data_bytes);
  
  vlib_buffer_push_uninit(b, skip);

  return rv;
}

always_inline
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
  u32 suffix;
  u32 interest_index;

  transport_proto_t proto = hm->transport_protocol_id;
  st = session_type_from_proto_and_ip (proto, ctx->c_is_ip4);

  buffer = hicn_hs_buffer (interest);

  if (PREDICT_FALSE(!ctx->accepted))
    {
      session_stream_accept(&ctx->connection, ctx->session_index, 0, 1);
      ctx->accepted = 1;
    }

  interest_index = vlib_get_buffer_index (wrk->vm, interest);

  // Check for match in local output buffer
  if (PREDICT_FALSE(buffer->is_ip4))
    {
      // Handle ip4 case
      return;
    }
  else
  {
    hicn_hs_buffer_t *b = hicn_hs_buffer (interest);
    ip6_header_t *ip6 = vlib_buffer_get_current (interest);
    hicn_protocol_t *proto = (hicn_protocol_t *)(ip6);
    hicn_ops_vft[b->type.l1]->get_interest_name_suffix(b->type, proto, &suffix);
    make_obuffer_kv(&kv, (ip46_address_t *)&ip6->dst_address, suffix, ~0);
    rv = clib_bihash_search_inline_24_8(&ctx->output_buffer, &kv);
    if (PREDICT_TRUE(!rv))
      {
	u32 bi = (u32) kv.value;

        // Retrieve corresponding data packet
	data_packet = vlib_get_buffer(vm, bi);

	hicn_header_t *interest = (hicn_header_t *)(proto);
	hicn_header_t *data = vlib_buffer_get_current (data_packet);
	
	ASSERT(!hicn_hs_buffer (data_packet)->is_interest);
	hicn_hs_buffer (data_packet)->ctx_index = ctx->c_c_index;
	hicn_hs_buffer (data_packet)->flush = 1;

	data->v6.ip.daddr = interest->v6.ip.saddr;
	
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

	if (ip46_address_is_equal ((ip46_address_t *) (&ctx->current_production_name.prefix),
				   (ip46_address_t *) (&ip6->dst_address)))
	  {
	    /**
	     * Content currently in production.
	     **/
	    if (PREDICT_FALSE(suffix >= ctx->number_of_segments))
	      goto cleanup;
	    
	    kv.value = interest_index;
	    clib_bihash_add_del_24_8 (&ctx->output_buffer, &kv, 1);
	    return;
	  }
	
	// Signal this cache miss to parent app.
	// session_enqueue_dgram_connection(ctx->c_s_index, )
	ip46_address_copy((ip46_address_t *) (&ctx->current_production_name.prefix),
			  (ip46_address_t *) (&ip6->dst_address));
	ctx->current_production_name.suffix = 0;
	kv.value = interest_index;
	clib_bihash_add_del_24_8 (&ctx->output_buffer, &kv, 1);
	hicn_hs_app_notify_rx (ctx);
	return;
      }
  }

cleanup:
  vlib_buffer_free_one (wrk->vm, interest_index);
}

always_inline
void hicn_hs_process_incoming_data(hicn_hs_ctx_t *ctx, vlib_buffer_t* data)
{
  hicn_hs_worker_t *wrk = hicn_hs_get_worker_by_context (ctx);
  hicn_hs_rcv_stream (wrk, ctx, data);

  /**
   * If stream connection, tcp seq number in data packet stores
   * the byte number of the first byte of data in the TCP packet sent.
   */
  
}

#endif  /* __included_hicn_hs_inlines_h__ */