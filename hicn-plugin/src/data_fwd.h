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

#ifndef __HICN_DATA_FWD_H__
#define __HICN_DATA_FWD_H__

#include <vlib/buffer.h>

#include "pcs.h"

/*
 * Node context data; we think this is per-thread/instance
 */
typedef struct hicn_data_fwd_runtime_s
{
  vlib_combined_counter_main_t repm_counters;

  /* per-cpu vector of cloned packets */
  u32 **clones;
} hicn_data_fwd_runtime_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[64];
} hicn_data_fwd_trace_t;

typedef enum
{
  HICN_DATA_FWD_NEXT_V4_LOOKUP,
  HICN_DATA_FWD_NEXT_V6_LOOKUP,
  HICN_DATA_FWD_NEXT_PUSH,
  HICN_DATA_FWD_NEXT_ERROR_DROP,
  HICN_DATA_FWD_N_NEXT,
} hicn_data_fwd_next_t;

/**
 *@brief Create a maximum of 256 clones of buffer and store them
 *   in the supplied array. Unlike the original function in the vlib
 *   library, we don't prevent cloning if n_buffer==1 and if
 *   s->current_length <= head_end_offset + CLIB_CACHE_LINE_BYTES * 2.
 *
 * @param vm - (vlib_main_t *) vlib main data structure pointer
 * @param src_buffer - (u32) source buffer index
 * @param buffers - (u32 * ) buffer index array
 * @param n_buffers - (u16) number of buffer clones requested (<=256)
 * @param head_end_offset - (u16) offset relative to current position
 *          where packet head ends
 * @return - (u16) number of buffers actually cloned, may be
 *   less than the number requested or zero
 */
always_inline u16
vlib_buffer_clone_256_2 (vlib_main_t * vm, u32 src_buffer, u32 * buffers,
			 u16 n_buffers, u16 head_end_offset)
{
  u16 i;
  vlib_buffer_t *s = vlib_get_buffer (vm, src_buffer);

  ASSERT (n_buffers);
  ASSERT (n_buffers <= 256);

  if (s->current_length <= head_end_offset + CLIB_CACHE_LINE_BYTES * 2)
    {
      for (i = 0; i < n_buffers; i++)
	{
	  vlib_buffer_t *d;
	  d = vlib_buffer_copy (vm, s);
	  if (d == 0)
	    return i;
	  buffers[i] = vlib_get_buffer_index (vm, d);
	}
      return n_buffers;
    }
  n_buffers = vlib_buffer_alloc_from_free_list (vm, buffers, n_buffers,
						vlib_buffer_get_free_list_index
						(s));

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *d = vlib_get_buffer (vm, buffers[i]);
      d->current_data = s->current_data;
      d->current_length = head_end_offset;
      d->trace_index = s->trace_index;
      vlib_buffer_set_free_list_index (d,
				       vlib_buffer_get_free_list_index (s));

      d->total_length_not_including_first_buffer = s->current_length -
	head_end_offset;
      if (PREDICT_FALSE (s->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  d->total_length_not_including_first_buffer +=
	    s->total_length_not_including_first_buffer;
	}
      d->flags = s->flags | VLIB_BUFFER_NEXT_PRESENT;
      d->flags &= ~VLIB_BUFFER_EXT_HDR_VALID;
      d->trace_index = s->trace_index;
      clib_memcpy (d->opaque, s->opaque, sizeof (s->opaque));
      clib_memcpy (d->opaque2, s->opaque2, sizeof (s->opaque2));
      clib_memcpy (vlib_buffer_get_current (d), vlib_buffer_get_current (s),
		   head_end_offset);
      d->next_buffer = src_buffer;
    }
  vlib_buffer_advance (s, head_end_offset);
  s->n_add_refs = n_buffers - 1;
  while (s->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      s = vlib_get_buffer (vm, s->next_buffer);
      s->n_add_refs = n_buffers - 1;
    }

  return n_buffers;
}

/**
 * @brief Create multiple clones of buffer and store them
 *  in the supplied array. Unlike the function in the vlib library,
 *   we allow src_buffer to have n_add_refs != 0.
 *
 * @param vm - (vlib_main_t *) vlib main data structure pointer
 * @param src_buffer - (u32) source buffer index
 * @param buffers - (u32 * ) buffer index array
 * @param n_buffers - (u16) number of buffer clones requested (<=256)
 * @param head_end_offset - (u16) offset relative to current position
 *   where packet head ends
 * @return - (u16) number of buffers actually cloned, may be
 *   less than the number requested or zero
 */
always_inline u16
vlib_buffer_clone2 (vlib_main_t * vm, u32 src_buffer, u32 * buffers,
		    u16 n_buffers, u16 head_end_offset)
{
  vlib_buffer_t *s = vlib_get_buffer (vm, src_buffer);

  /*
   * total_length_not_including_first_buffer is not initialized to 0
   * when a buffer is used.
   */
  if (PREDICT_TRUE (s->next_buffer == 0))
    s->total_length_not_including_first_buffer = 0;

  u16 n_cloned = 0;
  u8 n_clone_src = 255 - s->n_add_refs;

  /*
   * We need to copy src for all the clones that cannot be chained in
   * the src_buffer
   */
  /* MAX(n_add_refs) = 256 */
  if (n_buffers > n_clone_src)
    {
      vlib_buffer_t *copy;
      /* Ok to call the original vlib_buffer_copy. */
      copy = vlib_buffer_copy (vm, s);
      n_cloned += vlib_buffer_clone (vm,
				     vlib_get_buffer_index (vm, copy),
				     buffers,
				     n_buffers - n_clone_src,
				     head_end_offset);
      n_buffers -= n_cloned;
    }
  /*
   * vlib_buffer_clone_256 check if n_add_refs is 0. We force it to be
   * 0 before calling the function and we retore it to the right value
   * after the function has been called
   */
  u8 tmp_n_add_refs = s->n_add_refs;

  s->n_add_refs = 0;
  /*
   * The regular vlib_buffer_clone_256 does copy if we need to clone
   * only one packet. While this is not a problem per se, it adds
   * complexity to the code, especially because we need to add 1 to
   * n_add_refs when the packet is cloned.
   */
  n_cloned += vlib_buffer_clone_256_2 (vm,
				       src_buffer,
				       (buffers + n_cloned),
				       n_buffers, head_end_offset);

  s->n_add_refs += tmp_n_add_refs;

  return n_cloned;
}

#endif /* //__HICN_DATA_FWD_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
