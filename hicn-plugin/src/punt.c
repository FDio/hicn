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

#include <stdarg.h>
#include <stddef.h>		// offsetof()
#include <inttypes.h>
#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <vnet/ip/format.h>
#include <vnet/classify/in_out_acl.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ethernet/packet.h>
#include <vlib/global_funcs.h>
#include <hicn/hicn.h>

#include "hicn.h"
#include "infra.h"
#include "parser.h"
#include "mgmt.h"
#include "punt.h"
#include "error.h"
#include "route.h"

/* Those are not static as they are used for pgen in hicn_cli.c */
ip_version_t ipv4 = {
  .tbl = (u32 *) hicn_punt_glb.ip4_vnet_tbl_idx,
  .addr_len_bits = IPV4_ADDR_LEN_BITS,
  .protocol_field = &ipv4_protocol,
  .version_field = &ipv4_version,
  .ip_version = 0x40,
};

ip_version_t ipv6 = {
  .tbl = (u32 *) hicn_punt_glb.ip6_vnet_tbl_idx,
  .addr_len_bits = IPV6_ADDR_LEN_BITS,
  .protocol_field = &ipv6_protocol,
  .version_field = &ipv6_version,
  .ip_version = 0x60,
};

ip_version_t ipv44 = {
  .tbl = (u32 *) hicn_punt_glb.udp44_vnet_tbl_idx,
  .addr_len_bits = IPV4_ADDR_LEN_BITS,
  .protocol_field = &udp4_protocol,
  .udp_sport = &udp4_sport,
  .udp_dport = &udp4_dport,
  .ip_version = 0x40,
};

ip_version_t ipv64 = {
  .tbl = (u32 *) hicn_punt_glb.udp64_vnet_tbl_idx,
  .addr_len_bits = IPV4_ADDR_LEN_BITS,
  .protocol_field = &udp6_protocol,
  .udp_sport = &udp6_sport,
  .udp_dport = &udp6_dport,
  .ip_version = 0x60,
};

ip_version_t ipv46 = {
  .tbl = (u32 *) hicn_punt_glb.udp46_vnet_tbl_idx,
  .addr_len_bits = IPV6_ADDR_LEN_BITS,
  .protocol_field = &udp4_protocol,
  .udp_sport = &udp4_sport,
  .udp_dport = &udp4_dport,
  .ip_version = 0x40,
};

ip_version_t ipv66 = {
  .tbl = (u32 *) hicn_punt_glb.udp66_vnet_tbl_idx,
  .addr_len_bits = IPV6_ADDR_LEN_BITS,
  .protocol_field = &udp6_protocol,
  .udp_sport = &udp6_sport,
  .udp_dport = &udp6_dport,
  .ip_version = 0x60,
};

#define _(NAME, BASE, LAYER, FIELD, PUNT_ID)          \
    field_t NAME = {                     \
        .offset = BASE + offsetof(LAYER, FIELD),       \
        .len = STRUCT_SIZE_OF(LAYER, FIELD),       \
        .punt_id = PUNT_ID,                     \
    };
foreach_field
#undef _
/*
 * In the latest version, we let faces direct the traffic towards Interest
 * processing, or MAP-Me nodes. Punting should only make sure that the ICMP
 * packets are also sent to the face node. We added the following defines to
 * determine the next node to send punted packets. Ideally we might remove
 * protocol number check from punting rule.
 */
#define NEXT_MAPME_CTRL4 hicn_punt_glb.next_hit_interest_ipv4
#define NEXT_MAPME_ACK4 hicn_punt_glb.next_hit_data_ipv4
#define NEXT_MAPME_CTRL6 hicn_punt_glb.next_hit_interest_ipv6
#define NEXT_MAPME_ACK6 hicn_punt_glb.next_hit_data_ipv6

/* Maximum number of vector allowed in match. Value hardcoded in vnet_classify_hash_packet_inline in vnet_classify.h */
#define MAX_MATCH_SIZE 5
/**
 * HICN global Punt Info
 *
 *
 *
 */
hicn_punt_glb_t hicn_punt_glb;

/**
 * We use the function build_bit_array to populate an initially empty buffer
 * with masks/values for the parts of the packet to match. The function also
 * returns the correct skip and match values to pass to vnet_classify_*, which
 * are the number of vectors to skip/match during classification (they should be
 * multiples of vector size = CLASSIFIER_VECTOR_SIZE).
 *
 * offsets:
 * 0         14     offsetof(IP_HDR, SRC)
 * |          |    /
 * +----------+----+-------+-------+----+-...
 * |   ETH    | IP .  src  .  dst  .    |
 * +----------+----+-------+-------+----+-...
 * |            |                   |
 * |<- skip=1 ->|<--- match=2/3 --->|
 *
 *
 */

/**
 * The following section defines a couple of protocol fields that we will use
 * for creating the buffer. We retrieve the offset and length on those fields
 * based on the (portable) header struct aliases defined in libhicn.
 *
 * In the foreach_field macro, the punt_id field is used as convenience as we
 * will have to create different classifier tables based on whether we punt
 * interests (on dst) or data (on src). It is undefined (NA) otherwise.
 */

#define NA 0


/**
 * @brief Create a bitmask from mask length.
 * @param mask [in] mask length (in bits)
 * @param buffer [out] output buffer
 * @param len [out] output buffer length
 */
static void
build_ip_address_mask (u8 mask, u8 * buffer, u32 len)
{
  u32 hi_bytes = mask / 8;
  u32 hi_bits = mask % 8;
  u8 byte_mask = 0xff;

  /*
   * memset buffer with 0xff in case of IPV6 16 bytes will be used for
   * match
   */
  memset (buffer, 0, len);
  //might not be needed if buffer is already 0 'ed XXX
  memset (buffer, 0xff, hi_bytes);
  if (hi_bits != 0)
    {
      for (int i = 0; i < (8 - hi_bits); i++)
	byte_mask = byte_mask << 1;
      buffer[hi_bytes] = byte_mask;
    }
}

#define CEIL_DIV(x, y) (1 + ((x - 1) / y))

/**
 * @brief Create a bit array from field/value list
 * @param buffer [out] output buffer
 * @param len [out] output buffer length
 * @param skip [out] number of CLASSIFIER_VECTOR to skip
 * @param match [out] number of CLASSIFIER_VECTOR to match
 * @param ... [in] list of [field_t *, value] * used to populate buffer
 */
static int
build_bit_array (u8 * buffer, u32 len, u32 base_offset, u32 * skip,
		 u32 * match, va_list vl)
{
  u8 min = len, max = 0;
  field_t *field;
  u8 *value;
  int pos;
  int count = 0;

  /* Clear buffer */
  memset (buffer, 0, len);

  for (;;)
    {
      count++;
      field = va_arg (vl, field_t *);
      if (!field)
	break;

      /* Check that the field belongs to the reserved buffer */
      if (field->offset + field->len > len)
	goto ERR_PUNT;

      /*
       * Copy the value of the field inside the buffer at the
       * correct offset
       */
      pos = base_offset + field->offset;
      value = va_arg (vl, u8 *);
      memcpy (buffer + pos, value, field->len);
      if (min > pos)
	min = pos;
      if (max < pos + field->len)
	max = pos + field->len;
    }

  /* We can skip multiples of the vector match */
  *skip = min / CLASSIFIER_VECTOR_SIZE;
  *match = CEIL_DIV (max, CLASSIFIER_VECTOR_SIZE) - *skip;

  if (*match > MAX_MATCH_SIZE)
    *match = MAX_MATCH_SIZE;

  return HICN_ERROR_NONE;

ERR_PUNT:
  *skip = 0;
  *match = 0;
  return HICN_ERROR_PUNT_INVAL;
}

void
update_table4_index (u32 intfc, u32 table_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;

  if (hicn_punt_glb.head_ip4[intfc] == ~0)
    hicn_punt_glb.head_ip4[intfc] = table_index;

  /* Update the table in tail to poin to this */
  if (hicn_punt_glb.tail_ip4[intfc] != ~0)
    {
      vnet_classify_table_t *t =
	pool_elt_at_index (cm->tables, hicn_punt_glb.tail_ip4[intfc]);
      t->next_table_index = table_index;
    }
  hicn_punt_glb.tail_ip4[intfc] = table_index;
}

void
update_table6_index (u32 intfc, u32 table_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;

  if (hicn_punt_glb.head_ip6[intfc] == ~0)
    hicn_punt_glb.head_ip6[intfc] = table_index;

  /* Update the table in tail to poin to this */
  if (hicn_punt_glb.tail_ip6[intfc] != ~0)
    {
      vnet_classify_table_t *t =
	pool_elt_at_index (cm->tables, hicn_punt_glb.tail_ip6[intfc]);
      t->next_table_index = table_index;
    }
  hicn_punt_glb.tail_ip6[intfc] = table_index;
}

/**
 * @brief Add or remove a vnet table matching the list of fields/values passed
 * as parameters.
 *
 * @param punt_id Storage identifier (HICN_PUNT_SRC | HICN_PUNT_DST)
 * @param mask Subnet mask to match in the table
 * @param next_tbl_index next table to match in case of miss
 * @param intfc Interface identifier
 * @param is_add 1 if the table must be created, 0 if removed
 * @param ... list of (field_t, value) to be matched
 *
 * @result Returns:
 *    HICN_ERROR_TBL_EXIST if is_add == 1 and a table for the same mask
 *      already exists,
 *    HICN_ERROR_TBL_NOT_FOUND if is_add == 0 and there is no table for the
 *      given mask,
 *    HICN_ERROR_NONE if no * error occurred.
 */
int
_hicn_punt_add_del_vnettbl (ip_version_t * ip, u8 punt_id, u8 mask,
			    u32 next_tbl_index, u32 intfc, int base_offset,
			    int is_add, u8 use_current_data, ...)
{
  u8 buffer[PUNT_BUFFER_SIZE];	/* must be dimensioned
				 * large enough */
  int rt;
  va_list vl;
  u32 *table_index;
  u32 new_table_index;
  u32 skip, match;


  /* Build the buffer right from the start to determine the skip size */
  va_start (vl, use_current_data);
  build_bit_array (buffer, sizeof (buffer), base_offset, &skip, &match, vl);
  va_end (vl);

  ASSERT (skip < 4);
  //Hardcoded limit in following array

  table_index = TABLE_ELT_P (ip, intfc, skip, punt_id, mask);

  if (is_add && *table_index != HICNP_PUNY_INVALID_TBL)
    return HICN_ERROR_PUNT_TBL_EXIST;
  if (!is_add && *table_index == HICNP_PUNY_INVALID_TBL)
    return HICN_ERROR_PUNT_TBL_NOT_FOUND;

  new_table_index = ~0;
  rt = vnet_classify_add_del_table (&vnet_classify_main,
				    buffer + skip * CLASSIFIER_VECTOR_SIZE,
				    HICN_CLASSIFY_NBUCKETS,
				    HICN_CLASSIFY_TABLE_MEMORY_SIZE, skip,
				    match, HICN_CLASSIFY_NO_NEXT_TABLE,
				    HICN_CLASSIFY_MISS_NEXT_INDEX,
				    &new_table_index,
				    use_current_data,
				    HICN_CLASSIFY_CURRENT_DATA_OFFSET, is_add,
				    HICN_CLASSIFY_DON_T_DEL_CHAIN);

  if (rt != 0)
    return HICN_ERROR_PUNT_INVAL;

  *table_index = new_table_index;
  if (ip->ip_version == 0x40)
    update_table4_index (intfc, new_table_index);
  else
    update_table6_index (intfc, new_table_index);
  return HICN_ERROR_NONE;
}

/**
 * @brief Add or remove a vnet table matching the ip_version and field (src/dst)
 */
int
hicn_punt_add_del_vnettbl (ip_version_t * ip, field_t * field, u8 mask,
			   u32 next_tbl_index, u32 intfc, u8 base_offset,
			   u8 use_current_data, int is_add)
{
  u8 ip_mask[IPV6_ADDR_LEN];
  build_ip_address_mask (mask, ip_mask, sizeof (ip_mask));

  return _hicn_punt_add_del_vnettbl (ip, field->punt_id, mask, next_tbl_index,
				     intfc, base_offset, is_add,
				     use_current_data, field, ip_mask, NULL);
}


/**
 * @brief Add or remove a vnet table for udp tunnels matching the ip_version and field (src/dst)
 *
 */
int
hicn_punt_add_del_vnettbl_udp (ip_version_t * outer, ip_version_t * inner,
			       field_t * field, u8 mask, u32 next_tbl_index,
			       u32 intfc, u8 base_offset, int is_add)
{
  u8 udp_mask[inner->addr_len_bits];
  build_ip_address_mask (mask, udp_mask, sizeof (udp_mask));
  u16 port_value = 0xffff;
  u8 protocol_value = 0xff;
  
  return _hicn_punt_add_del_vnettbl (outer, field->punt_id, mask,
				     next_tbl_index, intfc, base_offset,
				     is_add,
				     HICN_CLASSIFY_NO_CURRENT_DATA_FLAG,
				     outer->protocol_field, &protocol_value,
				     outer->udp_sport, &port_value,
				     outer->udp_dport, &port_value, field,
				     udp_mask, NULL);
}

#define hicn_punt_add_vnettbl_udp(outer, inner, field, mask, next_tbl_index, intfc, base_offset) \
  (hicn_punt_add_del_vnettbl_udp(outer, inner, field, mask, next_tbl_index, intfc, base_offset, OP_ADD))

#define hicn_punt_del_vnettbl_udp(outer, inner, field, mask, next_tbl_index, intfc, base_offset) \
  (hicn_punt_add_del_vnettbl_udp(outer, inner, field, mask, next_tbl_index, intfc, base_offset, OP_DEL))

/**
 * @brief Add or remove a vnet session matching the list of fields/values passed
 * as parameters.
 *
 * @param punt_id Storage identifier (HICN_PUNT_SRC | HICN_PUNT_DST)
 * @param v4_address IPv4 address to match in the session // XXX v4/v6
 * @param mask Subnet mask to match in the session
 * @param next_hit_index vlib arch id pointing to the next node
 * @param intfc Interface identifier
 * @param is_add 1 if the session must be create, 0 if removed
 * @param ... list of (field_t, value) to be matched
 *
 * @result Returns:
 *   HICN_ERROR_TBL_NOT_FOUND there is no table for the given mask,
 *   HICN_ERROR_PUNT_SSN_NOT_FOUND if is_add == 0 and there is no session for
 *     the given address,
 *   HICN_ERROR_NONE if no error * occurred.
 */
int
_hicn_punt_add_del_vnetssn (ip_version_t * ip, u8 punt_id, u8 mask,
			    u32 next_hit_index, u32 intfc, int base_offset,
			    int is_add, ...)
{
  u8 buffer[PUNT_BUFFER_SIZE];	/* must be dimensioned
				 * large enough */
  int rt;
  va_list vl;
  u32 table_index;
  u32 skip, match;

  /* Build the buffer right from the start to determine the skip size */
  va_start (vl, is_add);
  build_bit_array (buffer, sizeof (buffer), base_offset, &skip, &match, vl);
  va_end (vl);

  ASSERT (skip < 4);
  //Hardcoded limit in following array

  table_index = TABLE_ELT (ip, intfc, skip, punt_id, mask);

  if (table_index == HICNP_PUNY_INVALID_TBL)
    return HICN_ERROR_PUNT_TBL_NOT_FOUND;

  rt = vnet_classify_add_del_session (&vnet_classify_main, table_index, buffer,	//+skip * CLASSIFIER_VECTOR_SIZE,
				      next_hit_index,
				      HICN_CLASSIFY_OPAQUE_INDEX,
				      HICN_CLASSIFY_ADVANCE,
				      HICN_CLASSIFY_ACTION,
				      HICN_CLASSIFY_METADATA, is_add);

  if (rt == VNET_API_ERROR_NO_SUCH_ENTRY)
    rt = HICN_ERROR_PUNT_SSN_NOT_FOUND;

  return rt;
}

/**
 * @brief Add or remove a vnet session matching the ip6 src address
 *
 * See hicn_punt_add_del_vnetssn for details about parameters.
 */
int
hicn_punt_add_del_vnetssn (ip_version_t * ip, field_t * field,
			   ip46_address_t * v46_address, u8 mask,
			   u32 next_hit_index, u32 intfc, u8 base_offset,
			   int is_add)
{
  return _hicn_punt_add_del_vnetssn (ip, field->punt_id, mask, next_hit_index,
				     intfc, base_offset, is_add, field,
				     ip46_address_is_ip4 (v46_address) ?
				     v46_address->ip4.as_u8 : v46_address->
				     ip6.as_u8, NULL);
}



/**
 * @brief Add or remove a vnet session for udp tunnels matching the ip6 src address
 *
 * See hicn_punt_add_del_vnetssn for details about parameters.
 */
int
hicn_punt_add_del_vnetssn_udp (ip_version_t * outer, ip_version_t * inner,
			       field_t * field, ip46_address_t * v46_address,
			       u8 mask, u32 next_hit_index, u32 intfc,
			       u8 base_offset, u8 protocol, u16 sport,
			       u16 dport, int is_add)
{    
  return _hicn_punt_add_del_vnetssn (outer, field->punt_id, mask,
				     next_hit_index, intfc, base_offset,
				     is_add, outer->protocol_field, &protocol,
				     outer->udp_sport, &sport,
				     outer->udp_dport, &dport, field,
				     v46_address->as_u8, NULL);
}

#define hicn_punt_add_vnetssn_udp(outer, inner, field, addr, mask, index, intfc, offset, protocol, sport, dport) \
  (hicn_punt_add_del_vnetssn_udp(outer, inner, field, addr, mask, index, intfc, offset, protocol, sport, dport, OP_ADD))

#define hicn_punt_del_vnetssn_udp(outer, inner, field, addr, mask, index, intfc, offset, protocol, sport, dport) \
  (hicn_punt_add_del_vnetssn_udp(outer, inner, field, addr, mask, index, intfc, offset, protocol, sport, dport, OP_DEL))

/*
 * Enable the table on a given interface considering the table type
 */
void
hicn_punt_enable_disable_vnet_ip4_table_on_intf (vlib_main_t * vm,
						 u32 sw_if_index,
						 int is_enable)
{
  if (hicn_punt_glb.head_ip4[sw_if_index] != HICNP_PUNY_INVALID_TBL)
    (void) vnet_set_input_acl_intfc (vm, sw_if_index,
				     hicn_punt_glb.head_ip4[sw_if_index],
				     0xFFFFFFFF, 0xFFFFFFFF, is_enable);
  return;
}

/*
 * Enable the table on a given interface considering the table type
 *
 * XXX replace skip by base_offset XXX are we sure we always have ETH_L2, and
 * not base_offset ???
 */
int
hicn_punt_remove_ip4_address (vlib_main_t * vm, ip4_address_t * addr,
			      u8 mask, int skip, u32 sw_if_index,
			      int is_enable)
{

  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_classify_table_t *vnet_table = NULL;

  u32 table_index = ~0;

  u32 base_offset = (skip ? ETH_L2 : NO_L2);
  ip46_address_t addr46;
  ip46_address_set_ip4 (&addr46, addr);

  hicn_punt_del_vnetssn (&ipv4, &ipv4_src, &addr46, mask,
			 hicn_punt_glb.next_hit_data_ipv4, sw_if_index,
			 ETH_L2);
  hicn_punt_del_vnetssn (&ipv4, &ipv4_dst, &addr46, mask,
			 hicn_punt_glb.next_hit_interest_ipv4, sw_if_index,
			 ETH_L2);

  table_index =
    hicn_punt_glb.ip4_vnet_tbl_idx[sw_if_index][skip][HICN_PUNT_DST][mask];
  vnet_table = pool_elt_at_index (cm->tables, table_index);
  if (vnet_table->active_elements == 0)
    {
      hicn_punt_del_vnettbl (&ipv4, &ipv4_dst, mask,
			     hicn_punt_glb.ip4_vnet_tbl_idx[sw_if_index][skip]
			     [HICN_PUNT_SRC][mask], sw_if_index, base_offset);
    }
  table_index =
    hicn_punt_glb.ip4_vnet_tbl_idx[sw_if_index][skip][HICN_PUNT_SRC][mask];
  vnet_table = pool_elt_at_index (cm->tables, table_index);
  if (vnet_table->active_elements == 0)
    {
      hicn_punt_del_vnettbl (&ipv4, &ipv4_src, mask, ~0, sw_if_index,
			     base_offset);
    }
  return HICN_ERROR_NONE;
}

int
hicn_punt_remove_ip6_address (vlib_main_t * vm, ip6_address_t * addr,
			      u8 mask, int skip, u32 sw_if_index,
			      int is_enable)
{

  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_classify_table_t *vnet_table = NULL;

  u32 table_index = ~0;

  u32 base_offset = (skip ? ETH_L2 : NO_L2);

  hicn_punt_del_vnetssn (&ipv6, &ipv6_src, (ip46_address_t *) addr, mask,
			 hicn_punt_glb.next_hit_data_ipv6, sw_if_index,
			 ETH_L2);
  hicn_punt_del_vnetssn (&ipv6, &ipv6_dst, (ip46_address_t *) addr, mask,
			 hicn_punt_glb.next_hit_interest_ipv6, sw_if_index,
			 ETH_L2);

  table_index =
    hicn_punt_glb.ip6_vnet_tbl_idx[sw_if_index][skip][HICN_PUNT_DST][mask];
  vnet_table = pool_elt_at_index (cm->tables, table_index);
  if (vnet_table->active_elements == 0)
    {
      hicn_punt_del_vnettbl (&ipv6, &ipv6_dst, mask,
			     hicn_punt_glb.ip6_vnet_tbl_idx[sw_if_index][skip]
			     [HICN_PUNT_SRC][mask], sw_if_index, base_offset);
    }
  table_index =
    hicn_punt_glb.ip6_vnet_tbl_idx[sw_if_index][skip][HICN_PUNT_SRC][mask];
  vnet_table = pool_elt_at_index (cm->tables, table_index);
  if (vnet_table->active_elements == 0)
    {
      hicn_punt_del_vnettbl (&ipv6, &ipv6_src, mask, ~0, sw_if_index,
			     base_offset);
    }
  return HICN_ERROR_NONE;
}

/*
 * Enable the table on a given interface considering the table type
 */
void
hicn_punt_enable_disable_vnet_ip6_table_on_intf (vlib_main_t * vm,
						 u32 sw_if_index,
						 int is_enable)
{
  if (hicn_punt_glb.head_ip6[sw_if_index] != HICNP_PUNY_INVALID_TBL)
    (void) vnet_set_input_acl_intfc (vm, sw_if_index,
				     0xFFFFFFFF,
				     hicn_punt_glb.head_ip6[sw_if_index],
				     0xFFFFFFFF, is_enable);
  return;
}

/*
 * HICN PUNT vlibd node addtion
 */
void
hicn_punt_vlib_node_add (vlib_main_t * vm)
{
  u32 hit_next_index = 0xFFFFFFFF;
  vlib_node_t *node;

  /* to remove the warning */
  hit_next_index = hit_next_index;

  //Accquire the node indexes

  /* ip face */
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-face-ip4-input");
  hicn_punt_glb.hicn_node_info.hicn_face_ip4_input_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-face-ip6-input");
  hicn_punt_glb.hicn_node_info.hicn_face_ip6_input_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-face-ip4-output");
  hicn_punt_glb.hicn_node_info.hicn_face_ip4_output_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-face-ip6-output");
  hicn_punt_glb.hicn_node_info.hicn_face_ip6_output_index = node->index;

  /* ip iface */
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-iface-ip4-input");
  hicn_punt_glb.hicn_node_info.hicn_iface_ip4_input_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-iface-ip6-input");
  hicn_punt_glb.hicn_node_info.hicn_iface_ip6_input_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-iface-ip4-output");
  hicn_punt_glb.hicn_node_info.hicn_iface_ip4_output_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-iface-ip6-output");
  hicn_punt_glb.hicn_node_info.hicn_iface_ip4_output_index = node->index;

  /* udp face */
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-face-udp4-input");
  hicn_punt_glb.hicn_node_info.hicn_face_udp4_input_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-face-udp6-input");
  hicn_punt_glb.hicn_node_info.hicn_face_udp6_input_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-face-udp4-output");
  hicn_punt_glb.hicn_node_info.hicn_face_udp4_output_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-face-udp6-output");
  hicn_punt_glb.hicn_node_info.hicn_face_udp6_output_index = node->index;

  /* udp iface */
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-iface-udp4-input");
  hicn_punt_glb.hicn_node_info.hicn_iface_udp4_input_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-iface-udp6-input");
  hicn_punt_glb.hicn_node_info.hicn_iface_udp6_input_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-iface-udp4-output");
  hicn_punt_glb.hicn_node_info.hicn_iface_udp4_output_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "hicn-iface-udp6-output");
  hicn_punt_glb.hicn_node_info.hicn_iface_udp6_output_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "ip4-inacl");
  hicn_punt_glb.hicn_node_info.ip4_inacl_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "ip6-inacl");
  hicn_punt_glb.hicn_node_info.ip6_inacl_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
  hicn_punt_glb.hicn_node_info.ip4_lookup_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "ip6-lookup");
  hicn_punt_glb.hicn_node_info.ip6_lookup_node_index = node->index;


  hicn_punt_glb.next_hit_data_ipv4 = vlib_node_add_next (vm,
							 hicn_punt_glb.hicn_node_info.
							 ip4_inacl_node_index,
							 hicn_punt_glb.hicn_node_info.
							 hicn_face_ip4_input_index);

  hicn_punt_glb.next_hit_interest_ipv4 = vlib_node_add_next (vm,
							     hicn_punt_glb.hicn_node_info.
							     ip4_inacl_node_index,
							     hicn_punt_glb.hicn_node_info.
							     hicn_iface_ip4_input_index);

  hicn_punt_glb.next_hit_data_ipv6 = vlib_node_add_next (vm,
							 hicn_punt_glb.hicn_node_info.
							 ip6_inacl_node_index,
							 hicn_punt_glb.hicn_node_info.
							 hicn_face_ip6_input_index);

  hicn_punt_glb.next_hit_interest_ipv6 = vlib_node_add_next (vm,
							     hicn_punt_glb.hicn_node_info.
							     ip6_inacl_node_index,
							     hicn_punt_glb.hicn_node_info.
							     hicn_iface_ip6_input_index);

  hicn_punt_glb.next_hit_data_udp4 = vlib_node_add_next (vm,
							 hicn_punt_glb.hicn_node_info.
							 ip4_inacl_node_index,
							 hicn_punt_glb.hicn_node_info.
							 hicn_face_udp4_input_index);

  hicn_punt_glb.next_hit_interest_udp4 = vlib_node_add_next (vm,
							     hicn_punt_glb.hicn_node_info.
							     ip4_inacl_node_index,
							     hicn_punt_glb.hicn_node_info.
							     hicn_iface_udp4_input_index);

  hicn_punt_glb.next_hit_data_udp6 = vlib_node_add_next (vm,
							 hicn_punt_glb.hicn_node_info.
							 ip6_inacl_node_index,
							 hicn_punt_glb.hicn_node_info.
							 hicn_face_udp6_input_index);

  hicn_punt_glb.next_hit_interest_udp6 = vlib_node_add_next (vm,
							     hicn_punt_glb.hicn_node_info.
							     ip6_inacl_node_index,
							     hicn_punt_glb.hicn_node_info.
							     hicn_iface_udp6_input_index);

  return;
}

/*
 * HICN PUNT INIT
 */
void
hicn_punt_init (vlib_main_t * vm)
{
  u32 table_index = ~0;
  //Create vnet classify tables and store the table indexes
  memset (hicn_punt_glb.ip4_vnet_tbl_idx, table_index,
	  sizeof (u32) * 4 * 2 * HICN_PUNT_IP4_MASK * HICN_MAX_INTFC);
  memset (hicn_punt_glb.ip6_vnet_tbl_idx, table_index,
	  sizeof (u32) * 4 * 2 * HICN_PUNT_IP6_MASK * HICN_MAX_INTFC);

  memset (hicn_punt_glb.udp44_vnet_tbl_idx, table_index,
	  sizeof (u32) * 4 * 2 * HICN_PUNT_IP4_MASK * HICN_MAX_INTFC);
  memset (hicn_punt_glb.udp46_vnet_tbl_idx, table_index,
	  sizeof (u32) * 4 * 2 * HICN_PUNT_IP6_MASK * HICN_MAX_INTFC);
  memset (hicn_punt_glb.udp64_vnet_tbl_idx, table_index,
	  sizeof (u32) * 4 * 2 * HICN_PUNT_IP4_MASK * HICN_MAX_INTFC);
  memset (hicn_punt_glb.udp66_vnet_tbl_idx, table_index,
	  sizeof (u32) * 4 * 2 * HICN_PUNT_IP6_MASK * HICN_MAX_INTFC);
  //Register hicn nodes after vnet table creation
  hicn_punt_vlib_node_add (vm);
  memset (hicn_punt_glb.head_ip4, ~0, sizeof (u32) * HICN_MAX_INTFC);
  memset (hicn_punt_glb.tail_ip4, ~0, sizeof (u32) * HICN_MAX_INTFC);
  memset (hicn_punt_glb.head_ip6, ~0, sizeof (u32) * HICN_MAX_INTFC);
  memset (hicn_punt_glb.tail_ip6, ~0, sizeof (u32) * HICN_MAX_INTFC);
  return;
}

u32
hicn_punt_interest_data_for_udp (vlib_main_t * vm,
				 ip46_address_t * prefix, u8 mask,
				 u32 swif, u8 punt_type, u16 sport, u16 dport)
{
  int skip = 1;
  u32 table_index;

  if (punt_type != HICN_PUNT_IP_TYPE && punt_type != HICN_PUNT_UDP4_TYPE
      && punt_type != HICN_PUNT_UDP6_TYPE)
    return HICN_ERROR_PUNT_INVAL;

  if (ip46_address_is_ip4 (prefix))
    {
      if (mask > IPV4_ADDR_LEN_BITS)
	return HICN_ERROR_PUNT_INVAL;

      if (punt_type == HICN_PUNT_UDP4_TYPE)
	{
	  skip = 2;
	  /* Create Vnet table for a given mask */
	  hicn_punt_add_vnettbl_udp (&ipv44, &ipv4, &udp44_src, mask, ~0,
				     swif, ETH_L2);

	  table_index =
	    hicn_punt_glb.udp44_vnet_tbl_idx[swif][skip][HICN_PUNT_SRC][mask];

	  hicn_punt_add_vnettbl_udp (&ipv44, &ipv4, &udp44_dst, mask,
				     table_index, swif, ETH_L2);
	  /*
	   * Add a session for the specified ip address and
	   * subnet mask
	   */
	  hicn_punt_add_vnetssn_udp (&ipv44, &ipv4, &udp44_src,
				     prefix, mask,
				     hicn_punt_glb.next_hit_data_udp4,
				     swif, ETH_L2, IPPROTO_UDP, sport, dport);

	  hicn_punt_add_vnetssn_udp (&ipv44, &ipv4, &udp44_dst,
				     prefix, mask,
				     hicn_punt_glb.next_hit_interest_udp4,
				     swif, ETH_L2, IPPROTO_UDP, sport, dport);

	  hicn_punt_enable_disable_vnet_ip4_table_on_intf (vm, swif,
							   OP_ENABLE);
	}
      else			//PUNTING is UDP6
	{
	  skip = 3;
	  /* Create Vnet table for a given mask */
	  hicn_punt_add_vnettbl_udp (&ipv64, &ipv6, &udp64_src, mask, ~0,
				     swif, ETH_L2);

	  table_index =
	    hicn_punt_glb.udp64_vnet_tbl_idx[swif][skip][HICN_PUNT_SRC][mask];

	  hicn_punt_add_vnettbl_udp (&ipv64, &ipv6, &udp64_dst, mask,
				     table_index, swif, ETH_L2);

	  /*
	   * Add a session for the specified ip address and
	   * subnet mask
	   */
	  hicn_punt_add_vnetssn_udp (&ipv64, &ipv4, &udp64_src,
				     prefix, mask,
				     hicn_punt_glb.next_hit_data_udp6,
				     swif, ETH_L2, IPPROTO_UDP, sport, dport);

	  hicn_punt_add_vnetssn_udp (&ipv64, &ipv4, &udp64_dst,
				     prefix, mask,
				     hicn_punt_glb.next_hit_interest_udp6,
				     swif, ETH_L2, IPPROTO_UDP, sport, dport);

	  hicn_punt_enable_disable_vnet_ip6_table_on_intf (vm, swif,
							   OP_ENABLE);
	}
    }
  else
    {
      if (punt_type == HICN_PUNT_UDP4_TYPE)
	{
	  skip = 2;
	  /* Create Vnet table for a given mask */
	  if (mask > 96)
	    return HICN_ERROR_PUNT_INVAL;

	  hicn_punt_add_vnettbl_udp (&ipv46, &ipv4, &udp46_src, mask, ~0,
				     swif, ETH_L2);

	  table_index =
	    hicn_punt_glb.udp46_vnet_tbl_idx[swif][skip][HICN_PUNT_SRC][mask];
	  hicn_punt_add_vnettbl_udp (&ipv46, &ipv4, &udp46_dst, mask,
				     table_index, swif, ETH_L2);

	  /*
	   * Add a session for the specified ip address and
	   * subnet mask
	   */
	  hicn_punt_add_vnetssn_udp (&ipv46, &ipv4, &udp46_src,
				     prefix, mask,
				     hicn_punt_glb.next_hit_data_udp4,
				     swif, ETH_L2, IPPROTO_UDP, sport, dport);
	  hicn_punt_add_vnetssn_udp (&ipv46, &ipv4, &udp46_dst,
				     prefix, mask,
				     hicn_punt_glb.next_hit_interest_udp4,
				     swif, ETH_L2, IPPROTO_UDP, sport, dport);

	  hicn_punt_enable_disable_vnet_ip4_table_on_intf (vm, swif,
							   OP_ENABLE);
	}
      else
	{
	  if (mask > 122)
	    return HICN_ERROR_PUNT_INVAL;
	  
	  skip = 3;
	  hicn_punt_add_vnettbl_udp (&ipv66, &ipv6, &udp66_src, mask, ~0,
				     swif, ETH_L2);

	  table_index =
	    hicn_punt_glb.udp66_vnet_tbl_idx[swif][skip][HICN_PUNT_SRC][mask];
	  hicn_punt_add_vnettbl_udp (&ipv66, &ipv6, &udp66_dst, mask,
				     table_index, swif, ETH_L2);

	  /*
	   * Add a session for the specified ip address and
	   * subnet mask
	   */
	  hicn_punt_add_vnetssn_udp (&ipv66, &ipv6, &udp66_src,
				     prefix, mask,
				     hicn_punt_glb.next_hit_data_udp6,
				     swif, ETH_L2, IPPROTO_UDP, sport, dport);
	  hicn_punt_add_vnetssn_udp (&ipv66, &ipv6, &udp66_dst,
				     prefix, mask,
				     hicn_punt_glb.next_hit_interest_udp6,
				     swif, ETH_L2, IPPROTO_UDP, sport, dport);

	  hicn_punt_enable_disable_vnet_ip6_table_on_intf (vm, swif,
							   OP_ENABLE);
	}

    }
  return HICN_ERROR_NONE;
}



u32
hicn_punt_interest_data_for_ethernet (vlib_main_t * vm,
				      ip46_address_t * prefix, u8 mask,
				      u32 swif, u8 punt_type)
{
  int skip = 1;
  u32 table_index;
  u8 use_current_data = HICN_CLASSIFY_NO_CURRENT_DATA_FLAG;

  if (punt_type != HICN_PUNT_IP_TYPE && punt_type != HICN_PUNT_UDP4_TYPE
      && punt_type != HICN_PUNT_UDP6_TYPE)
    return HICN_ERROR_PUNT_INVAL;

  if (ip46_address_is_ip4 (prefix))
    {
      if (mask > IPV4_ADDR_LEN_BITS)
	return HICN_ERROR_PUNT_INVAL;

      if (punt_type == HICN_PUNT_IP_TYPE)
	{
	  /* Create Vnet table for a given mask */
	  hicn_punt_add_vnettbl (&ipv4, &ipv4_src, mask, ~0, swif, ETH_L2,
				 use_current_data);

	  table_index =
	    hicn_punt_glb.ip4_vnet_tbl_idx[swif][skip][HICN_PUNT_SRC][mask];

	  hicn_punt_add_vnettbl (&ipv4, &ipv4_dst, mask, table_index, swif,
				 ETH_L2, use_current_data);

	  /*
	   * Add a session for the specified ip address and
	   * subnet mask
	   */
	  hicn_punt_add_vnetssn (&ipv4, &ipv4_src,
				 prefix, mask,
				 hicn_punt_glb.next_hit_data_ipv4, swif,
				 ETH_L2);
	  hicn_punt_add_vnetssn (&ipv4, &ipv4_dst,
				 prefix, mask,
				 hicn_punt_glb.next_hit_interest_ipv4, swif,
				 ETH_L2);

	  hicn_punt_enable_disable_vnet_ip4_table_on_intf (vm, swif,
							   OP_ENABLE);
	}
      else
	{
	  return HICN_ERROR_PUNT_INVAL;
	}
    }
  else
    {
      if (punt_type == HICN_PUNT_IP_TYPE)
	{
	  if (mask > IPV6_ADDR_LEN_BITS)
	    return HICN_ERROR_PUNT_INVAL;

	  /* Create Vnet table for a given mask */
	  hicn_punt_add_vnettbl (&ipv6, &ipv6_src, mask, ~0, swif, ETH_L2,
				 use_current_data);

	  table_index =
	    hicn_punt_glb.ip6_vnet_tbl_idx[swif][skip][HICN_PUNT_SRC][mask];

	  hicn_punt_add_vnettbl (&ipv6, &ipv6_dst, mask, table_index, swif,
				 ETH_L2, use_current_data);

	  /*
	   * Add a session for the specified ip address and
	   * subnet mask
	   */
	  hicn_punt_add_vnetssn (&ipv6, &ipv6_src, prefix,
				 mask, hicn_punt_glb.next_hit_data_ipv6, swif,
				 ETH_L2);
	  hicn_punt_add_vnetssn (&ipv6, &ipv6_dst, prefix,
				 mask, hicn_punt_glb.next_hit_interest_ipv6,
				 swif, ETH_L2);

	  hicn_punt_enable_disable_vnet_ip6_table_on_intf (vm, swif,
							   OP_ENABLE);
	}
      else
	{
	  return HICN_ERROR_PUNT_INVAL;
	}

    }
  return HICN_ERROR_NONE;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
