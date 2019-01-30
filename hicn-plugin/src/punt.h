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

#ifndef __HICN_PUNT_H__
#define __HICN_PUNT_H__

#include <vppinfra/error.h>
#include <hicn/hicn.h>

#define HICN_CLASSIFY_TABLE_MEMORY_SIZE (2*1024*1024)	// 2MB allocated for the classification table
#define HICN_PUNTING_BUFFER_SIZE_32 (32)
#define HICN_PUNTING_BUFFER_SIZE_48 (48)
#define HICN_PUNTING_BUFFER_SIZE_64 (64)
#define HICN_PUNTING_BUFFER_SIZE_80 (80)
#define HICN_PUNTING_BUFFER_SIZE_128 (128)

/* Limits */

#define HICN_PUNT_IP4     0
#define HICN_PUNT_IP6     1

#define HICN_MAX_INTFC 256

/* We also consider mask = 0 to match everything */
#define HICN_PUNT_IP4_MASK   33
#define HICN_PUNT_IP6_MASK   129

#define HICN_PUNT_IP_TYPE 0
#define HICN_PUNT_UDP4_TYPE 1
#define HICN_PUNT_UDP6_TYPE 2
/*
 * u32 ip4_vnet_tbl_idx[HICN_MAX_INTFC][2][3][HICN_PUNT_IP4_MASK];
 * //[skip][src][mask],[skip][dst][mask] u32
 * ip6_vnet_tbl_idx[HICN_MAX_INTFC][2][3][HICN_PUNT_IP6_MASK];
 * //[skip][src][mask],[skip][dst][mask]
 */
#define PUNT_MASK(ip) (ip->addr_len_bits + 1)
#define TABLE_ELT_P(ip, i, j, k, l) (ip->tbl + (4 * 2 * PUNT_MASK(ip)) * i + (2 * PUNT_MASK(ip)) * j + k * PUNT_MASK(ip) + l)
#define TABLE_ELT(ip, i, j, k, l)  (*(TABLE_ELT_P(ip, i, j, k, l)))

#define NO_L2 0
#define ETH_L2 sizeof(ethernet_header_t)

#define IPPROTO_MASK 0xFF

/* Index to access vnet table index */
#define HICN_PUNT_SRC     0
#define HICN_PUNT_DST     1

#define HICN_PUNT_OK      0
#define HICN_PUNT_ERR     1

#define HICNP_PUNY_INVALID_TBL ~0

/* Number of bytes before the next header/protocol field in ip6/4 */
#define BYTES_TO_PROTOCOL_IP4 9
#define BYTES_TO_NEXT_HEADER_IP6 6

#define PUNT_BUFFER_SIZE 100	/* B */
#define CLASSIFIER_VECTOR_SIZE 16	/* B */

#define OP_DEL 0
#define OP_ADD 1
#define OP_DISABLE 0
#define OP_ENABLE 1

/* vnet_classify_add_del_table */
#define HICN_CLASSIFY_NO_NEXT_TABLE  0xFFFFFFFF
#define HICN_CLASSIFY_MISS_NEXT_INDEX 16
#define HICN_CLASSIFY_CURRENT_DATA_FLAG CLASSIFY_FLAG_USE_CURR_DATA
#define HICN_CLASSIFY_NO_CURRENT_DATA_FLAG 0
#define HICN_CLASSIFY_CURRENT_DATA_OFFSET 0
#define HICN_CLASSIFY_DON_T_DEL_CHAIN 0

/* vnet_classify_add_del_session */
#define HICN_CLASSIFY_OPAQUE_INDEX 0xFFFFFFFF
#define HICN_CLASSIFY_ADVANCE 0
#define HICN_CLASSIFY_ACTION 0
#define HICN_CLASSIFY_METADATA 0

/* This should be equal to the number of rules we expect in each table */
#define HICN_CLASSIFY_NBUCKETS 3


/* HICN punt node index */
typedef struct _hicn_node_info_s
{
  u32 hicn_face_ip4_input_index;
  u32 hicn_face_ip6_input_index;
  u32 hicn_iface_ip4_input_index;
  u32 hicn_iface_ip6_input_index;
  u32 hicn_face_ip4_output_index;
  u32 hicn_face_ip6_output_index;
  u32 hicn_iface_ip4_output_index;
  u32 hicn_iface_ip6_output_index;
  u32 hicn_face_udp4_input_index;
  u32 hicn_face_udp6_input_index;
  u32 hicn_iface_udp4_input_index;
  u32 hicn_iface_udp6_input_index;
  u32 hicn_face_udp4_output_index;
  u32 hicn_face_udp6_output_index;
  u32 hicn_iface_udp4_output_index;
  u32 hicn_iface_udp6_output_index;
  u32 ip4_inacl_node_index;
  u32 ip6_inacl_node_index;
  u32 ip4_lookup_node_index;
  u32 ip6_lookup_node_index;
} hicn_node_info_t;

/*
 * HICN global PUNT info
 */
typedef struct _hicn_punt_glb_s
{
  hicn_node_info_t hicn_node_info;

  /*
   * The following nodes are used to create the vlib node graph, and
   * point classified packets to the right node.
   */
  u32 next_hit_interest_ipv4;
  //node - graph index to forward packets to our hicn nodes
  u32 next_hit_data_ipv4;
  u32 next_hit_interest_ipv6;
  //node - graph index to forward packets to our hicn nodes
  u32 next_hit_data_ipv6;
  u32 next_hit_interest_udp4;
  //node - graph index to forward packets to our hicn nodes
  u32 next_hit_data_udp4;
  u32 next_hit_interest_udp6;
  //node - graph index to forward packets to our hicn nodes
  u32 next_hit_data_udp6;

  /*
   * One table is created : - per interface : so that we can have
   * different punted prefixes per interface, and thus decrease the
   * amount of matched rules per packet. An interface will be
   * consistently receiving packets with or without the ethernet
   * header, and thus the offsets should always be correct. - per skip
   * (assuming it is for the base offset (ethernet or not), in which
   * case the interface should be sufficient. - per prefix length to
   * allow for sorting later. - per src / dst (?)
   *
   * Note that there is no test on the packet type (v4 or v6), as they
   * follow distinct paths in the vpp graph and will thus be dispatched
   * to distinct classifiers. This is also why we duplicate the state
   * for both IPv4 and IPv6 in this implementation.
   *
   * Tables are chained per interface in the order they are added. Each
   * table consists in a set of rules (named sessions).
   *
   * / interface --> table i [.next_table_index=j] --> table j [.nti=~0]
   * -- drop \      |                                 | +-- on match,
   * send to node m      +-- [...] to node n
   *
   * For debugging purposes, you can use the following commands:
   *
   * vppctl show inacl type ip4 vppctl show inacl type ip6
   *
   * vppctl show classify tables [verbose]
   *
   * TODO: - allow tables to be removed - sort tables with decreasing
   * prefix length to allow for LPM. - directly access the linked list
   * through vpp APIs and remove global variables. They are not
   * sufficient anyways for removal.
   */

  /**
   * Given the current implementation, the following multidimensional array
   * stores the table indexes uniquerly identified by the 4-tuple (interface,
   * skip, src/dst, mask).
   *
   * For flexibility, some macros and functions will be defined in the .c to
   * manipulate this array.
   */
  u32 ip4_vnet_tbl_idx[HICN_MAX_INTFC][4][2][HICN_PUNT_IP4_MASK];
  //[skip][src][mask],[skip][dst][mask]
  u32 ip6_vnet_tbl_idx[HICN_MAX_INTFC][4][2][HICN_PUNT_IP6_MASK];
  //[skip][src][mask],[skip][dst][mask]
  u32 udp44_vnet_tbl_idx[HICN_MAX_INTFC][4][2][HICN_PUNT_IP4_MASK];
  //[skip][src][mask],[skip][dst][mask]
  u32 udp46_vnet_tbl_idx[HICN_MAX_INTFC][4][2][HICN_PUNT_IP6_MASK];
  //[skip][src][mask],[skip][dst][mask]
  u32 udp64_vnet_tbl_idx[HICN_MAX_INTFC][4][2][HICN_PUNT_IP4_MASK];
  //[skip][src][mask],[skip][dst][mask]
  u32 udp66_vnet_tbl_idx[HICN_MAX_INTFC][4][2][HICN_PUNT_IP6_MASK];
  //[skip][src][mask],[skip][dst][mask]

  /*
   * The first and last tables associated to each interface (both for
   * v4 and v6) are stored. They are respectively used to : - start
   * classification on the correct table depending on the input
   * interface: the assumption is that different interfaces with punt
   * different prefixes, which should decreate the number of potential
   * rules to match for each incoming packet. see.
   * vnet_set_input_acl_intfc() - maintain the chaining between tables
   * so that upon addition, the newly created table can be chained to
   * the previous last one.
   */
  u32 head_ip4[HICN_MAX_INTFC];
  u32 tail_ip4[HICN_MAX_INTFC];
  u32 head_ip6[HICN_MAX_INTFC];
  u32 tail_ip6[HICN_MAX_INTFC];

} hicn_punt_glb_t;

extern hicn_punt_glb_t hicn_punt_glb;



/* XXX The two following structs might be opaque */

#define NA 0

typedef struct
{
  u32 offset;
  u32 len;			/* bytes */
  u32 punt_id;			/* see explanation in hicn_punt.c */
} field_t;

/* Format: _(name, base, layer, field, punt_id) */
#define foreach_field                                            \
  _(ipv6_src, 0, _ipv6_header_t, saddr, HICN_PUNT_SRC)           \
  _(ipv6_dst, 0, _ipv6_header_t, daddr, HICN_PUNT_DST)           \
  _(ipv6_protocol, 0, _ipv6_header_t, nxt, NA)                   \
  _(ipv4_src, 0, _ipv4_header_t, saddr, HICN_PUNT_SRC)           \
  _(ipv4_dst, 0, _ipv4_header_t, daddr, HICN_PUNT_DST)           \
  _(ipv4_protocol, 0, _ipv4_header_t, protocol, NA)              \
                                                                 \
  _(ipv4_version, 0, _ipv4_header_t, version_ihl, NA)                   \
  _(ipv6_version, 0, _ipv6_header_t, vfc, NA)                           \
  _(udp4_sport, IPV4_HDRLEN, _udp_header_t, src_port, NA)               \
  _(udp4_dport, IPV4_HDRLEN, _udp_header_t, dst_port, NA)               \
  _(udp6_sport, IPV6_HDRLEN, _udp_header_t, src_port, NA)               \
  _(udp6_dport, IPV6_HDRLEN, _udp_header_t, dst_port, NA)               \
  _(udp6_protocol, 0, _ipv6_header_t, nxt, NA)				\
  _(udp4_protocol, 0, _ipv4_header_t, protocol, NA) \
  _(udp46_src, IPV4_HDRLEN + UDP_HDRLEN, _ipv6_header_t, saddr, HICN_PUNT_SRC) \
  _(udp46_dst, IPV4_HDRLEN + UDP_HDRLEN, _ipv6_header_t, daddr, HICN_PUNT_DST) \
  _(udp44_src, IPV4_HDRLEN + UDP_HDRLEN, _ipv4_header_t, saddr, HICN_PUNT_SRC) \
  _(udp44_dst, IPV4_HDRLEN + UDP_HDRLEN, _ipv4_header_t, daddr, HICN_PUNT_DST) \
  _(udp66_src, IPV6_HDRLEN + UDP_HDRLEN, _ipv6_header_t, saddr, HICN_PUNT_SRC) \
  _(udp66_dst, IPV6_HDRLEN + UDP_HDRLEN, _ipv6_header_t, daddr, HICN_PUNT_DST) \
  _(udp64_src, IPV6_HDRLEN + UDP_HDRLEN, _ipv6_header_t, saddr, HICN_PUNT_SRC) \
  _(udp64_dst, IPV6_HDRLEN + UDP_HDRLEN, _ipv6_header_t, daddr, HICN_PUNT_DST) \


#define _(NAME, BASE, LAYER, FIELD, PUNT_ID)          \
    extern field_t NAME;
foreach_field
#undef _
  typedef struct
{
  u32 *tbl;
  u8 addr_len_bits;
  field_t *protocol_field;
  field_t *version_field;
  field_t *udp_sport;
  field_t *udp_dport;
  u8 ip_version;
} ip_version_t;

extern ip_version_t ipv4;
extern ip_version_t ipv6;


/* ------------------------- */

/**
 * @brief Punt table APIs
 *
 * Those APIs are called when the first punting table is created for a given
 * interface, so as to point to the start of the chain.
 */
void
hicn_punt_enable_disable_vnet_ip4_table_on_intf (vlib_main_t * vm,
						 u32 sw_if_index,
						 int is_enable);
void
hicn_punt_enable_disable_vnet_ip6_table_on_intf (vlib_main_t * vm,
						 u32 sw_if_index,
						 int is_enable);
u32 hicn_punt_interest_data_for_udp (vlib_main_t * vm,
				     ip46_address_t * prefix, u8 mask,
				     u32 swif, u8 punt_type, u16 sport,
				     u16 dport);
u32 hicn_punt_interest_data_for_ethernet (vlib_main_t * vm,
					  ip46_address_t * prefix, u8 mask,
					  u32 swif, u8 type);
int hicn_punt_remove_ip6_address (vlib_main_t * vm, ip6_address_t * addr,
				  u8 mask, int skip, u32 swif, int is_enable);
int hicn_punt_remove_ip4_address (vlib_main_t * vm, ip4_address_t * addr,
				  u8 mask, int skip, u32 swif, int is_enable);
void hicn_punt_init (vlib_main_t * vm);

int
hicn_punt_add_del_vnettbl (ip_version_t * ip, field_t * field, u8 mask, u32
			   next_tbl_index, u32 intfc, u8 base_offset,
			   u8 use_current_data, int is_add);

#define hicn_punt_add_vnettbl(ip, field, mask, next_tbl_index, intfc, base_offset, use_current_data) \
  (hicn_punt_add_del_vnettbl(ip, field, mask, next_tbl_index, intfc, base_offset, use_current_data, OP_ADD))

#define hicn_punt_del_vnettbl(ip, field, mask, next_tbl_index, intfc, base_offset) \
  (hicn_punt_add_del_vnettbl(ip, field, mask, next_tbl_index, intfc, base_offset, HICN_CLASSIFY_NO_CURRENT_DATA_FLAG, OP_DEL))

int
hicn_punt_add_del_vnetssn (ip_version_t * ip, field_t * field,
			   ip46_address_t * v46_address, u8 mask,
			   u32 next_hit_index, u32 intfc, u8 base_offset,
			   int is_add);

#define hicn_punt_add_vnetssn(ip, field, addr, mask, index, intfc, offset) \
    (hicn_punt_add_del_vnetssn(ip, field, addr, mask, index, intfc, offset, OP_ADD))

#define hicn_punt_del_vnetssn(ip, field, addr, mask, index, intfc, offset) \
    (hicn_punt_add_del_vnetssn(ip, field, addr, mask, index, intfc, offset, OP_DEL))

#endif /* // __HICN_PUNT_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
