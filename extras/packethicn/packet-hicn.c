/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <epan/packet.h>
#include <gmodule.h>

#define WS_BUILD_DLL
#include "ws_symbol_export.h"
#include "config.h"

#include "epan/proto.h"
#include "epan/etypes.h"

#include <hicn/hicn.h>

#define PATHLABEL_PAD_LEN 3 // To remove once fixed in libhicn

// These should be defined in libhicn
#define TIMESCALE_BITS_OFFSET 4
#define TIMESCALE_BITS_LENGTH 4

#define HICN_VERSION "0.0.1"

/* TCP-HICN flags */
#define FLAGS_BITS_LEN 8
#define FLAGS_MASK 0xFF
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_ACK  0x10
#define TH_CWR  0x80
#define TH_ID   0x40
#define TH_MAN  0x20
#define TH_SIG  0x08

#define HICN_PORT 9695

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = HICN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
static void proto_register_hicn(void);
static void proto_reg_handoff_hicn(void);

static int proto_hicn = -1;

static int hf_hicn_ipv6_src = -1;
static int hf_hicn_ipv6_src_data = -1;
static int hf_hicn_ipv6_dst = -1;
static int hf_hicn_ipv6_dst_interest = -1;
static int hf_hicn_tcp_namesuffix = -1;
static int hf_hicn_tcp_pathlabel = -1;
static int hf_hicn_tcp_hdrlen_timescale = -1;
static int hf_hicn_tcp_hdrlen = -1;
static int hf_hicn_tcp_timescale = -1;
static int hf_hicn_tcp_flags = -1;
static int hf_hicn_tcp_flags_cwr = -1;
static int hf_hicn_tcp_flags_man = -1;
static int hf_hicn_tcp_flags_id = -1;
static int hf_hicn_tcp_flags_ack = -1;
static int hf_hicn_tcp_flags_sig = -1;
static int hf_hicn_tcp_flags_rst = -1;
static int hf_hicn_tcp_flags_syn = -1;
static int hf_hicn_tcp_flags_fin = -1;
static int hf_hicn_tcp_ldr = -1;
static int hf_hicn_tcp_csum = -1;
static int hf_hicn_tcp_lifetime = -1;

static gint ett_hicn = -1;
static gint ett_hicn_l3 = -1;
static gint ett_hicn_l4 = -1;
static gint ett_hicn_l4_flags = -1;


static uint8_t *_p_hdr = NULL;

bool is_interest(const hicn_header_t *header) {
  bool is_interest = false;

  hicn_packet_test_ece(header, &is_interest);

  return !is_interest;
}

// TODO: HANDLE ERRORS

hicn_header_t *get_header(tvbuff_t *tvb, const gint offset, const gint length){
  tvb_ensure_bytes_exist(tvb, offset, length);
  hicn_header_t *pkt_hdr = (hicn_header_t *) tvb_get_ptr(tvb, offset, length);
  _p_hdr = (uint8_t *) pkt_hdr;
  return pkt_hdr;
}

uint32_t get_offset(uint8_t *data_addr){
  return data_addr - _p_hdr;
}

static int
dissect_hicn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gint i = 0;
  guint bpos;

  hicn_header_t *pkt_hdr = get_header(tvb, 0, HICN_V6_TCP_HDRLEN);

  wmem_strbuf_t *flags_strbuf = wmem_strbuf_new_label(wmem_packet_scope());
  static const gchar *flags[] = {"_FIN", "_SYN", "_RST", "SIG", "_ACK", "MAN", "ID", "_CWR"};
  wmem_strbuf_append(flags_strbuf, "<None>");

  uint32_t flags_offset = get_offset((uint8_t *) &(pkt_hdr->v6.tcp.flags));

  gboolean first_flag = TRUE;
  for(i=0; i<9; i++) {
    bpos = 1 << i;
    if(pkt_hdr->v6.tcp.flags & bpos) {
      if(first_flag) {
        wmem_strbuf_truncate(flags_strbuf, 0);
      }
      wmem_strbuf_append_printf(flags_strbuf, "%s%s", first_flag ? "" : ", ", flags[i]);
      first_flag = FALSE;
    }
  }

  // DISPLAY SECTION
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "HICN");
  col_clear(pinfo->cinfo, COL_INFO);

  proto_item *ti = proto_tree_add_item(tree, proto_hicn, tvb, 0, HICN_V6_TCP_HDRLEN, ENC_NA);
  proto_tree *hicn_tree = proto_item_add_subtree(ti, ett_hicn);

  // L3
  proto_item *ti_l3;
  proto_tree *hicn_l3_tree = proto_tree_add_subtree(hicn_tree, tvb, 0, IPV6_HDRLEN, ett_hicn_l3, &ti_l3, "HICN Layer 3");

  if(is_interest(pkt_hdr)){
    proto_item_append_text(ti, ", Interest Packet");
    col_set_str(pinfo->cinfo, COL_INFO, "Interest Packet");
    proto_tree_add_item(hicn_l3_tree, hf_hicn_ipv6_src, tvb, get_offset((uint8_t *) &(pkt_hdr->v6.ip.saddr)), sizeof(pkt_hdr->v6.ip.saddr), ENC_BIG_ENDIAN);
    proto_tree_add_item(hicn_l3_tree, hf_hicn_ipv6_dst_interest, tvb, get_offset((uint8_t *) &(pkt_hdr->v6.ip.daddr)), sizeof(pkt_hdr->v6.ip.daddr), ENC_BIG_ENDIAN);
  } else {
    // TODO: NEW LABEL FOR NACKS
    proto_item_append_text(ti, ", Data Packet");
    col_set_str(pinfo->cinfo, COL_INFO, "Data Packet");
    proto_tree_add_item(hicn_l3_tree, hf_hicn_ipv6_src_data, tvb, get_offset((uint8_t *) &(pkt_hdr->v6.ip.saddr)), sizeof(pkt_hdr->v6.ip.saddr), ENC_BIG_ENDIAN);
    proto_tree_add_item(hicn_l3_tree, hf_hicn_ipv6_dst, tvb, get_offset((uint8_t *) &(pkt_hdr->v6.ip.daddr)), sizeof(pkt_hdr->v6.ip.daddr), ENC_BIG_ENDIAN);
  }

  // L4
  proto_item *ti_l4;
  proto_tree *hicn_l4_tree = proto_tree_add_subtree(hicn_tree, tvb, IPV6_HDRLEN, TCP_HDRLEN, ett_hicn_l4, &ti_l4, "HICN Layer 4");

  proto_tree_add_item(hicn_l4_tree, hf_hicn_tcp_namesuffix, tvb, get_offset((uint8_t *) &(pkt_hdr->v6.tcp.name_suffix)), sizeof(pkt_hdr->v6.tcp.name_suffix), ENC_BIG_ENDIAN);
  proto_tree_add_item(hicn_l4_tree, hf_hicn_tcp_pathlabel, tvb, get_offset((uint8_t *) &(pkt_hdr->v6.tcp.pathlabel))+PATHLABEL_PAD_LEN, sizeof(pkt_hdr->v6.tcp.pathlabel), ENC_BIG_ENDIAN);
  proto_item *ti_l4_ts = proto_tree_add_bits_item(hicn_l4_tree, hf_hicn_tcp_timescale, tvb,
    get_offset((uint8_t *) &(pkt_hdr->v6.tcp.data_offset_and_reserved))*8 + TIMESCALE_BITS_OFFSET, TIMESCALE_BITS_LENGTH, ENC_BIG_ENDIAN);
  proto_item_append_text(ti_l4_ts, " (Lifetime scaling factor: %dx)", pkt_hdr->v6.tcp.timescale+1);
  proto_item *hicn_l4_flags_tree = proto_tree_add_uint_format_value(hicn_l4_tree, hf_hicn_tcp_flags, tvb,
    get_offset((uint8_t *) &(pkt_hdr->v6.tcp.flags)), 1, pkt_hdr->v6.tcp.flags, "0x%02x (%s)", pkt_hdr->v6.tcp.flags, wmem_strbuf_get_str(flags_strbuf)
  );
  proto_tree *field_tree = proto_item_add_subtree(hicn_l4_flags_tree, ett_hicn_l4_flags);
  proto_tree_add_boolean(field_tree, hf_hicn_tcp_flags_cwr, tvb, flags_offset, 1, pkt_hdr->v6.tcp.flags);
  proto_tree_add_boolean(field_tree, hf_hicn_tcp_flags_id, tvb, flags_offset, 1, pkt_hdr->v6.tcp.flags);
  proto_tree_add_boolean(field_tree, hf_hicn_tcp_flags_man, tvb, flags_offset, 1, pkt_hdr->v6.tcp.flags);
  proto_tree_add_boolean(field_tree, hf_hicn_tcp_flags_ack, tvb, flags_offset, 1, pkt_hdr->v6.tcp.flags);
  proto_tree_add_boolean(field_tree, hf_hicn_tcp_flags_sig, tvb, flags_offset, 1, pkt_hdr->v6.tcp.flags);
  proto_tree_add_boolean(field_tree, hf_hicn_tcp_flags_rst, tvb, flags_offset, 1, pkt_hdr->v6.tcp.flags);
  proto_tree_add_boolean(field_tree, hf_hicn_tcp_flags_syn, tvb, flags_offset, 1, pkt_hdr->v6.tcp.flags);
  proto_tree_add_boolean(field_tree, hf_hicn_tcp_flags_fin, tvb, flags_offset, 1, pkt_hdr->v6.tcp.flags);
  proto_tree_add_item(hicn_l4_tree, hf_hicn_tcp_ldr, tvb, get_offset((uint8_t *) &(pkt_hdr->v6.tcp.ldr)), sizeof(pkt_hdr->v6.tcp.ldr), ENC_BIG_ENDIAN);
  proto_tree_add_item(hicn_l4_tree, hf_hicn_tcp_csum, tvb, get_offset((uint8_t *) &(pkt_hdr->v6.tcp.csum)), sizeof(pkt_hdr->v6.tcp.ldr), ENC_BIG_ENDIAN);
  proto_item *ti_l4_lt = proto_tree_add_item(hicn_l4_tree, hf_hicn_tcp_lifetime, tvb, get_offset((uint8_t *) &(pkt_hdr->v6.tcp.lifetime)), sizeof(pkt_hdr->v6.tcp.ldr), ENC_BIG_ENDIAN);
  proto_item_append_text(ti_l4_lt, " milliseconds");

  dissector_handle_t data_handle = find_dissector("data");
  call_dissector(data_handle, tvb_new_subset_remaining(tvb, HICN_V6_TCP_HDRLEN), pinfo, tree);
  return tvb_captured_length(tvb);
}

static void
proto_register_hicn(void)
{
  static hf_register_info hf[] = {
    { &hf_hicn_ipv6_src, { "Source Address", "hicn.l3.src", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_hicn_ipv6_src_data, { "Name Prefix", "hicn.l3.src", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_hicn_ipv6_dst, { "Destination Address", "hicn.l3.dst", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_hicn_ipv6_dst_interest, { "Name Prefix", "hicn.l3.dst", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_hicn_tcp_namesuffix, { "Name Suffix", "hicn.l4.namesuffix", FT_UINT32, BASE_HEX_DEC , NULL, 0x0, NULL, HFILL }},
    { &hf_hicn_tcp_pathlabel, { "Path Label", "hicn.l4.pathlabel", FT_UINT8, BASE_HEX_DEC , NULL, 0x0, NULL, HFILL }},
    { &hf_hicn_tcp_hdrlen_timescale, { "Header length and Timescale", "hicn.l4.hdrlen_ts", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_hicn_tcp_hdrlen, { "Header length", "hicn.l4.hdrlen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_hicn_tcp_timescale, { "Timescale", "hicn.l4.timescale", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_hicn_tcp_flags, { "Flags", "hicn.l4.flags", FT_UINT8, BASE_HEX, NULL, FLAGS_MASK, NULL, HFILL }},
    { &hf_hicn_tcp_flags_cwr, { "_CWR", "hicn.l4.flags.cwr", FT_BOOLEAN, FLAGS_BITS_LEN, TFS(&tfs_set_notset), TH_CWR, NULL, HFILL }},
    { &hf_hicn_tcp_flags_id, { "ID", "hicn.l4.flags.id", FT_BOOLEAN, FLAGS_BITS_LEN, TFS(&tfs_set_notset),TH_ID, NULL, HFILL }},
    { &hf_hicn_tcp_flags_man, { "MAN", "hicn.l4.flags.man", FT_BOOLEAN, FLAGS_BITS_LEN, TFS(&tfs_set_notset), TH_MAN, NULL, HFILL }},
    { &hf_hicn_tcp_flags_ack, { "_ACK", "hicn.l4.flags.ack", FT_BOOLEAN, FLAGS_BITS_LEN, TFS(&tfs_set_notset), TH_ACK, NULL, HFILL }},
    { &hf_hicn_tcp_flags_sig, { "SIG", "hicn.l4.flags.sig", FT_BOOLEAN, FLAGS_BITS_LEN, TFS(&tfs_set_notset), TH_SIG, NULL, HFILL }},
    { &hf_hicn_tcp_flags_rst, { "_RST", "hicn.l4.flags.reset", FT_BOOLEAN, FLAGS_BITS_LEN, TFS(&tfs_set_notset), TH_RST, NULL, HFILL }},
    { &hf_hicn_tcp_flags_syn, { "_SYN", "hicn.l4.flags.syn", FT_BOOLEAN, FLAGS_BITS_LEN, TFS(&tfs_set_notset), TH_SYN, NULL, HFILL }},
    { &hf_hicn_tcp_flags_fin, { "_FIN", "hicn.l4.flags.fin", FT_BOOLEAN, FLAGS_BITS_LEN, TFS(&tfs_set_notset), TH_FIN, NULL, HFILL }},
    { &hf_hicn_tcp_ldr, { "Loss Detection and Recovery", "hicn.l4.ldr", FT_UINT16, BASE_HEX , NULL, 0x0, NULL, HFILL }},
    { &hf_hicn_tcp_csum, { "Checksum", "hicn.l4.csum", FT_UINT16, BASE_HEX , NULL, 0x0, NULL, HFILL }},
    { &hf_hicn_tcp_lifetime, { "Lifetime", "hicn.l4.lifetime", FT_UINT16, BASE_DEC , NULL, 0x0, NULL, HFILL }}
  };

  static gint *ett[] = {
    &ett_hicn,
    &ett_hicn_l3,
    &ett_hicn_l4,
    &ett_hicn_l4_flags,
  };

  proto_hicn = proto_register_protocol ("Hybrid Information-Centric Networking Protocol", "HICN", "hicn");
  proto_register_field_array(proto_hicn, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

static void
proto_reg_handoff_hicn(void)
{
  static dissector_handle_t hicn_handle;

  hicn_handle = create_dissector_handle(dissect_hicn, proto_hicn);
 
  dissector_add_uint("udp.port", HICN_PORT, hicn_handle);
  dissector_add_uint("ethertype", ETHERTYPE_IPv6, hicn_handle);

}

void plugin_register(void)
{
  static proto_plugin plug_hicn;
  plug_hicn.register_protoinfo = proto_register_hicn;
  plug_hicn.register_handoff = proto_reg_handoff_hicn;
  proto_register_plugin(&plug_hicn);
}
