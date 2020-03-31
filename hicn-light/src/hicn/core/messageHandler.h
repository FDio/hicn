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

#ifndef messageHandler
#define messageHandler

#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h> // close
#endif /* _WIN32 */

#include <hicn/hicn.h>
#include <hicn/core/messagePacketType.h>

//#include <hicn/core/connection_table.h>

#define H(packet) ((hicn_header_t *)packet)
#define H6(packet) (H(packet)->v6.ip)
#define H6T(packet) (H(packet)->v6.tcp)
#define H4(packet) (H(packet)->v4.ip)
#define H4T(packet) (H(packet)->v4.tcp)

#define HICN_V6_LEN(packet) (H6(packet).len)
#define HICN_V4_LEN(packet) (H4(packet).len)

/*** codes and types ***/
#define IPv6_TYPE 6
#define IPv4_TYPE 4
#define ICMP_WLDR_TYPE 42
#define ICMP_WLDR_CODE 0
#define ICMP_LB_TYPE 43

/*** masks and constants ***/
#define PATH_LABEL_MASK 0x8000      // 1000 0000 0000 0000
#define NOT_PATH_LABEL_MASK 0x7fff  // 0111 0000 0000 0000
#define UINT16_T_MASK 0x0000ffff    // 1111 1111 1111 1111

/*** HICN ALLOWED PORTS ***/
#define CONTROL_PORT 9695
#define HTTP_PORT 8080

#define IPV6_DEFAULT_VERSION 6
#define IPV6_DEFAULT_TRAFFIC_CLASS 0
#define IPV6_DEFAULT_FLOW_LABEL 0

//#include <hicn/core/forwarder.h>

//#ifdef WITH_MAPME
//#include <hicn/core/mapme.h>
//#include <hicn/socket/api.h>
//#endif /* WITH_MAPME */

#define BFD_PORT 3784

static inline uint8_t messageHandler_GetIPPacketType(const uint8_t *message) {
  return HICN_IP_VERSION(message);
}

static inline void messageHandler_UpdateTCPCheckSum(uint8_t *message,
                                                    uint16_t *old_val,
                                                    uint16_t *new_val,
                                                    uint8_t size) {
  switch (messageHandler_GetIPPacketType(message)) {
    case IPv4_TYPE:
      for (uint8_t i = 0; i < size; i++) {
        uint16_t old_csum = ~(H4T(message).csum);
        uint16_t not_old_val = ~(*old_val);
        uint32_t sum = (uint32_t)old_csum + not_old_val + *new_val;

        while (sum >> 16) {
          sum = (sum >> 16) + (sum & UINT16_T_MASK);
        }

        H4T(message).csum = ~sum;
        ++old_val;
        ++new_val;
      }
      break;
    case IPv6_TYPE:
      for (uint8_t i = 0; i < size; i++) {
        uint16_t old_csum = ~(H6T(message).csum);
        uint16_t not_old_val = ~(*old_val);
        uint32_t sum = (uint32_t)old_csum + not_old_val + *new_val;

        while (sum >> 16) {
          sum = (sum >> 16) + (sum & UINT16_T_MASK);
        }

        H6T(message).csum = ~sum;
        ++old_val;
        ++new_val;
      }
      break;
    default:
      return;
  }
}

static inline void messageHandler_UpdateIPv4CheckSum(uint8_t *message,
                                                     uint16_t *old_val,
                                                     uint16_t *new_val,
                                                     uint8_t size) {
  for (uint8_t i = 0; i < size; i++) {
    uint16_t old_csum = ~(H4(message).csum);
    uint16_t not_old_val = ~(*old_val);
    uint32_t sum = (uint32_t)old_csum + not_old_val + *new_val;

    while (sum >> 16) {
      sum = (sum >> 16) + (sum & UINT16_T_MASK);
    }

    H4(message).csum = ~sum;
    ++old_val;
    ++new_val;
  }
}

static inline size_t messageHandler_GetEmptyTCPPacketSize(unsigned ipVersion) {
  if (ipVersion == IPv4_TYPE)
    return IPV4_HDRLEN + TCP_HDRLEN;
  else if (ipVersion == IPv6_TYPE)
    return IPV6_HDRLEN + TCP_HDRLEN;
  else
    return 0;
}

static inline size_t messageHandler_GetICMPPacketSize(unsigned ipVersion) {
  if (ipVersion == IPv4_TYPE)
    return IPV4_HDRLEN + ICMP_HDRLEN;
  else if (ipVersion == IPv6_TYPE)
    return IPV6_HDRLEN + ICMP_HDRLEN;
  else
    return 0;
}

static inline size_t messageHandler_GetIPHeaderLength(unsigned ipVersion) {
  if (ipVersion == IPv4_TYPE)
    return IPV4_HDRLEN;
  else if (ipVersion == IPv6_TYPE)
    return IPV6_HDRLEN;
  else
    return 0;
}

#if 0
static inline bool messageHandler_IsValidHicnPacket(const uint8_t *message) {
  uint8_t version = messageHandler_GetIPPacketType(message);
  if (version == IPv6_TYPE || version == IPv4_TYPE) {
    return true;
  }
  return false;
}
#endif

static inline uint8_t messageHandler_NextHeaderType(const uint8_t *message) {
  switch (messageHandler_GetIPPacketType(message)) {
    case IPv6_TYPE:
      return (uint8_t)H6(message).nxt;
    case IPv4_TYPE:
      return (uint8_t)H4(message).protocol;
    default:
      return 0;
  }
}

static inline bool messageHandler_IsTCP(const uint8_t *message) {
  if (messageHandler_NextHeaderType(message) != IPPROTO_TCP) return false;
  return true;
}

static inline bool messageHandler_IsInterest(const uint8_t *message) {
  if (!messageHandler_IsTCP(message)) return false;

  bool flag;
  hicn_packet_test_ece((hicn_header_t *)message,
                       &flag);  // ECE flag is set to 0 in interest packets
  if (flag == false) return true;
  return false;
}

static inline bool messageHandler_IsData(const uint8_t *message) {
  if (!messageHandler_IsTCP(message)) return false;

  bool flag;
  hicn_packet_test_ece((hicn_header_t *)message,
                       &flag);  // ECE flag is set to 1 in data packets
  if (flag == true) return true;
  return false;
}

static inline bool messageHandler_IsWldrNotification(const uint8_t *message) {
  // this function returns true only if the packet is an ICMP packet in Wldr
  // form. type must be equal to ICMP_WLDR_TYPE and code equal to ICMP_WLDR_CODE
  uint8_t next_header = messageHandler_NextHeaderType(message);

  const uint8_t *icmp_ptr;
  if (next_header == IPPROTO_ICMP) {
    icmp_ptr = message + IPV4_HDRLEN;
  } else if (next_header == IPPROTO_ICMPV6) {
    icmp_ptr = message + IPV6_HDRLEN;
  } else {
    return false;
  }

  uint8_t type = ((_icmp_header_t *)icmp_ptr)->type;
  uint8_t code = ((_icmp_header_t *)icmp_ptr)->code;
  if (type == ICMP_WLDR_TYPE && code == ICMP_WLDR_CODE) {
    return true;
  }

  return false;
}

static inline bool messageHandler_IsLoadBalancerProbe(const uint8_t *message) {
  uint8_t next_header = messageHandler_NextHeaderType(message);

  const uint8_t *icmp_ptr;
  if (next_header == IPPROTO_ICMP) {
    icmp_ptr = message + IPV4_HDRLEN;
  } else if (next_header == IPPROTO_ICMPV6) {
    icmp_ptr = message + IPV6_HDRLEN;
  } else {
    return false;
  }

  uint8_t type = ((_icmp_header_t *)icmp_ptr)->type;
  if (type == ICMP_LB_TYPE) {
    return true;
  }

  return false;
}

static inline uint16_t messageHandler_GetTotalPacketLength(
    const uint8_t *message) {
  switch (messageHandler_GetIPPacketType(message)) {
    case IPv6_TYPE:
      return ntohs((uint16_t)HICN_V6_LEN(message)) + IPV6_HDRLEN;
    case IPv4_TYPE:
      return ntohs((uint16_t)HICN_V4_LEN(message));
    default:
      return 0;
  }
}

static inline uint32_t messageHandler_GetSegment(const uint8_t *message) {
  if (!messageHandler_IsTCP(message)) return 0;

  switch (messageHandler_GetIPPacketType(message)) {
    case IPv6_TYPE:
      return ntohl((uint32_t)H6T(message).seq);
    case IPv4_TYPE:
      return ntohl((uint32_t)H4T(message).seq);
    default:
      return 0;
  }
}

static inline uint16_t messageHandler_GetExpectedWldrLabel(
    const uint8_t *message) {
  const uint8_t *icmp_ptr;
  switch (messageHandler_GetIPPacketType(message)) {
    case IPv6_TYPE:
      icmp_ptr = message + IPV6_HDRLEN;
      break;
    case IPv4_TYPE:
      icmp_ptr = message + IPV4_HDRLEN;
      break;
    default:
      return 0;
  }

  return ntohs(((_icmp_wldr_header_t *)icmp_ptr)->wldr_notification_lbl.expected_lbl);
}

static inline uint16_t messageHandler_GetWldrLastReceived(
    const uint8_t *message) {
  const uint8_t *icmp_ptr;
  switch (messageHandler_GetIPPacketType(message)) {
    case IPv6_TYPE:
      icmp_ptr = message + IPV6_HDRLEN;
      break;
    case IPv4_TYPE:
      icmp_ptr = message + IPV4_HDRLEN;
      break;
    default:
      return 0;
  }

  return ntohs(((_icmp_wldr_header_t *)icmp_ptr)->wldr_notification_lbl.received_lbl);
}

static inline uint16_t messageHandler_GetWldrLabel(const uint8_t *message) {
  switch (messageHandler_GetIPPacketType(message)) {
    case IPv6_TYPE:
      return ntohs((uint16_t)H6T(message).window);
    case IPv4_TYPE:
      return ntohs((uint16_t)H4T(message).window);
    default:
      return 0;
  }
}

static inline void messageHandler_SetWldrLabel(uint8_t *message,
                                               uint16_t label) {
  uint16_t old_val = messageHandler_GetWldrLabel(message);

  switch (messageHandler_GetIPPacketType(message)) {
    case IPv6_TYPE:
      H6T(message).window = htons(label);
      break;
    case IPv4_TYPE:
      H4T(message).window = htons(label);
      break;
    default:
      break;
  }

  messageHandler_UpdateTCPCheckSum(message, &old_val, &label, 1);
}

static inline void messageHandler_ResetWldrLabel(uint8_t *message) {
  messageHandler_SetWldrLabel(message, 0);
}

static inline bool messageHandler_HasWldr(const uint8_t *message) {
  if (messageHandler_IsTCP(message)) {
    uint16_t lbl = messageHandler_GetWldrLabel(message);
    if (lbl != 0) {
      return true;
    }
  }
  return false;
}

static inline uint32_t messageHandler_GetPathLabel(const uint8_t *message) {
  if (!messageHandler_IsTCP(message)) return 0;

  uint32_t path_label;
  int res = hicn_data_get_path_label((hicn_header_t *)message, &path_label);
  if (res < 0) return 0;
  return path_label;
}

static inline void messageHandler_SetPathLabel(uint8_t *message,
                                               uint32_t new_path_label) {
  if (!messageHandler_IsTCP(message)) return;

  uint32_t old_path_label;
  int res = hicn_data_get_path_label((hicn_header_t *)message, &old_path_label);
  if (res < 0) return;

  hicn_data_set_path_label((hicn_header_t *)message, new_path_label);

  messageHandler_UpdateTCPCheckSum(message, (uint16_t *)&old_path_label,
                                   (uint16_t *)&new_path_label, 2);
}

static inline void messageHandler_UpdatePathLabel(uint8_t *message,
                                                  uint8_t outFace) {
  if (!messageHandler_IsTCP(message)) return;

  uint32_t pl_old_32bit = messageHandler_GetPathLabel(message);
  uint8_t pl_old_8bit = (uint8_t)(pl_old_32bit >> 24UL);
  uint32_t pl_new_32bit =
      (uint32_t)((((pl_old_8bit << 1) | (pl_old_8bit >> 7)) ^ outFace) << 24UL);

  hicn_data_set_path_label((hicn_header_t *)message, pl_new_32bit);

  messageHandler_UpdateTCPCheckSum(message, (uint16_t *)&pl_old_32bit,
                                   (uint16_t *)&pl_new_32bit, 2);
}

static inline void messageHandler_ResetPathLabel(uint8_t *message) {
  if (!messageHandler_IsTCP(message)) return;

  uint32_t pl_old_32bit = messageHandler_GetPathLabel(message);
  uint32_t pl_new_32bit = 0;
  hicn_data_set_path_label((hicn_header_t *)message, pl_new_32bit);
  messageHandler_UpdateTCPCheckSum(message, (uint16_t *)&pl_old_32bit,
                                   (uint16_t *)&pl_new_32bit, 2);
}

static inline uint16_t messageHandler_GetInterestLifetime(
    const uint8_t *message) {
  if (!messageHandler_IsTCP(message)) return 0;

  hicn_lifetime_t lifetime;
  int res = hicn_interest_get_lifetime((hicn_header_t *)message, &lifetime);
  if (res < 0) return 0;
  return lifetime;
}

static inline bool messageHandler_HasInterestLifetime(const uint8_t *message) {
  if (!messageHandler_IsTCP(message)) return false;

  if (messageHandler_GetInterestLifetime(message) == 0) return false;
  return true;
}

static inline uint32_t messageHandler_GetContentExpiryTime(
    const uint8_t *message) {
  if (!messageHandler_IsTCP(message)) return 0;

  uint32_t expirationTime;
  int res =
      hicn_data_get_expiry_time((hicn_header_t *)message, &expirationTime);
  if (res < 0) return 0;
  return expirationTime;
}

static inline bool messageHandler_HasContentExpiryTime(const uint8_t *message) {
  if (!messageHandler_IsTCP(message)) return 0;

  uint32_t expirationTime;
  int res =
      hicn_data_get_expiry_time((hicn_header_t *)message, &expirationTime);
  if (res < 0) return false;

  if (expirationTime == HICN_MAX_LIFETIME) return false;

  return true;
}

static inline void *messageHandler_GetSource(const uint8_t *message) {
  switch (messageHandler_GetIPPacketType(message)) {
    case IPv6_TYPE:
      return &H6(message).saddr;
      break;
    case IPv4_TYPE:
      return &H4(message).saddr;
      break;
    default:
      return NULL;
  }
}

static inline void *messageHandler_GetDestination(const uint8_t *message) {
  switch (messageHandler_GetIPPacketType(message)) {
    case IPv6_TYPE:
      return &H6(message).daddr;
      break;
    case IPv4_TYPE:
      return &H4(message).daddr;
      break;
    default:
      return NULL;
  }
}

static inline void messageHandler_SetSource_IPv6(uint8_t *message,
                                                 struct in6_addr *address) {
  if (messageHandler_IsTCP(message)) {
    uint16_t *old_src = (uint16_t *)messageHandler_GetSource(message);
    messageHandler_UpdateTCPCheckSum(message, old_src, (uint16_t *)address, 8);
  }
  H6(message).saddr.as_in6addr = *address;
}

static inline void messageHandler_SetDestination_IPv6(
    uint8_t *message, struct in6_addr *address) {
  if (messageHandler_IsTCP(message)) {
    uint16_t *old_dst = (uint16_t *)messageHandler_GetDestination(message);
    messageHandler_UpdateTCPCheckSum(message, old_dst, (uint16_t *)address, 8);
  }
  H6(message).daddr.as_in6addr = *address;
}

static inline void messageHandler_SetSource_IPv4(uint8_t *message,
                                                 uint32_t *address) {
  // update tcp checksum
  uint16_t *old_src = (uint16_t *)messageHandler_GetSource(message);
  if (messageHandler_IsTCP(message)) {
    messageHandler_UpdateTCPCheckSum(message, old_src, (uint16_t *)address, 2);
  }
  // update IPv4 cheksum
  // the IPv4 checksum is not part of the psudo header for TCP checksum
  // calculation we can update them separetelly
  messageHandler_UpdateIPv4CheckSum(message, old_src, (uint16_t *)address, 2);

  H4(message).saddr.as_u32 = *address;
}

static inline void messageHandler_SetDestination_IPv4(uint8_t *message,
                                                      uint32_t *address) {
  uint16_t *old_dst = (uint16_t *)messageHandler_GetDestination(message);
  if (messageHandler_IsTCP(message)) {
    messageHandler_UpdateTCPCheckSum(message, old_dst, (uint16_t *)address, 2);
  }
  messageHandler_UpdateIPv4CheckSum(message, old_dst, (uint16_t *)address, 2);
  H4(message).daddr.as_u32 = *address;
}

static inline void messageHandler_SetWldrNotification(uint8_t *notification,
                                                      uint8_t *original,
                                                      uint16_t expected,
                                                      uint16_t received) {
  hicn_header_t *h = (hicn_header_t *)notification;
  switch (messageHandler_GetIPPacketType(original)) {
    case IPv6_TYPE: {
      *h = (hicn_header_t){
        .v6 = {
          .ip =
              {
                  .version_class_flow = htonl(
                      (IPV6_DEFAULT_VERSION << 28) |
                      (IPV6_DEFAULT_TRAFFIC_CLASS << 20) |
                      (IPV6_DEFAULT_FLOW_LABEL & 0xfffff)),
                  .len = htons(ICMP_HDRLEN),
                  .nxt = IPPROTO_ICMPV6,
                  .hlim = 5,
              },
          .wldr =
              {
                  .type = ICMP_WLDR_TYPE,
                  .code = ICMP_WLDR_CODE,
                  .wldr_notification_lbl = {
                      .expected_lbl = htons(expected),
                      .received_lbl = htons(received),
                  },
              },
        }};
      messageHandler_SetSource_IPv6(
          notification,
          (struct in6_addr *)messageHandler_GetDestination(original));
      messageHandler_SetDestination_IPv6(
          notification, (struct in6_addr *)messageHandler_GetSource(original));
      break;
    }
    case IPv4_TYPE: {
      break;
    }
    default:
      break;
  }
}

static inline uint8_t * messageHandler_CreateProbePacket(hicn_format_t format,
    uint32_t probe_lifetime){
  size_t header_length;
  hicn_packet_get_header_length_from_format(format, &header_length);

  uint8_t *pkt = calloc(header_length, 1);

  hicn_packet_init_header(format, (hicn_header_t *) pkt);

  hicn_packet_set_dst_port((hicn_header_t *) pkt, BFD_PORT);
  hicn_interest_set_lifetime ((hicn_header_t *) pkt, probe_lifetime);

  return pkt;
}

static inline void messageHandler_CreateProbeReply(uint8_t * probe,
                                                      hicn_format_t format){

  hicn_name_t probe_name;
  hicn_interest_get_name (format,
          (const hicn_header_t *) probe, &probe_name);
  ip_address_t probe_locator;
  hicn_interest_get_locator (format,
             (const hicn_header_t *) probe, &probe_locator);

  uint16_t src_prt;
  uint16_t dst_prt;
  hicn_packet_get_src_port((const hicn_header_t *) probe, &src_prt);
  hicn_packet_get_dst_port((const hicn_header_t *) probe, &dst_prt);
  hicn_packet_set_src_port((hicn_header_t *) probe, dst_prt);
  hicn_packet_set_dst_port((hicn_header_t *) probe, src_prt);

  hicn_data_set_name (format, (hicn_header_t *) probe, &probe_name);
  hicn_data_set_locator (format, (hicn_header_t *) probe, &probe_locator);
  hicn_data_set_expiry_time ((hicn_header_t *) probe, 0);
}

static inline hicn_name_t * messageHandler_CreateProbeName(const ip_prefix_t *address){
  hicn_name_t * name = calloc(sizeof(hicn_name_t), 1);
  hicn_name_create_from_ip_prefix(address, 0, name);
  return name;
}

static inline void messageHandler_SetProbeName(uint8_t * probe, hicn_format_t format,
                                               hicn_name_t * name, uint32_t seq){
  hicn_name_set_seq_number (name, seq);
  hicn_interest_set_name(format, (hicn_header_t *) probe, name);
}

static inline bool messageHandler_IsAProbe(const uint8_t *packet){
  uint16_t src_prt;
  uint16_t dst_prt;
  hicn_packet_get_src_port ((const hicn_header_t *) packet, &src_prt);
  hicn_packet_get_dst_port ((const hicn_header_t *) packet, &dst_prt);

  if(dst_prt == BFD_PORT){
    //interest probe
    return true;
  }

  if(src_prt == BFD_PORT){
    //data (could be a probe)
    uint32_t expiry_time;
    hicn_data_get_expiry_time ((const hicn_header_t *) packet, &expiry_time);
    if(expiry_time == 0){
      //this is a probe
      return true;
    }
  }

  return false;
}

#endif  // Metis_metis_MessageHandler
