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

#ifndef __HICN_ERROR_H__
#define __HICN_ERROR_H__

/**
 * @file error.h
 *
 * Error codes for the hICN plugin.
 */

#define foreach_hicn_error                                                    \
  _ (NONE, 0, "Ok")                                                           \
  _ (UNSPECIFIED, -128, "Unspecified Error")                                  \
  _ (FACE_NOT_FOUND, -1000, "Face not found in Face table")                   \
  _ (FACE_NULL, -1001, "Face null")                                           \
  _ (FACE_IP_ADJ_NOT_FOUND, -1002, "Ip adjacecny for face not found")         \
  _ (FACE_HW_INT_NOT_FOUND, -1003, "Hardware interface not found")            \
  _ (FACE_NOMEM, -1004, "Face table is full")                                 \
  _ (FACE_NO_GLOBAL_IP, -1005, "No global ip address for face")               \
  _ (FACE_NOT_FOUND_IN_ENTRY, -1006, "Face not found in entry")               \
  _ (FACE_ALREADY_DELETED, -1007, "Face alredy deleted")                      \
  _ (FACE_ALREADY_CREATED, -1008, "Face alredy created")                      \
  _ (FWD_NOT_ENABLED, -2000, "hICN forwarder not enabled")                    \
  _ (FWD_ALREADY_ENABLED, -2001, "hICN forwarder alredy enabled")             \
  _ (PARSER_UNSUPPORTED_PROTO, -3000, "Unsupported protocol")                 \
  _ (PARSER_PKT_INVAL, -3001, "Packet null")                                  \
  _ (PARSER_MAPME_PACKET, -3002, "Packet is mapme")                           \
  _ (PIT_CONFIG_MINLT_OOB, -4000, "Min lifetime ouf of bounds")               \
  _ (PIT_CONFIG_MAXLT_OOB, -4001, "Max lifetime ouf of bounds")               \
  _ (PIT_CONFIG_MINMAXLT, -4002, "Min lifetime grater than max lifetime")     \
  _ (PIT_CONFIG_DFTLT_OOB, -4003, "Default lifetime ouf of bounds")           \
  _ (PIT_CONFIG_SIZE_OOB, -4004, "Pit size ouf of bounds")                    \
  _ (CS_CONFIG_SIZE_OOB, -5000, "CS size ouf of bounds")                      \
  _ (CS_CONFIG_RESERVED_OOB, -5001,                                           \
     "Reseved CS must be between 0 and 100 (excluded)")                       \
  _ (DPO_CTX_NHOPS_NS, -6000, "No space for additional next hop")             \
  _ (DPO_CTX_NHOPS_EXISTS, -6001, "Next hop already in the route")            \
  _ (DPO_CTX_NOT_FOUND, -6002, "Dpo context not found")                       \
  _ (DPO_MGR_ID_NOT_VALID, -6003,                                             \
     "Dpo id for strategy and context not valid")                             \
  _ (HASHTB_HASH_NOT_FOUND, -7000, "Hash not found in hash table")            \
  _ (HASHTB_HASH_INVAL, -7001, "Error while calculating the hash")            \
  _ (HASHTB_NOMEM, -7002, "Unable to allocate new buckets or nodes")          \
  _ (HASHTB_INVAL, -7003, "Invalid argument")                                 \
  _ (HASHTB_KEY_INVAL, -7004, "Invalid hashtb key")                           \
  _ (HASHTB_EXIST, -7005, "Hash already in hashtable")                        \
  _ (ROUTE_INVAL, -8000, "Invalid face id and weight")                        \
  _ (ROUTE_NO_LD, -8001, "Expected load balance dpo")                         \
  _ (ROUTE_MLT_LD, -8002, "Unexpected mulitple buckets in load balance dpo")  \
  _ (ROUTE_NO_INSERT, -8003, "Unable to insert a new FIB entry")              \
  _ (ROUTE_DPO_NO_HICN, -8004, "Dpo is not of type hICN")                     \
  _ (ROUTE_NOT_FOUND, -8005, "Route not found in FIB")                        \
  _ (ROUTE_NOT_UPDATED, -8006, "Unable to update route")                      \
  _ (ROUTE_ALREADY_EXISTS, -8007, "Route already in FIB")                     \
  _ (CLI_INVAL, -9000, "Invalid input")                                       \
  _ (IPS_ADDR_TYPE_NONUNIFORM, -10000,                                        \
     "Src and dst addr have different ip types")                              \
  _ (FACE_TYPE_EXISTS, -11000, "Face type already registered")                \
  _ (NO_BUFFERS, -12000, "No vlib_buffer available for packet cloning.")      \
  _ (NOT_IMPLEMENTED, -13000, "Function not yet implemented")                 \
  _ (IFACE_IP_ADJ_NOT_FOUND, -14000,                                          \
     "IP adjacency on incomplete face not available")                         \
  _ (APPFACE_ALREADY_ENABLED, -15000,                                         \
     "Application face already enabled on interface")                         \
  _ (APPFACE_FEATURE, -15001, "Error while enabling app face feature")        \
  _ (APPFACE_NOT_FOUND, -15002, "Application face not found")                 \
  _ (APPFACE_PROD_PREFIX_NULL, -15003,                                        \
     "Prefix must not be null for producer face")                             \
  _ (STRATEGY_NH_NOT_FOUND, -16000, "Next hop not found")                     \
  _ (MW_STRATEGY_SET, -16001, "Error while setting weight for next hop")      \
  _ (STRATEGY_NOT_FOUND, -16002, "Strategy not found")                        \
  _ (UDP_TUNNEL_NOT_FOUND, -17000, "Udp tunnel not found")                    \
  _ (UDP_TUNNEL_SRC_DST_TYPE, -17001,                                         \
     "Src and dst addresses have different type (ipv4 and ipv6)")             \
  _ (MAPME_NEXT_HOP_ADDED, -18000, "Next hop added to mapme")                 \
  _ (MAPME_NEXT_HOP_NOT_ADDED, -18001, "Next hop added to mapme")

typedef enum
{
#define _(a, b, c) HICN_ERROR_##a = (b),
  foreach_hicn_error
#undef _
    HICN_N_ERROR,
} hicn_error_t;

extern const char *HICN_ERROR_STRING[];

#define get_error_string(errno)                                               \
  (char *) (errno ? HICN_ERROR_STRING[(-errno) - 127] :                       \
			  HICN_ERROR_STRING[errno])

#endif /* //__HICN_ERROR_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
