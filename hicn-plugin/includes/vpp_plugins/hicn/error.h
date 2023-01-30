/*
 * Copyright (c) 2021-2023 Cisco and/or its affiliates.
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

#define PREFIX(x) HICN_ERROR_##x
#define NEXT(x)	  PREFIX (x) - 1

#define foreach_hicn_error                                                    \
  _ (NONE, 0, "Ok")                                                           \
  _ (UNSPECIFIED, -128, "Unspecified Error")                                  \
  _ (FACE_NOT_FOUND, NEXT (UNSPECIFIED), "Face not found in Face table")      \
  _ (FACE_NULL, NEXT (FACE_NOT_FOUND), "Face null")                           \
  _ (FACE_IP_ADJ_NOT_FOUND, NEXT (FACE_NULL),                                 \
     "Ip adjacecny for face not found")                                       \
  _ (FACE_HW_INT_NOT_FOUND, NEXT (FACE_IP_ADJ_NOT_FOUND),                     \
     "Hardware interface not found")                                          \
  _ (FACE_NOMEM, NEXT (FACE_HW_INT_NOT_FOUND), "Face table is full")          \
  _ (FACE_NO_GLOBAL_IP, NEXT (FACE_NOMEM), "No global ip address for face")   \
  _ (FACE_NOT_FOUND_IN_ENTRY, NEXT (FACE_NO_GLOBAL_IP),                       \
     "Face not found in entry")                                               \
  _ (FACE_NOT_VALID, NEXT (FACE_NOT_FOUND_IN_ENTRY), "Face not valid")        \
  _ (FACE_ALREADY_DELETED, NEXT (FACE_NOT_VALID), "Face alredy deleted")      \
  _ (FACE_ALREADY_CREATED, NEXT (FACE_ALREADY_DELETED),                       \
     "Face alredy created")                                                   \
  _ (FWD_NOT_ENABLED, NEXT (FACE_ALREADY_CREATED),                            \
     "hICN forwarder not enabled")                                            \
  _ (FWD_ALREADY_ENABLED, NEXT (FWD_NOT_ENABLED),                             \
     "hICN forwarder alredy enabled")                                         \
  _ (PARSER_UNSUPPORTED_PROTO, NEXT (FWD_ALREADY_ENABLED),                    \
     "Unsupported protocol")                                                  \
  _ (PARSER_PKT_INVAL, NEXT (PARSER_UNSUPPORTED_PROTO), "Packet null")        \
  _ (PARSER_MAPME_PACKET, NEXT (PARSER_PKT_INVAL), "Packet is mapme")         \
  _ (PIT_CONFIG_MINLT_OOB, NEXT (PARSER_MAPME_PACKET),                        \
     "Min lifetime ouf of bounds")                                            \
  _ (PIT_CONFIG_MAXLT_OOB, NEXT (PIT_CONFIG_MINLT_OOB),                       \
     "Max lifetime ouf of bounds")                                            \
  _ (PIT_CONFIG_MINMAXLT, NEXT (PIT_CONFIG_MAXLT_OOB),                        \
     "Min lifetime grater than max lifetime")                                 \
  _ (PIT_CONFIG_DFTLT_OOB, NEXT (PIT_CONFIG_MINMAXLT),                        \
     "Default lifetime ouf of bounds")                                        \
  _ (PIT_CONFIG_SIZE_OOB, NEXT (PIT_CONFIG_DFTLT_OOB),                        \
     "Pit size ouf of bounds")                                                \
  _ (CS_CONFIG_SIZE_OOB, NEXT (PIT_CONFIG_SIZE_OOB), "CS size ouf of bounds") \
  _ (CS_CONFIG_RESERVED_OOB, NEXT (CS_CONFIG_SIZE_OOB),                       \
     "Reseved CS must be between 0 and 100 (excluded)")                       \
  _ (DPO_CTX_NHOPS_NS, NEXT (CS_CONFIG_RESERVED_OOB),                         \
     "No space for additional next hop")                                      \
  _ (DPO_CTX_NHOPS_EXISTS, NEXT (DPO_CTX_NHOPS_NS),                           \
     "Next hop already in the route")                                         \
  _ (DPO_CTX_NOT_FOUND, NEXT (DPO_CTX_NHOPS_EXISTS), "Dpo context not found") \
  _ (DPO_MGR_ID_NOT_VALID, NEXT (DPO_CTX_NOT_FOUND),                          \
     "Dpo id for strategy and context not valid")                             \
  _ (HASHTB_HASH_NOT_FOUND, NEXT (DPO_MGR_ID_NOT_VALID),                      \
     "Hash not found in hash table")                                          \
  _ (HASHTB_HASH_INVAL, NEXT (HASHTB_HASH_NOT_FOUND),                         \
     "Error while calculating the hash")                                      \
  _ (HASHTB_NOMEM, NEXT (HASHTB_HASH_INVAL),                                  \
     "Unable to allocate new buckets or nodes")                               \
  _ (HASHTB_INVAL, NEXT (HASHTB_NOMEM), "Invalid argument")                   \
  _ (HASHTB_KEY_INVAL, NEXT (HASHTB_INVAL), "Invalid hashtb key")             \
  _ (HASHTB_EXIST, NEXT (HASHTB_KEY_INVAL), "Hash already in hashtable")      \
  _ (ROUTE_INVAL, NEXT (HASHTB_EXIST), "Invalid face id and weight")          \
  _ (ROUTE_NO_LD, NEXT (ROUTE_INVAL), "Expected load balance dpo")            \
  _ (ROUTE_MLT_LD, NEXT (ROUTE_NO_LD),                                        \
     "Unexpected mulitple buckets in load balance dpo")                       \
  _ (ROUTE_NO_INSERT, NEXT (ROUTE_MLT_LD),                                    \
     "Unable to insert a new FIB entry")                                      \
  _ (ROUTE_DPO_NO_HICN, NEXT (ROUTE_NO_INSERT), "Dpo is not of type hICN")    \
  _ (ROUTE_NOT_FOUND, NEXT (ROUTE_DPO_NO_HICN), "Route not found in FIB")     \
  _ (ROUTE_NOT_UPDATED, NEXT (ROUTE_NOT_FOUND), "Unable to update route")     \
  _ (ROUTE_ALREADY_EXISTS, NEXT (ROUTE_NOT_UPDATED), "Route already in FIB")  \
  _ (CLI_INVAL, NEXT (ROUTE_ALREADY_EXISTS), "Invalid input")                 \
  _ (IPS_ADDR_TYPE_NONUNIFORM, NEXT (CLI_INVAL),                              \
     "Src and dst addr have different ip types")                              \
  _ (FACE_TYPE_EXISTS, NEXT (IPS_ADDR_TYPE_NONUNIFORM),                       \
     "Face type already registered")                                          \
  _ (NO_BUFFERS, NEXT (FACE_TYPE_EXISTS),                                     \
     "No vlib_buffer available for packet cloning.")                          \
  _ (NOT_IMPLEMENTED, NEXT (NO_BUFFERS), "Function not yet implemented")      \
  _ (IFACE_IP_ADJ_NOT_FOUND, NEXT (NOT_IMPLEMENTED),                          \
     "IP adjacency on incomplete face not available")                         \
  _ (APPFACE_ALREADY_ENABLED, NEXT (IFACE_IP_ADJ_NOT_FOUND),                  \
     "Application face already enabled on interface")                         \
  _ (APPFACE_FEATURE, NEXT (APPFACE_ALREADY_ENABLED),                         \
     "Error while enabling app face feature")                                 \
  _ (APPFACE_NOT_FOUND, NEXT (APPFACE_FEATURE), "Application face not found") \
  _ (APPFACE_PROD_PREFIX_NULL, NEXT (APPFACE_NOT_FOUND),                      \
     "Prefix must not be null for producer face")                             \
  _ (STRATEGY_NH_NOT_FOUND, NEXT (APPFACE_PROD_PREFIX_NULL),                  \
     "Next hop not found")                                                    \
  _ (MW_STRATEGY_SET, NEXT (STRATEGY_NH_NOT_FOUND),                           \
     "Error while setting weight for next hop")                               \
  _ (STRATEGY_NOT_FOUND, NEXT (MW_STRATEGY_SET), "Strategy not found")        \
  _ (UDP_TUNNEL_NOT_FOUND, NEXT (STRATEGY_NOT_FOUND), "Udp tunnel not found") \
  _ (UDP_TUNNEL_SRC_DST_TYPE, NEXT (UDP_TUNNEL_NOT_FOUND),                    \
     "Src and dst addresses have different type (ipv4 and ipv6)")             \
  _ (MAPME_NEXT_HOP_ADDED, NEXT (UDP_TUNNEL_SRC_DST_TYPE),                    \
     "Next hop added to mapme")                                               \
  _ (MAPME_NEXT_HOP_NOT_ADDED, NEXT (MAPME_NEXT_HOP_ADDED),                   \
     "Next hop added to mapme")                                               \
  _ (PCS_NOT_FOUND, NEXT (MAPME_NEXT_HOP_NOT_ADDED),                          \
     "Hash not found in hash table")                                          \
  _ (PCS_HASH_INVAL, NEXT (PCS_NOT_FOUND),                                    \
     "Error while calculating the hash")                                      \
  _ (PCS_INVAL, NEXT (PCS_HASH_INVAL), "Invalid argument")                    \
  _ (PCS_KEY_INVAL, NEXT (PCS_INVAL), "Invalid hashtb key")                   \
  _ (PCS_EXIST, NEXT (PCS_KEY_INVAL), "Hash already in hashtable")

typedef enum
{
#define _(a, b, c) PREFIX (a) = (b),
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
