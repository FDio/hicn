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

#ifndef __HICN_ERROR_H__
#define __HICN_ERROR_H__

#define foreach_hicn_error                                              \
 _(NONE, 0, "Ok")                                                       \
 _(UNSPECIFIED, -128, "Unspecified Error")                              \
 _(FACE_NOT_FOUND, -129, "Face not found in Face table")                \
 _(FACE_NULL, -130, "Face null")                                        \
 _(FACE_IP_ADJ_NOT_FOUND, -131, "Ip adjacecny for face not found")      \
 _(FACE_HW_INT_NOT_FOUND, -132, "Hardware interface not found")         \
 _(FACE_NOMEM, -133, "Face table is full")                              \
 _(FACE_NO_GLOBAL_IP, -134, "No global ip address for face")            \
 _(FACE_NOT_FOUND_IN_ENTRY, -135, "Face not found in entry")            \
 _(FACE_ALREADY_DELETED, -136, "Face alredy deleted")                   \
 _(FACE_ALREADY_CREATED, -137, "Face alredy created")                   \
 _(FWD_NOT_ENABLED, -138, "hICN forwarder not enabled")                 \
 _(FWD_ALREADY_ENABLED, -139, "hICN forwarder alredy enabled")          \
 _(PARSER_UNSUPPORTED_PROTO, -140, "Unsupported protocol")              \
 _(PARSER_PKT_INVAL, -141, "Packet null")                               \
 _(PIT_CONFIG_MINLT_OOB, -142, "Min lifetime ouf of bounds")            \
 _(PIT_CONFIG_MAXLT_OOB, -143, "Max lifetime ouf of bounds")            \
 _(PIT_CONFIG_MINMAXLT, -144, "Min lifetime grater than max lifetime")	\
 _(PIT_CONFIG_DFTLT_OOB, -145, "Default lifetime ouf of bounds")        \
 _(PIT_CONFIG_SIZE_OOB, -146, "Pit size ouf of bounds")	                \
 _(CS_CONFIG_SIZE_OOB, -147, "CS size ouf of bounds")	                \
 _(CS_CONFIG_RESERVED_OOB, -148, "Reseved CS must be between 0 and 100 (excluded)") \
 _(DPO_CTX_NHOPS_NS, -149, "No space for additional next hop")          \
 _(DPO_CTX_NHOPS_EXISTS, -150, "Next hop already in the route")         \
 _(DPO_CTX_NOT_FOUND, -151, "Dpo context not found")                    \
 _(DPO_MGR_ID_NOT_VALID, -152, "Dpo id for strategy and context not valid") \
 _(HASHTB_HASH_NOT_FOUND, -153, "Hash not found in hash table")         \
 _(HASHTB_HASH_INVAL, -154, "Error while calculating the hash")         \
 _(HASHTB_NOMEM, -155, "Unable to allocate new buckets or nodes")       \
 _(HASHTB_INVAL, -156, "Invalid argument")                              \
 _(HASHTB_KEY_INVAL, -157, "Invalid hashtb key")                        \
 _(HASHTB_EXIST, -158, "Hash already in hashtable")                     \
 _(ROUTE_INVAL, -159, "Invalid face id and weight")                     \
 _(ROUTE_NO_LD, -160, "Expected load balance dpo")                      \
 _(ROUTE_MLT_LD, -161, "Unexpected mulitple buckets in load balance dpo") \
 _(ROUTE_NO_INSERT, -162, "Unable to insert a new FIB entry")           \
 _(ROUTE_DPO_NO_HICN, -163, "Dpo is not of type hICN")                  \
 _(ROUTE_NOT_FOUND, -164, "Route not found in FIB")                     \
 _(ROUTE_NOT_UPDATED, -165, "Unable to update route")                   \
 _(ROUTE_ALREADY_EXISTS, -166, "Route already in FIB")                  \
 _(CLI_INVAL, -167, "Invalid input")                                    \
 _(IPS_ADDR_TYPE_NONUNIFORM, -168, "Src and dst addr have different ip types") \
 _(FACE_TYPE_EXISTS, -169, "Face type already registered")              \
 _(NO_BUFFERS, -170, "No vlib_buffer available for packet cloning.")    \
 _(NOT_IMPLEMENTED, -171, "Function not yet implemented")               \
 _(IFACE_IP_ADJ_NOT_FOUND, -172, "IP adjacency on incomplete face not available") \
 _(APPFACE_ALREADY_ENABLED, -173, "Application face already enabled on interface") \
 _(APPFACE_FEATURE, -174, "Error while enabling app face feature")      \
 _(APPFACE_NOT_FOUND, -175, "Application face not found")               \
 _(APPFACE_PROD_PREFIX_NULL, -176, "Prefix must not be null for producer face") \
 _(STRATEGY_NH_NOT_FOUND, -177, "Next hop not found")		        \
 _(MW_STRATEGY_SET, -178, "Error while setting weight for next hop")	\
 _(STRATEGY_NOT_FOUND, -179, "Strategy not found")                      \
 _(UDP_TUNNEL_NOT_FOUND, -180, "Udp tunnel not found")                  \
 _(UDP_TUNNEL_SRC_DST_TYPE, -181, "Src and dst addresses have different type (ipv4 and ipv6)")

typedef enum
{
#define _(a,b,c) HICN_ERROR_##a = (b),
  foreach_hicn_error
#undef _
    HICN_N_ERROR,
} hicn_error_t;

extern const char *HICN_ERROR_STRING[];

#define get_error_string(errno) (char *)(errno ? HICN_ERROR_STRING[(-errno) - 127] : HICN_ERROR_STRING[errno])

#endif /* //__HICN_ERROR_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
