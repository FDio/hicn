/*
* Copyright (c) 2019-2020 Cisco and/or its affiliates.
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



/** @file hicn_model.c
 *  @brief This file contains implementations of the main calls
 */


#define _GNU_SOURCE

#include <stdio.h>
#include <malloc.h>
#include <sysrepo/xpath.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>



#include <sched.h>
/* Hicn headers */

#include <hicn/util/ip_address.h>
#include "../hicn_plugin.h"
#include "../hicn_vpp_comm.h"
#include "hicn_model.h"
#include "tlock.h"


DEFINE_VAPI_MSG_IDS_HICN_API_JSON


// Shared local variables between state and RPCs

/**
 * @brief this shared variable keeps the hicn state
 */
volatile hicn_state_t  * hicn_state = NULL;
/**
 * @brief  this shared variable keeps hicn strategies
 */
volatile hicn_strategies_t * hicn_strategies =NULL;
/**
 * @brief this shared variable keeps  statistics of hicn faces
 */
volatile hicn_faces_t *  hicn_faces = NULL;
/**
 * @brief this shared variable keeps routes information in hicn
 */
volatile hicn_routes_t *  hicn_routes = NULL;
/**
 * @brief this shared variable is the link list to maintain all the faces (up to MAX_FACES)
 */
struct hicn_faces_s * fcurrent = NULL;
/**
 * @brief this shared variable is the link list to maintain all the routes
 */
struct hicn_routes_s * rcurrent = NULL;


static int init_buffer(void){

 hicn_state = memalign(MEM_ALIGN, sizeof(hicn_state_t) );
 memset((hicn_state_t *)hicn_state, 0 , sizeof(hicn_state_t) );

 hicn_strategies = memalign(MEM_ALIGN, sizeof(hicn_strategies_t) );
 memset((hicn_strategies_t *) hicn_strategies, 0 , sizeof(hicn_strategies_t) );

 hicn_faces = memalign(MEM_ALIGN, sizeof(hicn_faces_t) );
 hicn_faces->next=memalign(MEM_ALIGN, sizeof(struct hicn_faces_s));
 fcurrent=hicn_faces->next;


 hicn_routes = memalign(MEM_ALIGN, sizeof(hicn_routes_t) );
 hicn_routes->next=memalign(MEM_ALIGN, sizeof(struct hicn_routes_s));
 rcurrent=hicn_routes->next;


 int retval=-1;
 ARG_CHECK5(retval, hicn_state, hicn_strategies, fcurrent, hicn_faces, hicn_routes);
 hicn_routes->nroute=0;
 hicn_faces->nface=0;
 retval=0;

 return retval;
}

static int init_face_pool(struct hicn_faces_s * head){

 for(int i=0; i<MAX_FACE_POOL; i++){
     head->next=memalign(MEM_ALIGN, sizeof(struct hicn_faces_s));
     head=head->next;
 }
 SRP_LOG_DBGMSG("Face memory pool allocated\n");
 head->next=NULL;
 return 0;

}

static int init_route_pool(struct hicn_routes_s * head){

 for(int i=0; i<MAX_ROUTE_POOL; i++){
     head->next=memalign(MEM_ALIGN, sizeof(struct hicn_routes_s));
     head=head->next;
 }
 SRP_LOG_DBGMSG("Route memory pool allocated\n");
 head->next=NULL;
 return 0;

}

/* VAPI CALLBACKS */

static vapi_error_e call_hicn_api_strategies_get(struct vapi_ctx_s *ctx,
                           void *callback_ctx,
                           vapi_error_e rv,
                           bool is_last,
                           vapi_payload_hicn_api_strategies_get_reply *reply){
if(!reply->retval){
  SRP_LOG_DBGMSG("Successfully done");
  return VAPI_OK;
 }else
  return VAPI_EUSER;
}

static vapi_error_e call_hicn_api_route_nhops_add(struct vapi_ctx_s *ctx,
                           void *callback_ctx,
                           vapi_error_e rv,
                           bool is_last,
                           vapi_payload_hicn_api_route_nhops_add_reply *reply){
if(!reply->retval){
  SRP_LOG_DBGMSG("Successfully done");
  return VAPI_OK;
 }else
  return VAPI_EUSER;
}

static vapi_error_e call_hicn_api_route_del(struct vapi_ctx_s *ctx,
                           void *callback_ctx,
                           vapi_error_e rv,
                           bool is_last,
                           vapi_payload_hicn_api_route_del_reply *reply){

if(!reply->retval){
  SRP_LOG_DBGMSG("Successfully done");
  return VAPI_OK;
 }else
  return VAPI_EUSER;
}

static vapi_error_e call_hicn_api_face_params_get(struct vapi_ctx_s *ctx,
                           void *callback_ctx,
                           vapi_error_e rv,
                           bool is_last,
                           vapi_payload_hicn_api_face_params_get_reply *reply){
if(!reply->retval){
  if (callback_ctx!=NULL){
      struct hicn_faces_s * tmp;
      tmp = (struct hicn_faces_s *) callback_ctx;
      tmp->face.intfc = reply->swif;
  }
  return VAPI_OK;
 }else
  return VAPI_EUSER;
}

static vapi_error_e call_hicn_api_route_nhop_del(struct vapi_ctx_s *ctx,
                           void *callback_ctx,
                           vapi_error_e rv,
                           bool is_last,
                           vapi_payload_hicn_api_route_nhop_del_reply *reply){
if(!reply->retval){
  SRP_LOG_DBGMSG("Successfully done");
  return VAPI_OK;
 }else
  return VAPI_EUSER;
}

static vapi_error_e call_vapi_hicn_api_node_stats_get(struct vapi_ctx_s *ctx,
                           void *callback_ctx,
                           vapi_error_e rv,
                           bool is_last,
                           vapi_payload_hicn_api_node_stats_get_reply *reply){


if(!reply->retval){
   hicn_state->pkts_processed = reply->pkts_processed;
   hicn_state->pkts_interest_count = reply->pkts_interest_count;
   hicn_state->pkts_data_count = reply->pkts_data_count;
   hicn_state->pkts_from_cache_count = reply->pkts_from_cache_count;
   hicn_state->pkts_no_pit_count = reply->pkts_no_pit_count;
   hicn_state->pit_expired_count = reply->pit_expired_count;
   hicn_state->cs_expired_count = reply->cs_expired_count;
   hicn_state->cs_lru_count = reply->cs_lru_count;
   hicn_state->pkts_drop_no_buf = reply->pkts_drop_no_buf;
   hicn_state->interests_aggregated = reply->interests_aggregated;
   hicn_state->interests_retx = reply->interests_retx;
   hicn_state->pit_entries_count = reply->pit_entries_count;
   hicn_state->cs_entries_count = reply->cs_entries_count;
   hicn_state->cs_entries_ntw_count = reply->cs_entries_ntw_count;
   return VAPI_OK;
 }else
   return VAPI_EUSER;
}

static inline void  state_update(sr_val_t * vals, struct lyd_node **parent, sr_session_ctx_t *session){
 char buf[20];

 sr_val_set_xpath(&vals[0], "/hicn:hicn-state/states/pkts_processed");
 vals[0].type = SR_UINT64_T;
 vals[0].data.uint64_val = hicn_state->pkts_processed;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64, hicn_state->pkts_processed);
 * parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(session)), vals[0].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[1], "/hicn:hicn-state/states/pkts_interest_count");
 vals[1].type = SR_UINT64_T;
 vals[1].data.uint64_val = hicn_state->pkts_interest_count;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64, hicn_state->pkts_interest_count );
 lyd_new_path(*parent, NULL, vals[1].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[2], "/hicn:hicn-state/states/pkts_data_count");
 vals[2].type = SR_UINT64_T;
 vals[2].data.uint64_val = hicn_state->pkts_data_count;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64, hicn_state->pkts_data_count );
 lyd_new_path(*parent, NULL, vals[2].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[3], "/hicn:hicn-state/states/pkts_from_cache_count");
 vals[3].type = SR_UINT64_T;
 vals[3].data.uint64_val = hicn_state->pkts_from_cache_count;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64,  hicn_state->pkts_from_cache_count );
 lyd_new_path(*parent, NULL, vals[3].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[4], "/hicn:hicn-state/states/pkts_no_pit_count");
 vals[4].type = SR_UINT64_T;
 vals[4].data.uint64_val = hicn_state->pkts_no_pit_count;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64,  hicn_state->pkts_no_pit_count );
 lyd_new_path(*parent, NULL, vals[4].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[5], "/hicn:hicn-state/states/pit_expired_count");
 vals[5].type = SR_UINT64_T;
 vals[5].data.uint64_val = hicn_state->pit_expired_count;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64, hicn_state->pit_expired_count );
 lyd_new_path(*parent, NULL, vals[5].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[6], "/hicn:hicn-state/states/cs_expired_count");
 vals[6].type = SR_UINT64_T;
 vals[6].data.uint64_val = hicn_state->cs_expired_count;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64, hicn_state->cs_expired_count );
 lyd_new_path(*parent, NULL, vals[6].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[7], "/hicn:hicn-state/states/cs_lru_count");
 vals[7].type = SR_UINT64_T;
 vals[7].data.uint64_val = hicn_state->cs_lru_count;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64, hicn_state->cs_lru_count );
 lyd_new_path(*parent, NULL, vals[7].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[8], "/hicn:hicn-state/states/pkts_drop_no_buf");
 vals[8].type = SR_UINT64_T;
 vals[8].data.uint64_val = hicn_state->pkts_drop_no_buf;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64, hicn_state->pkts_drop_no_buf );
 lyd_new_path(*parent, NULL, vals[8].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[9], "/hicn:hicn-state/states/interests_aggregated");
 vals[9].type = SR_UINT64_T;
 vals[9].data.uint64_val = hicn_state->interests_aggregated;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64, hicn_state->interests_aggregated );
 lyd_new_path(*parent, NULL, vals[9].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[10], "/hicn:hicn-state/states/interests_retx");
 vals[10].type = SR_UINT64_T;
 vals[10].data.uint64_val = hicn_state->interests_retx;
 memset(buf, 0x00, 20);
  sprintf( buf, "%" PRIu64, hicn_state->interests_retx );
 lyd_new_path(*parent, NULL, vals[10].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[11],
                  "/hicn:hicn-state/states/interests_hash_collision");
 vals[11].type = SR_UINT64_T;
 vals[11].data.uint64_val = hicn_state->interests_hash_collision;
 memset(buf, 0x00, 20);
  sprintf( buf, "%" PRIu64,  hicn_state->interests_hash_collision );
 lyd_new_path(*parent, NULL, vals[11].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[12], "/hicn:hicn-state/states/pit_entries_count");
 vals[12].type = SR_UINT64_T;
 vals[12].data.uint64_val = hicn_state->pit_entries_count;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64, hicn_state->pit_entries_count );
 lyd_new_path(*parent, NULL, vals[12].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[13], "/hicn:hicn-state/states/cs_entries_count");
 vals[13].type = SR_UINT64_T;
 vals[13].data.uint64_val = hicn_state->cs_entries_count;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64, hicn_state->cs_entries_count );
 lyd_new_path(*parent, NULL, vals[13].xpath, buf, 0, 0);

 sr_val_set_xpath(&vals[14], "/hicn:hicn-state/states/cs_entries_ntw_count");
 vals[14].type = SR_UINT64_T;
 vals[14].data.uint64_val = hicn_state->cs_entries_ntw_count;
 memset(buf, 0x00, 20);
 sprintf( buf, "%" PRIu64, hicn_state->cs_entries_ntw_count );
 lyd_new_path(*parent, NULL, vals[14].xpath, buf, 0, 0);

}

static inline int  routes_update(sr_val_t * vals, uint32_t nleaves, struct lyd_node **parent, sr_session_ctx_t *session){

 struct hicn_routes_s * temp = hicn_routes->next;
 char buf[20];
 int route =0;
 for(int count=0; count<nleaves; count++){

   sr_val_build_xpath(&vals[route], "%s[routeid='%d']/prefix", "/hicn:hicn-state/routes/route",
   temp->route.route_id);
   vals[route].type = SR_STRING_T;

   memset(buf, 0x00, 20);
   if (temp->route.prefix.address.af==ADDRESS_IP4){
     struct sockaddr_in sa;
     memcpy(&sa.sin_addr.s_addr, temp->route.prefix.address.un.ip4, IPV4_ADDR_LEN);
     inet_ntop(AF_INET, &(sa.sin_addr), buf, INET_ADDRSTRLEN);
     vals[route].data.string_val =  buf;
   }else{
     struct sockaddr_in6 sa;
     memcpy(&sa.sin6_addr,temp->route.prefix.address.un.ip6, IPV6_ADDR_LEN);
     inet_ntop(AF_INET6, &(sa.sin6_addr), buf, INET6_ADDRSTRLEN);
     vals[route].data.string_val =  buf;
   }


     lyd_new_path(*parent, NULL, vals[route].xpath, buf, 0, 0);


   route++;

   sr_val_build_xpath(&vals[route], "%s[routeid='%d']/strategy_id", "/hicn:hicn-state/routes/route",
   temp->route.route_id);
   vals[route].type = SR_UINT32_T;
   vals[route].data.uint32_val = temp->route.strategy_id;
   memset(buf, 0x00, 20);
   sprintf( buf, "%d", temp->route.strategy_id);
   lyd_new_path(*parent, NULL, vals[route].xpath, buf, 0, 0);

   route++;

   temp=temp->next;

}

 SRP_LOG_DBGMSG("Routes state updated \n");
 return SR_ERR_OK;
}

static inline int  faces_update(sr_val_t * vals, uint32_t nleaves, struct lyd_node **parent, sr_session_ctx_t *session){

 struct hicn_faces_s * temp = hicn_faces->next;
 char buf[20];
 int face =0;


 for(int count=0; count<nleaves; count++){

   vapi_msg_hicn_api_face_params_get *msg;
   msg = vapi_alloc_hicn_api_face_params_get(g_vapi_ctx_instance);


   msg->payload.faceid = temp->face.faceid;

   if(vapi_hicn_api_face_params_get(g_vapi_ctx_instance,msg,call_hicn_api_face_params_get, (void *)temp)!=VAPI_OK){
     SRP_LOG_DBGMSG("Operation failed");
     return SR_ERR_OPERATION_FAILED;
   }

   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/intfc", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT32_T;
   vals[face].data.uint32_val = temp->face.intfc;
   memset(buf, 0x00, 20);
   sprintf( buf,"%u", temp->face.intfc);
   lyd_new_path(*parent, NULL, vals[face].xpath, buf, 0, 0);


   face++;


   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/irx_packets", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.irx_packets;
   memset(buf, 0x00, 20);
   sprintf( buf, "%" PRIu64, temp->face.irx_packets);
   lyd_new_path(*parent, NULL, vals[face].xpath, buf, 0, 0);

   face++;



   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/irx_bytes", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.irx_bytes;
   memset(buf, 0x00, 20);
   sprintf( buf, "%" PRIu64, temp->face.irx_bytes);
   lyd_new_path(*parent, NULL, vals[face].xpath, buf, 0, 0);

   face++;



   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/itx_packets", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.itx_packets;
   memset(buf, 0x00, 20);
   sprintf( buf, "%" PRIu64, temp->face.itx_packets);
   lyd_new_path(*parent, NULL, vals[face].xpath, buf, 0, 0);

   face++;



   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/itx_bytes", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.itx_bytes;
   memset(buf, 0x00, 20);
   sprintf( buf, "%" PRIu64, temp->face.itx_bytes);
   lyd_new_path(*parent, NULL, vals[face].xpath, buf, 0, 0);


   face++;


   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/drx_packets", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.drx_packets;
   memset(buf, 0x00, 20);
   sprintf( buf, "%" PRIu64, temp->face.drx_packets);
   lyd_new_path(*parent, NULL, vals[face].xpath, buf, 0, 0);


   face++;



   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/drx_bytes", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val =  temp->face.drx_bytes;
   memset(buf, 0x00, 20);
   sprintf( buf, "%" PRIu64, temp->face.drx_packets);
   lyd_new_path(*parent, NULL, vals[face].xpath,  buf, 0, 0);


   face++;


   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/dtx_packets", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.dtx_packets;
   memset(buf, 0x00, 20);
   sprintf( buf, "%" PRIu64, temp->face.dtx_packets);
   lyd_new_path(*parent, NULL, vals[face].xpath, buf, 0, 0);

   face++;


   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/dtx_bytes", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.dtx_bytes;
   memset(buf, 0x00, 20);
   sprintf( buf, "%" PRIu64, temp->face.dtx_bytes);
   lyd_new_path(*parent, NULL, vals[face].xpath, buf, 0, 0);


   face++;

   temp=temp->next;

 }
 SRP_LOG_DBGMSG("Faces state updated \n");
 return SR_ERR_OK;
}

static int hicn_state_states_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath,
        uint32_t request_id, struct lyd_node **parent, void *private_data) {
 sr_val_t *vals;
 int rc;
 enum locks_name state;
 state=lstate;
 SRP_LOG_DBGMSG("Requesting state data");


 rc = sr_new_values(NSTATE_LEAVES, &vals);
 if (SR_ERR_OK != rc) {
   return rc;
 }


 tlock(state);
 state_update(vals,parent,session);
 tunlock(state);


 return SR_ERR_OK;
}

static int hicn_state_route_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath,
        uint32_t request_id, struct lyd_node **parent, void *private_data) {
 sr_val_t *vals;
 int rc;
 enum locks_name route;
 route=lroute;
 uint32_t NROUTE_NODES = hicn_routes->nroute * ROUTES_CHILDREN;



 rc = sr_new_values(NROUTE_NODES, &vals);
 if (SR_ERR_OK != rc) {
   return rc;
 }

 tlock(route);
 routes_update(vals,NROUTE_NODES/ROUTES_CHILDREN, parent, session);
 tunlock(route);


 return SR_ERR_OK;

 }


 static int hicn_state_faces_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath,
        uint32_t request_id, struct lyd_node **parent, void *private_data) {


 sr_val_t *vals;
 int rc;
 enum locks_name faces;
 faces=lfaces;
 uint32_t NFACES_NODES = hicn_faces->nface * FACES_CHILDREN;

 rc = sr_new_values(NFACES_NODES, &vals);
 if (SR_ERR_OK != rc) {
   return rc;
 }

 tlock(faces);
 faces_update(vals, NFACES_NODES/FACES_CHILDREN, parent, session);
 tunlock(faces);

 return SR_ERR_OK;

 }

static int hicn_strategies_get_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {

SRP_LOG_DBGMSG("hicn strategies received successfully");
vapi_msg_hicn_api_strategies_get *msg;

msg = vapi_alloc_hicn_api_strategies_get(g_vapi_ctx_instance);

if (vapi_hicn_api_strategies_get(g_vapi_ctx_instance, msg, call_hicn_api_strategies_get, NULL)!=VAPI_OK){
  SRP_LOG_DBGMSG("Operation failed");
  return SR_ERR_OPERATION_FAILED;
}
return SR_ERR_OK;

}

static int hicn_route_nhops_add_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {

 SRP_LOG_DBGMSG("hicn route nhops add received successfully");
 vapi_msg_hicn_api_route_nhops_add *msg;

 msg = vapi_alloc_hicn_api_route_nhops_add(g_vapi_ctx_instance);

 if(strcmp(input[0].data.string_val,"-1")){

   struct sockaddr_in sa;
   inet_pton(AF_INET,  input[0].data.string_val, &(sa.sin_addr));
   unsigned char * tmp = (unsigned char *) &sa.sin_addr.s_addr;
   memcpy(&msg->payload.prefix.address.un.ip4[0],tmp,B32);
   msg->payload.prefix.address.af = ADDRESS_IP4;

 }else if(strcmp(input[1].data.string_val,"-1")){

   void *dst = malloc(sizeof(struct in6_addr));
   inet_pton(AF_INET6, input[1].data.string_val, dst);
   unsigned char * tmp = (unsigned char *) ((struct in6_addr *)dst)->s6_addr;
   memcpy(&msg->payload.prefix.address.un.ip6[0],tmp,B128);
   msg->payload.prefix.address.af = ADDRESS_IP6;

 }else{
     SRP_LOG_DBGMSG("Invalid local IP address");
     return SR_ERR_OPERATION_FAILED;
 }

 msg->payload.prefix.len = input[2].data.uint8_val;
 msg->payload.face_ids[0] = input[3].data.uint32_val;
 msg->payload.face_ids[1] = input[4].data.uint32_val;
 msg->payload.face_ids[2] = input[5].data.uint32_val;
 msg->payload.face_ids[3] = input[6].data.uint32_val;
 msg->payload.face_ids[4] = input[7].data.uint32_val;
 msg->payload.face_ids[5] = input[8].data.uint32_val;
 msg->payload.face_ids[6] = input[9].data.uint32_val;
 msg->payload.n_faces = input[10].data.uint8_val;


if(vapi_hicn_api_route_nhops_add(g_vapi_ctx_instance,msg,call_hicn_api_route_nhops_add,NULL)!=VAPI_OK){
 SRP_LOG_DBGMSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}
return SR_ERR_OK;
}

static int hicn_route_del_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {

 SRP_LOG_DBGMSG("hicn route del received successfully");
 vapi_msg_hicn_api_route_del *msg;

 msg = vapi_alloc_hicn_api_route_del(g_vapi_ctx_instance);

 if(strcmp(input[0].data.string_val,"-1")){

   struct sockaddr_in sa;
   inet_pton(AF_INET,  input[0].data.string_val, &(sa.sin_addr));
   unsigned char * tmp = (unsigned char *) &sa.sin_addr.s_addr;
   memcpy(&msg->payload.prefix.address.un.ip4[0],tmp,B32);
   msg->payload.prefix.address.af = ADDRESS_IP4;


 }else if(strcmp(input[1].data.string_val,"-1")){

   void *dst = malloc(sizeof(struct in6_addr));
   inet_pton(AF_INET6, input[1].data.string_val, dst);
   unsigned char * tmp = (unsigned char *) ((struct in6_addr *)dst)->s6_addr;
   memcpy(&msg->payload.prefix.address.un.ip6[0],tmp,B128);
   msg->payload.prefix.address.af = ADDRESS_IP6;

 }else{
     SRP_LOG_DBGMSG("Invalid local IP address");
     return SR_ERR_OPERATION_FAILED;
 }


 msg->payload.prefix.len = input[2].data.uint8_val;


if(vapi_hicn_api_route_del(g_vapi_ctx_instance,msg,call_hicn_api_route_del,NULL)!=VAPI_OK){
 SRP_LOG_DBGMSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}
return SR_ERR_OK;
}

static int hicn_face_params_get_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {

 SRP_LOG_DBGMSG("hicn face ip params get received successfully");
 vapi_msg_hicn_api_face_params_get *msg;

 msg = vapi_alloc_hicn_api_face_params_get(g_vapi_ctx_instance);

 msg->payload.faceid = input[0].data.uint32_val;

if (vapi_hicn_api_face_params_get(g_vapi_ctx_instance,msg,call_hicn_api_face_params_get,NULL)!=VAPI_OK){
 SRP_LOG_DBGMSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}
return SR_ERR_OK;
}

static int hicn_route_nhops_del_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {

 SRP_LOG_DBGMSG("hicn route nhop del received successfully");
 // allocate memory msg
 vapi_msg_hicn_api_route_nhop_del *msg;

 msg = vapi_alloc_hicn_api_route_nhop_del(g_vapi_ctx_instance);


 if(strcmp(input[0].data.string_val,"-1")){

   struct sockaddr_in sa;
   // store this IP address in sa:
   inet_pton(AF_INET,  input[0].data.string_val, &(sa.sin_addr));
   unsigned char * tmp = (unsigned char *) &sa.sin_addr.s_addr;
   memcpy(&msg->payload.prefix.address.un.ip4[0],tmp,B32);
   msg->payload.prefix.address.af = ADDRESS_IP4;


 }else if(strcmp(input[1].data.string_val,"-1")){

   void *dst = malloc(sizeof(struct in6_addr));
   inet_pton(AF_INET6, input[1].data.string_val, dst);
   unsigned char * tmp = (unsigned char *) ((struct in6_addr *)dst)->s6_addr;
   memcpy(&msg->payload.prefix.address.un.ip6[0],tmp,B128);
   msg->payload.prefix.address.af = ADDRESS_IP6;

 }else{
     SRP_LOG_DBGMSG("Invalid local IP address");
     return SR_ERR_OPERATION_FAILED;
 }


 msg->payload.prefix.len = input[2].data.uint8_val;
 msg->payload.faceid = input[3].data.uint32_val;


if (vapi_hicn_api_route_nhop_del(g_vapi_ctx_instance, msg, call_hicn_api_route_nhop_del,NULL)!=VAPI_OK){
 SRP_LOG_DBGMSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}
return SR_ERR_OK;
}

static vapi_error_e
hicn_api_routes_dump_cb(struct vapi_ctx_s *ctx, void *callback_ctx,
                    vapi_error_e rv, bool is_last,
                    vapi_payload_hicn_api_routes_details *reply)
{

   static int counter = 0;

   tlock(lroute);
   if (reply!=NULL){
     rcurrent->route.route_id = counter;
     rcurrent->route.prefix =  reply->prefix;
     rcurrent->route.nfaces =   reply->nfaces;
     rcurrent->route.strategy_id = reply->strategy_id;
     for(int cnt=0;cnt<rcurrent->route.nfaces;cnt++)
       rcurrent->route.faceids[cnt] = rcurrent->route.faceids[cnt];

     counter++;
     rcurrent = rcurrent->next;

     SRP_LOG_DBG("nfaces %d", reply->nfaces);
     SRP_LOG_DBG("strategy_id %d", reply->strategy_id);

   }else
   {
     SRP_LOG_DBGMSG("---------Routes------- \n");
     hicn_routes->nroute=counter;
     counter=0;
     rcurrent=hicn_routes->next;
   }
   tunlock(lroute);
   return SR_ERR_OK;

}


static vapi_error_e
hicn_api_face_stats_dump_cb(struct vapi_ctx_s *ctx, void *callback_ctx,
                    vapi_error_e rv, bool is_last,
                    vapi_payload_hicn_api_face_stats_details *reply)
{

   static int counter = 0;

   tlock(lfaces);
   if (reply!=NULL){

     fcurrent->face.faceid =  reply->faceid;
     fcurrent->face.intfc =   1;
     fcurrent->face.irx_packets = reply->irx_packets;
     fcurrent->face.irx_bytes =   reply->irx_bytes;
     fcurrent->face.itx_packets = reply->itx_packets;
     fcurrent->face.itx_bytes =   reply->itx_bytes;
     fcurrent->face.drx_packets = reply->drx_packets;
     fcurrent->face.drx_bytes =   reply->drx_bytes;
     fcurrent->face.dtx_packets = reply->dtx_packets;
     fcurrent->face.dtx_bytes =   reply->dtx_bytes;
     counter++;
     fcurrent = fcurrent->next;
     SRP_LOG_DBG("faceid %d", reply->faceid);
     SRP_LOG_DBG("drxB %d", reply->drx_bytes);
     SRP_LOG_DBG("dtxB %d", reply->dtx_bytes);

   }else
   {
     SRP_LOG_DBGMSG("---------Faces------- \n");
     hicn_faces->nface=counter;
     counter=0;
     fcurrent=hicn_faces->next;
   }
   tunlock(lfaces);
   return SR_ERR_OK;
}


static void *state_thread(void *arg) {

 // mapping can be retrieved by cpuinfo
 int map = 0;
 cpu_set_t cpuset;
 CPU_ZERO(&cpuset);
 CPU_SET(map, &cpuset);

 // pin the thread to a core
 if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset))
 {
     SRP_LOG_DBGMSG("Thread pining failed\n");
     exit(1);
 }

 vapi_msg_hicn_api_node_stats_get *msg=NULL;
 enum locks_name state;
 state=lstate;

 while(true){

  // dump faces
  vapi_msg_hicn_api_face_stats_dump *fmsg;
  fmsg = vapi_alloc_hicn_api_face_stats_dump(g_vapi_ctx_instance);
  vapi_hicn_api_face_stats_dump(g_vapi_ctx_instance, fmsg, hicn_api_face_stats_dump_cb, fcurrent);

  // dump routes
  vapi_msg_hicn_api_routes_dump *rmsg;
  rmsg = vapi_alloc_hicn_api_routes_dump(g_vapi_ctx_instance);
  vapi_hicn_api_routes_dump(g_vapi_ctx_instance, rmsg, hicn_api_routes_dump_cb, rcurrent);



  msg = vapi_alloc_hicn_api_node_stats_get(g_vapi_ctx_instance);


  tlock(state);

  if(vapi_hicn_api_node_stats_get(g_vapi_ctx_instance,msg,call_vapi_hicn_api_node_stats_get,NULL)!=VAPI_OK){
  SRP_LOG_DBGMSG(" State operation failed");
  }


  tunlock(state);
  sleep(1);

  SRP_LOG_DBGMSG("state cached");

 }
 return NULL;
}


int hicn_subscribe_events(sr_session_ctx_t *session,
                         sr_subscription_ctx_t **subscription) {
   int rc = SR_ERR_OK;
   SRP_LOG_DBGMSG("Subscriging hicn.");

   //Initializing the locks
   for (int i=0; i<NLOCKS; i++)
     ticket_init(i,LOCK_INIT);

   //Initializing the buffer
   rc=init_buffer();
   if(rc!= SR_ERR_OK){
       SRP_LOG_DBGMSG("Problem in initializing the buffers\n");
       goto error;
   }

   SRP_LOG_DBGMSG("buffer initialized successfully.");


   rc=init_face_pool(fcurrent);
   if(rc){
       SRP_LOG_DBGMSG("Problem in initializing the pools\n");
       goto error;
   }


   rc=init_route_pool(rcurrent);
   if(rc){
       SRP_LOG_DBGMSG("Problem in initializing the pools\n");
       goto error;
   }


   SRP_LOG_DBGMSG("pools created successfully.");


   // Create state thread observation
   pthread_t state_tid;
   rc = pthread_create((pthread_t *)&state_tid, NULL, state_thread, NULL);
   if (rc != 0) {
         SRP_LOG_DBGMSG("Error making hicn state thread");
         return SR_ERR_OPERATION_FAILED;
   }
   SRP_LOG_DBGMSG("State thread created successfully.");


/*
 // subscripe for edit-config
 rc = sr_module_change_subscribe(
     session, "hicn","/hicn:hicn-conf", hicn_node_params_set_cb, g_vapi_ctx_instance,
     0, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_ENABLED, subscription);
 if (SR_ERR_OK != rc) {
   //SRP_LOG_DBGMSG("Problem in subscription /hicn:hicn-conf\n");
   perror("Problem in subscription /hicn:hicn-conf\n");
   goto error;
 }
*/

   // strategies subscriptions

   rc = sr_rpc_subscribe(session, "/hicn:strategies-get",
   hicn_strategies_get_cb, session, 98,SR_SUBSCR_CTX_REUSE, subscription);
   if (rc!= SR_ERR_OK) {
      SRP_LOG_DBGMSG("Problem in subscription strategies-get\n");
      goto error;
   }

   // route nhops subscriptions

   rc = sr_rpc_subscribe(session, "/hicn:route-nhops-add",
   hicn_route_nhops_add_cb, session, 95,SR_SUBSCR_CTX_REUSE, subscription);
    if (rc!= SR_ERR_OK) {
     SRP_LOG_DBGMSG("Problem in subscription route-nhops-add\n");
     goto error;
   }

   rc = sr_rpc_subscribe(session, "/hicn:route-nhops-del",
   hicn_route_nhops_del_cb, session, 94,SR_SUBSCR_CTX_REUSE, subscription);
    if (rc!= SR_ERR_OK) {
      SRP_LOG_DBGMSG("Problem in subscription route-nhops-del\n");
      goto error;
   }

   rc = sr_rpc_subscribe(session, "/hicn:route-del", hicn_route_del_cb,
   session, 96,SR_SUBSCR_CTX_REUSE, subscription);
   if (rc != SR_ERR_OK) {
     SRP_LOG_DBGMSG("Problem in subscription route-del\n");
     goto error;
   }

   // face ip subscriptions

   rc = sr_rpc_subscribe(session, "/hicn:face-params-get",
   hicn_face_params_get_cb, session, 93,SR_SUBSCR_CTX_REUSE, subscription);
   if (rc != SR_ERR_OK) {
     SRP_LOG_DBGMSG("Problem in subscription face-ip-params-get\n");
     goto error;
   }

 // subscribe as hicn state data provider

 rc = sr_oper_get_items_subscribe(session, "hicn","/hicn:hicn-state/states",
                                hicn_state_states_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                subscription);
 if (rc != SR_ERR_OK) {
   SRP_LOG_DBGMSG("Problem in subscription /hicn:hicn-state/states\n");
   goto error;
 }


 rc = sr_oper_get_items_subscribe(session, "hicn","/hicn:hicn-state/routes",
                                hicn_state_route_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                subscription);
 if (rc != SR_ERR_OK) {
   SRP_LOG_DBGMSG("Problem in subscription /hicn:hicn-state/routes\n");
   goto error;
 }


 rc = sr_oper_get_items_subscribe(session, "hicn","/hicn:hicn-state/faces",
                                hicn_state_faces_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                subscription);
 if (rc != SR_ERR_OK) {
   SRP_LOG_DBGMSG("Problem in subscription /hicn:hicn-state/faces\n");
   goto error;
 }


   SRP_LOG_DBGMSG("hicn plugin initialized successfully.\n");
 return SR_ERR_OK;

error:
 SRP_LOG_ERRMSG("Error by initialization of the hicn plugin.");
 sr_plugin_cleanup_cb(session, &g_vapi_ctx_instance);
 return rc;
}
