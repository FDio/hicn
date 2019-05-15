/*
* Copyright (c) 2019 Cisco and/or its affiliates.
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

#define _GNU_SOURCE

#include <stdio.h>
#include <malloc.h>
#include <sysrepo/xpath.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>



#include <sched.h>
/* Hicn headers */

#include <vapi/hicn.api.vapi.h>
#include <hicn/api/ip_address.h>
#include "../hicn_plugin.h"
#include "../hicn_vpp_comm.h"
#include "hicn_model.h"
#include "tlock.h"


DEFINE_VAPI_MSG_IDS_HICN_API_JSON


// Shared local variables between state and RPCs

volatile hicn_state_t  * hicn_state = NULL;
volatile hicn_strategy_t * hicn_strategy = NULL;
volatile hicn_strategies_t * hicn_strategies =NULL;
volatile hicn_route_t * hicn_route = NULL;
volatile hicn_face_ip_params_t *  hicn_face_ip_params = NULL;
volatile hicn_faces_t *  hicn_faces = NULL;
//volatile hicn_face_stat_t * hicn_face_stat=NULL;
struct hicn_faces_s * current = NULL;
//volatile hicn_state_face_t * hicn_state_face=NULL;

uint64_t teth1=0,teth2=0,teth3=0;

void RemoveSpaces(char* source)
{
  char* i = source;
  char* j = source;
  while(*j != 0)
  {
    *i = *j++;
    if(*i != ' ')
      i++;
  }
  *i = 0;
}

static void host_speed(void){

    FILE *fp = fopen("/proc/net/dev", "r");
    char buf[200];
    char * ifname;
    ifname = malloc (20);
    unsigned long int r_bytes, t_bytes, r_packets, t_packets;

    // skip first two lines
    for (int i = 0; i < 2; i++) {
        fgets(buf, 200, fp);
    }

    while (fgets(buf, 200, fp)) {
        sscanf(buf, "%[^:]: %lu %lu %*u %*u %*u %*u %*u %*u %lu %lu",
               ifname, &r_bytes, &r_packets, &t_bytes, &t_packets);
        RemoveSpaces(ifname);
        if (!strcmp(ifname,"eth1"))
          teth1=r_bytes+t_bytes;
        if (!strcmp(ifname,"eth2"))
          teth2=r_bytes+t_bytes;
        if (!strcmp(ifname,"eth3"))
          teth3=r_bytes+t_bytes;
        //printf(" rbytes: %lu tbytes: %lu, bandwidth: %lu \n",
        //       r_bytes, t_bytes, r_bytes+t_bytes);
    }
    fclose(fp);
    free(ifname);
}

static int init_buffer(void){

 hicn_state = memalign(MEM_ALIGN, sizeof(hicn_state_t) );
 memset((hicn_state_t *)hicn_state, 0 , sizeof(hicn_state_t) );

 hicn_strategy = memalign(MEM_ALIGN, sizeof(hicn_strategy_t) );
 memset((hicn_strategy_t *) hicn_strategy, 0 , sizeof(hicn_strategy_t) );

 hicn_strategies = memalign(MEM_ALIGN, sizeof(hicn_strategies_t) );
 memset((hicn_strategies_t *) hicn_strategies, 0 , sizeof(hicn_strategies_t) );

 hicn_route = memalign(MEM_ALIGN, sizeof(hicn_route_t) );
 memset((hicn_route_t *) hicn_route, 0 , sizeof(hicn_route_t) );

 hicn_faces = memalign(MEM_ALIGN, sizeof(hicn_faces_t) );
 hicn_faces->next=memalign(MEM_ALIGN, sizeof(struct hicn_faces_s));
 current=hicn_faces->next;

//  hicn_state_face = memalign(MEM_ALIGN, sizeof(hicn_state_face_t) );
//  memset((hicn_state_face_t *) hicn_state_face, 0, sizeof(hicn_state_face_t));

 int retval=-1;
 ARG_CHECK6(retval, hicn_state, hicn_strategy, hicn_strategies, hicn_route, current, hicn_faces);
 hicn_faces->nface=0;
 retval=0;

 return retval;
}


static int init_face_pool(struct hicn_faces_s * head){

 ARG_CHECK(HICN_EINVAL, head);
 for(int i=0; i<MAX_FACE_POOL; i++){
     head->next=memalign(MEM_ALIGN, sizeof(struct hicn_faces_s));
     head=head->next;
     SRP_LOG_DBG_MSG("Allocated\n");
 }
 head->next=NULL;
 return HICN_OK;

}

static inline void  state_cache(vapi_msg_hicn_api_node_stats_get_reply * resp){
   hicn_state->pkts_processed = resp->payload.pkts_processed;
   hicn_state->pkts_interest_count = resp->payload.pkts_interest_count;
   hicn_state->pkts_data_count = resp->payload.pkts_data_count;
   hicn_state->pkts_from_cache_count = resp->payload.pkts_from_cache_count;
   hicn_state->pkts_no_pit_count = resp->payload.pkts_no_pit_count;
   hicn_state->pit_expired_count = resp->payload.pit_expired_count;
   hicn_state->cs_expired_count = resp->payload.cs_expired_count;
   hicn_state->cs_lru_count = resp->payload.cs_lru_count;
   hicn_state->pkts_drop_no_buf = resp->payload.pkts_drop_no_buf;
   hicn_state->interests_aggregated = resp->payload.interests_aggregated;
   hicn_state->interests_retx = resp->payload.interests_retx;
   hicn_state->pit_entries_count = resp->payload.pit_entries_count;
   hicn_state->cs_entries_count = resp->payload.cs_entries_count;
   hicn_state->cs_entries_ntw_count = resp->payload.cs_entries_ntw_count;
   SRP_LOG_DBG_MSG("state cached");
}


static inline void  state_update(sr_val_t * vals ){
 sr_val_set_xpath(&vals[0], "/hicn:hicn-state/states/pkts_processed");
 vals[0].type = SR_UINT64_T;
 vals[0].data.uint64_val = hicn_state->pkts_processed;

 sr_val_set_xpath(&vals[1], "/hicn:hicn-state/states/pkts_interest_count");
 vals[1].type = SR_UINT64_T;
 vals[1].data.uint64_val = hicn_state->pkts_interest_count;

 sr_val_set_xpath(&vals[2], "/hicn:hicn-state/states/pkts_data_count");
 vals[2].type = SR_UINT64_T;
 vals[2].data.uint64_val = hicn_state->pkts_data_count;

 sr_val_set_xpath(&vals[3], "/hicn:hicn-state/states/pkts_from_cache_count");
 vals[3].type = SR_UINT64_T;
 vals[3].data.uint64_val = hicn_state->pkts_from_cache_count;

 sr_val_set_xpath(&vals[4], "/hicn:hicn-state/states/pkts_no_pit_count");
 vals[4].type = SR_UINT64_T;
 vals[4].data.uint64_val = hicn_state->pkts_no_pit_count;

 sr_val_set_xpath(&vals[5], "/hicn:hicn-state/states/pit_expired_count");
 vals[5].type = SR_UINT64_T;
 vals[5].data.uint64_val = hicn_state->pit_expired_count;

 sr_val_set_xpath(&vals[6], "/hicn:hicn-state/states/cs_expired_count");
 vals[6].type = SR_UINT64_T;
 vals[6].data.uint64_val = hicn_state->cs_expired_count;

 sr_val_set_xpath(&vals[7], "/hicn:hicn-state/states/cs_lru_count");
 vals[7].type = SR_UINT64_T;
 vals[7].data.uint64_val = hicn_state->cs_lru_count;

 sr_val_set_xpath(&vals[8], "/hicn:hicn-state/states/pkts_drop_no_buf");
 vals[8].type = SR_UINT64_T;
 vals[8].data.uint64_val = hicn_state->pkts_drop_no_buf;

 sr_val_set_xpath(&vals[9], "/hicn:hicn-state/states/interests_aggregated");
 vals[9].type = SR_UINT64_T;
 vals[9].data.uint64_val = hicn_state->interests_aggregated;

 sr_val_set_xpath(&vals[10], "/hicn:hicn-state/states/interests_retx");
 vals[10].type = SR_UINT64_T;
 vals[10].data.uint64_val = hicn_state->interests_retx;

 sr_val_set_xpath(&vals[11],
                  "/hicn:hicn-state/states/interests_hash_collision");
 vals[11].type = SR_UINT64_T;
 vals[11].data.uint64_val = hicn_state->interests_hash_collision;

 sr_val_set_xpath(&vals[12], "/hicn:hicn-state/states/pit_entries_count");
 vals[12].type = SR_UINT64_T;
 vals[12].data.uint64_val = hicn_state->pit_entries_count;

 sr_val_set_xpath(&vals[13], "/hicn:hicn-state/states/cs_entries_count");
 vals[13].type = SR_UINT64_T;
 vals[13].data.uint64_val = hicn_state->cs_entries_count;

 sr_val_set_xpath(&vals[14], "/hicn:hicn-state/states/cs_entries_ntw_count");
 vals[14].type = SR_UINT64_T;
 vals[14].data.uint64_val = hicn_state->cs_entries_ntw_count;
}

static inline void  strategies_update(sr_val_t * vals ){
 sr_val_set_xpath(&vals[0], "/hicn:hicn-state/strategies/n_strategies");
 vals[0].type = SR_UINT8_T;
 vals[0].data.uint8_val = hicn_strategies->n_strategies;

 sr_val_set_xpath(&vals[1], "/hicn:hicn-state/strategies/strategy_id");
 vals[1].type = SR_UINT32_T;
 vals[1].data.uint32_val = hicn_strategies->strategy_id[0];
}

static inline void  route_update(sr_val_t * vals ){
 sr_val_set_xpath(&vals[0], "/hicn:hicn-state/routes/faceids");
 vals[0].type = SR_UINT16_T;
 vals[0].data.uint32_val = hicn_route->faceids[0];

 sr_val_set_xpath(&vals[1], "/hicn:hicn-state/routes/strategy_id");
 vals[1].type = SR_UINT32_T;
 vals[1].data.uint32_val = hicn_route->strategy_id;
}

static inline int  faces_update(sr_val_t * vals, uint32_t nleaves){

 struct hicn_faces_s * temp = hicn_faces->next;
 int face =0;

 for(int count=0; count<nleaves; count++){


  // This part must be removed once the faceid is provided by the dump msg
   vapi_msg_hicn_api_face_ip_params_get *msg;
   vapi_msg_hicn_api_face_ip_params_get_reply *resp;
   msg = vapi_alloc_hicn_api_face_ip_params_get(g_vapi_ctx_instance);
   msg->payload.faceid = temp->face.faceid;
   vapi_msg_hicn_api_face_ip_params_get_hton(msg);
   params_send(msg,resp);
   vapi_msg_hicn_api_face_ip_params_get_reply_ntoh(resp);
   if(!resp->payload.retval){
     SRP_LOG_DBG("faceid(%d)-->intfc(%d)", temp->face.faceid, resp->payload.swif);
     temp->face.intfc= resp->payload.swif;
   }


   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/intfc", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT32_T;
   vals[face].data.uint32_val = temp->face.intfc;


   face++;


   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/irx_packets", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.irx_packets;

   face++;

   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/irx_bytes", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.irx_bytes;

   face++;

   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/itx_packets", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.itx_packets;

   face++;

   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/itx_bytes", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.itx_bytes;

   face++;

   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/drx_packets", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.drx_packets;

   face++;

   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/drx_bytes", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.drx_bytes;

   face++;

   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/dtx_packets", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.dtx_packets;

   face++;

   sr_val_build_xpath(&vals[face], "%s[faceid='%d']/dtx_bytes", "/hicn:hicn-state/faces/face",
   temp->face.faceid);
   vals[face].type = SR_UINT64_T;
   vals[face].data.uint64_val = temp->face.dtx_bytes;

   face++;

   SRP_LOG_DBG(" **********************face is: %d-%d-%d ****************\n",temp->face.dtx_bytes,temp->face.drx_bytes,temp->face.faceid);

   printf("%" PRId64 "\n", temp->face.drx_bytes);

   temp=temp->next;

 }
 SRP_LOG_DBG_MSG("Faces state updated \n");
 return SR_ERR_OK;
}

static int hicn_state_states_cb(const char *xpath, sr_val_t **values,
                        size_t *values_cnt, uint64_t request_id,
                        const char *original_xpath, void *private_ctx) {
 sr_val_t *vals;
 int rc;
 enum locks_name state;
 state=lstate;
 SRP_LOG_DBG("Requesting state data for '%s'", xpath);

 if (!sr_xpath_node_name_eq(xpath, "states")) {
   *values = NULL;
   *values_cnt = 0;
   return SR_ERR_OK;
 }

 rc = sr_new_values(NSTATE_LEAVES, &vals);
 if (SR_ERR_OK != rc) {
   return rc;
 }

 SRP_LOG_DBG("Requesting state data for '%s'", xpath);
 tlock(state);
 state_update(vals);
 tunlock(state);

 *values = vals;
 *values_cnt = NSTATE_LEAVES;

 return SR_ERR_OK;
}

static int hicn_state_strategies_cb(const char *xpath, sr_val_t **values,
                        size_t *values_cnt, uint64_t request_id,
                        const char *original_xpath, void *private_ctx) {
 sr_val_t *vals;
 int rc;
 enum locks_name strategies;
 strategies=lstrategies;



 if (! sr_xpath_node_name_eq(xpath, "strategies")) {
   SRP_LOG_DBG_MSG("Requesting state is not for strategies");
   *values = NULL;
   *values_cnt = 0;
   return SR_ERR_OK;
 }


 rc = sr_new_values(NSTRATEGIES_LEAVES, &vals);
 if (SR_ERR_OK != rc) {
   return rc;
 }

 SRP_LOG_DBG("Requesting state data for '%s'", xpath);
 tlock(strategies);
 strategies_update(vals);
 tunlock(strategies);

 *values = vals;
 *values_cnt = NSTRATEGIES_LEAVES;
 return SR_ERR_OK;

 }


static int hicn_state_route_cb(const char *xpath, sr_val_t **values,
                        size_t *values_cnt, uint64_t request_id,
                        const char *original_xpath, void *private_ctx) {
 sr_val_t *vals;
 int rc;
 enum locks_name route;
 route=lroute;


 if (! sr_xpath_node_name_eq(xpath, "routes")) {
   SRP_LOG_DBG_MSG("Requesting state is not for routes");
   *values = NULL;
   *values_cnt = 0;
   return SR_ERR_OK;
 }

 rc = sr_new_values(NROUTE_LEAVES, &vals);
 if (SR_ERR_OK != rc) {
   return rc;
 }

 SRP_LOG_DBG("Requesting state data for '%s'", xpath);
 tlock(route);
 route_update(vals);
 tunlock(route);

 *values = vals;
 *values_cnt = NROUTE_LEAVES;
 return SR_ERR_OK;

 }


 static int hicn_state_faces_cb(const char *xpath, sr_val_t **values,
                        size_t *values_cnt, uint64_t request_id,
                        const char *original_xpath, void *private_ctx) {
 sr_val_t *vals;
 int rc;
 enum locks_name faces;
 faces=lfaces;
 uint32_t NFACES_NODES = hicn_faces->nface * FACES_CHILDREN;

 if (! sr_xpath_node_name_eq(xpath, "faces")) {
   SRP_LOG_DBG_MSG("Requesting state is not for faces");
   *values = NULL;
   *values_cnt = 0;
   return SR_ERR_OK;
 }

 // We should only consider the number of leaves not the head of list(faceid)
 rc = sr_new_values(NFACES_NODES, &vals);
 if (SR_ERR_OK != rc) {
   return rc;
 }

 SRP_LOG_DBG("Requesting state data for '%s'", xpath);

 tlock(faces);
 SRP_LOG_DBG("**********NFACES-LEAVES '%d'  *********", NFACES_NODES);
 faces_update(vals, NFACES_NODES/FACES_CHILDREN);
 tunlock(faces);
 //hicn_faces->nface=0;
 *values = vals;
 *values_cnt = NFACES_NODES;
 return SR_ERR_OK;

 }

/**
* @brief Callback to be called by any config change of "/hicn:/" leaf.
*/
static int hicn_node_params_set_cb(sr_session_ctx_t *session, const char *xpath,
                                  sr_notif_event_t event, void *private_ctx) {
 sr_change_iter_t *iter = NULL;
 sr_change_oper_t op = SR_OP_CREATED;
 sr_val_t *old_val = NULL;
 sr_val_t *new_val = NULL;
 sr_xpath_ctx_t xpath_ctx = {
     0,
 };
 int rc = SR_ERR_OK, op_rc = SR_ERR_OK;
 // no-op for apply, we only care about SR_EV_ENABLED, SR_EV_VERIFY,
 // SR_EV_ABORT
 if (SR_EV_APPLY == event) {
   return SR_ERR_OK;
 }

 // get changes iterator
 rc = sr_get_changes_iter(session, xpath, &iter);
 if (SR_ERR_OK != rc) {
   SRP_LOG_ERR("Unable to retrieve change iterator: %s", sr_strerror(rc));
   return rc;
 }

 vapi_msg_hicn_api_node_params_set *msg;
 vapi_msg_hicn_api_node_params_set_reply *resp = NULL;
 msg = vapi_alloc_hicn_api_node_params_set(g_vapi_ctx_instance);
 SRP_LOG_DBG("H:recv msgid [%d]\n", msg->header._vl_msg_id);                     \

 // iterate over all changes
 while ((SR_ERR_OK == op_rc || event == SR_EV_ABORT) &&
        (SR_ERR_OK ==
         (rc = sr_get_change_next(session, iter, &op, &old_val, &new_val)))) {
   if (!strcmp(new_val->xpath, "/hicn:hicn-conf/params/enable_disable")) {
     SRP_LOG_DBG("A change detected in '%s', op=%d",
                 new_val ? new_val->xpath : old_val->xpath,
                 new_val->data.bool_val);
     msg->payload.enable_disable = new_val->data.bool_val;
   } else if (!strcmp(new_val->xpath, "/hicn:hicn-conf/params/pit_max_size")) {
     SRP_LOG_DBG("A change detected in '%s', op=%d",
                 new_val ? new_val->xpath : old_val->xpath,
                 new_val->data.int32_val);
     msg->payload.pit_max_size = new_val->data.int32_val;
   } else if (!strcmp(new_val->xpath, "/hicn:hicn-conf/params/cs_max_size")) {
     SRP_LOG_DBG("A change detected in '%s', op=%d",
                 new_val ? new_val->xpath : old_val->xpath,
                 new_val->data.int32_val);
     msg->payload.cs_max_size = new_val->data.int32_val;
   } else if (!strcmp(new_val->xpath,
                      "/hicn:hicn-conf/params/cs_reserved_app")) {
     SRP_LOG_DBG("A change detected in '%s', op=%d",
                 new_val ? new_val->xpath : old_val->xpath,
                 new_val->data.int32_val);
     msg->payload.cs_reserved_app = new_val->data.int32_val;
   } else if (!strcmp(new_val->xpath,
                      "/hicn:hicn-conf/params/pit_dflt_lifetime_sec")) {
     SRP_LOG_DBG("A change detected in '%s', op=%d",
                 new_val ? new_val->xpath : old_val->xpath,
                 new_val->data.decimal64_val);
     msg->payload.pit_dflt_lifetime_sec = new_val->data.decimal64_val;
   } else if (!strcmp(new_val->xpath,
                      "/hicn:hicn-conf/params/pit_min_lifetime_sec")) {
     SRP_LOG_DBG("A change detected in '%s', op=%d",
                 new_val ? new_val->xpath : old_val->xpath,
                 new_val->data.decimal64_val);
     msg->payload.pit_min_lifetime_sec = new_val->data.decimal64_val;
   } else if (!strcmp(new_val->xpath,
                      "/hicn:hicn-conf/params/pit_max_lifetime_sec")) {
     SRP_LOG_DBG("A change detected in '%s', op=%d",
                 new_val ? new_val->xpath : old_val->xpath,
                 new_val->data.decimal64_val);
     msg->payload.pit_max_lifetime_sec = new_val->data.decimal64_val;
   }

   switch (op) {
     case SR_OP_CREATED:
     case SR_OP_MODIFIED:
       op_rc = SR_ERR_OK;  // OK
       break;
     case SR_OP_DELETED:
       op_rc = SR_ERR_OPERATION_FAILED;  // ERROR
       break;
     default:
       break;
   }
   sr_xpath_recover(&xpath_ctx);
   if (SR_ERR_INVAL_ARG == op_rc) {
     sr_set_error(session, "You are not allowed to change the schema.",
                  new_val ? new_val->xpath : old_val->xpath);
   }
   sr_free_val(old_val);
   sr_free_val(new_val);
 }

 vapi_msg_hicn_api_node_params_set_hton(msg);

 params_send(msg, resp);

 vapi_msg_hicn_api_node_params_set_reply_ntoh(resp);

 if(!resp->payload.retval){
     SRP_LOG_DBG_MSG("Successfully done");
     sr_free_change_iter(iter);
     return SR_ERR_OK;
 }
 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}

/**
* @brief API to get hicn param in vpp.
*/
static int hicn_node_params_get_cb(const char *xpath, const sr_val_t *input,
                                  const size_t input_cnt, sr_val_t **output,
                                  size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn node parameter received successfully");
 vapi_msg_hicn_api_node_params_get *msg;
 vapi_msg_hicn_api_node_params_get_reply *resp;

 msg = vapi_alloc_hicn_api_node_params_get(g_vapi_ctx_instance);




 vapi_msg_hicn_api_node_params_get_hton(msg);
 params_send(msg, resp);
 vapi_msg_hicn_api_node_params_get_reply_ntoh(resp);

 if(!resp->payload.retval){
     SRP_LOG_DBG_MSG("Successfully done");
     return SR_ERR_OK;
 }
 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}

/**
* @brief API to get hicn stat in vpp.
*/
static int hicn_node_stat_get_cb(const char *xpath, const sr_val_t *input,
                                const size_t input_cnt, sr_val_t **output,
                                size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn status received successfully");
 vapi_msg_hicn_api_node_stats_get *msg;
 vapi_msg_hicn_api_node_stats_get_reply *resp;
 enum locks_name state;
 state=lstate;
 msg = vapi_alloc_hicn_api_node_stats_get(g_vapi_ctx_instance);

 vapi_msg_hicn_api_node_stats_get_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_node_stats_get_reply_ntoh(resp);

 if(resp->payload.retval){
     SRP_LOG_DBG_MSG("Error updating state");
     return SR_ERR_OPERATION_FAILED;
 }
 tlock(state);

 state_cache(resp);

 tunlock(state);
 return SR_ERR_OK;

}

/**
* @brief API to get hicn strategy in vpp.
*/
static int hicn_strategy_get_cb(const char *xpath, const sr_val_t *input,
                               const size_t input_cnt, sr_val_t **output,
                               size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn strategy receive successfully");
 vapi_msg_hicn_api_strategy_get *msg;
 vapi_msg_hicn_api_strategy_get_reply *resp;

 msg = vapi_alloc_hicn_api_strategy_get(g_vapi_ctx_instance);
  SRP_LOG_DBG("msg id:%d",msg->header._vl_msg_id);

 msg->payload.strategy_id = input[0].data.uint32_val;

 vapi_msg_hicn_api_strategy_get_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_strategy_get_reply_ntoh(resp);

 if(!resp->payload.retval){
     SRP_LOG_DBG_MSG("Successfully done");
     return SR_ERR_OK;
 }

 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}

/**
* @brief API to get hicn strategies in vpp.
*/
static int hicn_strategies_get_cb(const char *xpath, const sr_val_t *input,
                                 const size_t input_cnt, sr_val_t **output,
                                 size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn strategies received successfully");
 vapi_msg_hicn_api_strategies_get *msg;
 vapi_msg_hicn_api_strategies_get_reply *resp;

 msg = vapi_alloc_hicn_api_strategies_get(g_vapi_ctx_instance);
  SRP_LOG_DBG("msg id:%d",msg->header._vl_msg_id);


 vapi_msg_hicn_api_strategies_get_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_strategies_get_reply_ntoh(resp);

 if(!resp->payload.retval){
     SRP_LOG_DBG_MSG("Successfully done");
     return SR_ERR_OK;
 }

 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}

/**
* @brief API to get hicn route in vpp.
*/
static int hicn_route_get_cb(const char *xpath, const sr_val_t *input,
                            const size_t input_cnt, sr_val_t **output,
                            size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn route receive successfully");
 vapi_msg_hicn_api_route_get *msg;
 vapi_msg_hicn_api_route_get_reply *resp;

 msg = vapi_alloc_hicn_api_route_get(g_vapi_ctx_instance);
  SRP_LOG_DBG("msg id:%d",msg->header._vl_msg_id);


 if(strcmp(input[0].data.string_val,"-1")){

   struct sockaddr_in sa;
   inet_pton(AF_INET,  input[0].data.string_val, &(sa.sin_addr));
   unsigned char * tmp = (unsigned char *) &sa.sin_addr.s_addr;
   memcpy(&msg->payload.prefix[0],tmp,B32);


 }else if(strcmp(input[1].data.string_val,"-1")){

   void *dst = malloc(sizeof(struct in6_addr));
   inet_pton(AF_INET6, input[1].data.string_val, dst);
   unsigned char * tmp = (unsigned char *) ((struct in6_addr *)dst)->s6_addr;
   memcpy(&msg->payload.prefix[0],tmp,B64);
   memcpy(&msg->payload.prefix[1],tmp+B64,B64);

 }else{
     SRP_LOG_DBG_MSG("Invalid local IP address");
     return SR_ERR_OPERATION_FAILED;
 }



 msg->payload.len = input[2].data.uint8_val;

 vapi_msg_hicn_api_route_get_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_route_get_reply_ntoh(resp);

 if(!resp->payload.retval){
     SRP_LOG_DBG_MSG("Successfully done");
     return SR_ERR_OK;
 }

 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}

/**
* @brief API to add hicn route nhops in vpp.
*/
static int hicn_route_nhops_add_cb(const char *xpath, const sr_val_t *input,
                                  const size_t input_cnt, sr_val_t **output,
                                  size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn route nhops add received successfully");
 vapi_msg_hicn_api_route_nhops_add *msg;
 vapi_msg_hicn_api_route_nhops_add_reply *resp;

 msg = vapi_alloc_hicn_api_route_nhops_add(g_vapi_ctx_instance);
   SRP_LOG_DBG("msg id:%d",msg->header._vl_msg_id);

 if(strcmp(input[0].data.string_val,"-1")){

   struct sockaddr_in sa;
   inet_pton(AF_INET,  input[0].data.string_val, &(sa.sin_addr));
   unsigned char * tmp = (unsigned char *) &sa.sin_addr.s_addr;
   memcpy(&msg->payload.prefix[0],tmp,4);


 }else if(strcmp(input[1].data.string_val,"-1")){

   void *dst = malloc(sizeof(struct in6_addr));
   inet_pton(AF_INET6, input[1].data.string_val, dst);
   unsigned char * tmp = (unsigned char *) ((struct in6_addr *)dst)->s6_addr;
   memcpy(&msg->payload.prefix[0],tmp,B64);
   memcpy(&msg->payload.prefix[1],tmp+B64,B64);

 }else{
     SRP_LOG_DBG_MSG("Invalid local IP address");
     return SR_ERR_OPERATION_FAILED;
 }

 msg->payload.len = input[2].data.uint8_val;
 msg->payload.face_ids[0] = input[3].data.uint32_val;
 msg->payload.face_ids[1] = input[4].data.uint32_val;
 msg->payload.face_ids[2] = input[5].data.uint32_val;
 msg->payload.face_ids[3] = input[6].data.uint32_val;
 msg->payload.face_ids[4] = input[7].data.uint32_val;
 msg->payload.face_ids[5] = input[8].data.uint32_val;
 msg->payload.face_ids[6] = input[9].data.uint32_val;
 msg->payload.n_faces = input[10].data.uint8_val;

 vapi_msg_hicn_api_route_nhops_add_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_route_nhops_add_reply_ntoh(resp);

 if(!resp->payload.retval){
     SRP_LOG_DBG_MSG("Successfully done");
     return SR_ERR_OK;
 }

 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}

/**
* @brief API to del hicn route in vpp.
*/
static int hicn_route_del_cb(const char *xpath, const sr_val_t *input,
                            const size_t input_cnt, sr_val_t **output,
                            size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn route del received successfully");
 vapi_msg_hicn_api_route_del *msg;
 vapi_msg_hicn_api_route_del_reply *resp;

 msg = vapi_alloc_hicn_api_route_del(g_vapi_ctx_instance);

 if(strcmp(input[0].data.string_val,"-1")){

   struct sockaddr_in sa;
   inet_pton(AF_INET,  input[0].data.string_val, &(sa.sin_addr));
   unsigned char * tmp = (unsigned char *) &sa.sin_addr.s_addr;
   memcpy(&msg->payload.prefix[0],tmp,B32);


 }else if(strcmp(input[1].data.string_val,"-1")){

   void *dst = malloc(sizeof(struct in6_addr));
   inet_pton(AF_INET6, input[1].data.string_val, dst);
   unsigned char * tmp = (unsigned char *) ((struct in6_addr *)dst)->s6_addr;
   memcpy(&msg->payload.prefix[0],tmp,B64);
   memcpy(&msg->payload.prefix[1],tmp+B64,B64);

 }else{
     SRP_LOG_DBG_MSG("Invalid local IP address");
     return SR_ERR_OPERATION_FAILED;
 }


 msg->payload.len = input[2].data.uint8_val;

 vapi_msg_hicn_api_route_del_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_route_del_reply_ntoh(resp);

 if(!resp->payload.retval){
     SRP_LOG_DBG_MSG("Successfully done");
     return SR_ERR_OK;
 }

 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}

/**
* @brief API to get face ip params in hicn in vpp.
*/
static int hicn_face_ip_params_get_cb(const char *xpath, const sr_val_t *input,
                                     const size_t input_cnt, sr_val_t **output,
                                     size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn face ip params get received successfully");
 vapi_msg_hicn_api_face_ip_params_get *msg;
 vapi_msg_hicn_api_face_ip_params_get_reply *resp;

 msg = vapi_alloc_hicn_api_face_ip_params_get(g_vapi_ctx_instance);
  SRP_LOG_DBG("msg id:%d",msg->header._vl_msg_id);

 msg->payload.faceid = input[0].data.uint32_val;

 vapi_msg_hicn_api_face_ip_params_get_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_face_ip_params_get_reply_ntoh(resp);

 if(!resp->payload.retval){
     SRP_LOG_DBG("faceid(%d)-->intfc(%d)",input[0].data.uint32_val, resp->payload.swif);
     SRP_LOG_DBG_MSG("Successfully done");
     return SR_ERR_OK;
 }

 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;

}

/**
* @brief API to get face ip params in hicn in vpp.
*/
static int hicn_punting_add_cb(const char *xpath, const sr_val_t *input,
                              const size_t input_cnt, sr_val_t **output,
                              size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn punting add received successfully");
 // allocate memory msg and resp
 vapi_msg_hicn_api_punting_add *msg;
 vapi_msg_hicn_api_punting_add_reply *resp;

 msg = vapi_alloc_hicn_api_punting_add(g_vapi_ctx_instance);
  SRP_LOG_DBG("msg id:%d",msg->header._vl_msg_id);


 if(strcmp(input[0].data.string_val,"-1")){

   struct sockaddr_in sa;
   // store this IP address in sa:
   inet_pton(AF_INET,  input[0].data.string_val, &(sa.sin_addr));
   unsigned char * tmp =  (unsigned char *) &sa.sin_addr.s_addr;
   memcpy(&msg->payload.prefix[0],tmp,B32);


 }else if(strcmp(input[1].data.string_val,"-1")){

   void *dst = malloc(sizeof(struct in6_addr));
   inet_pton(AF_INET6, input[1].data.string_val, dst);
   unsigned char * tmp =(unsigned char *) ((struct in6_addr *)dst)->s6_addr;
   memcpy(&msg->payload.prefix[0],tmp,B64);
   memcpy(&msg->payload.prefix[1],tmp+B64,B64);

 }else{
     SRP_LOG_DBG_MSG("Invalid local IP address");
     return SR_ERR_OPERATION_FAILED;
 }

 msg->payload.len = input[2].data.uint8_val;
 msg->payload.swif = input[3].data.uint32_val;


 vapi_msg_hicn_api_punting_add_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_punting_add_reply_ntoh(resp);

 if(!resp->payload.retval){
       SRP_LOG_DBG_MSG("Successfully done");
       return SR_ERR_OK;
 }

 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}

/**
* @brief API to del hicn route nhops in vpp.
*/
static int hicn_route_nhops_del_cb(const char *xpath, const sr_val_t *input,
                                  const size_t input_cnt, sr_val_t **output,
                                  size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn route nhop del received successfully");
 // allocate memory msg and resp
 vapi_msg_hicn_api_route_nhop_del *msg;
 vapi_msg_hicn_api_route_nhop_del_reply *resp;

 msg = vapi_alloc_hicn_api_route_nhop_del(g_vapi_ctx_instance);
  SRP_LOG_DBG("msg id:%d",msg->header._vl_msg_id);


 if(strcmp(input[0].data.string_val,"-1")){

   struct sockaddr_in sa;
   // store this IP address in sa:
   inet_pton(AF_INET,  input[0].data.string_val, &(sa.sin_addr));
   unsigned char * tmp = (unsigned char *) &sa.sin_addr.s_addr;
   memcpy(&msg->payload.prefix[0],tmp,B32);


 }else if(strcmp(input[1].data.string_val,"-1")){

   void *dst = malloc(sizeof(struct in6_addr));
   inet_pton(AF_INET6, input[1].data.string_val, dst);
   unsigned char * tmp = (unsigned char *) ((struct in6_addr *)dst)->s6_addr;
   memcpy(&msg->payload.prefix[0],tmp,B64);
   memcpy(&msg->payload.prefix[1],tmp+B64,B64);

 }else{
     SRP_LOG_DBG_MSG("Invalid local IP address");
     return SR_ERR_OPERATION_FAILED;
 }


 msg->payload.len = input[2].data.uint8_val;
 msg->payload.faceid = input[3].data.uint32_val;

 vapi_msg_hicn_api_route_nhop_del_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_route_nhop_del_reply_ntoh(resp);

 if(!resp->payload.retval){
       SRP_LOG_DBG_MSG("Successfully done");
       return SR_ERR_OK;
 }


 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}

/**
* @brief API to del hicn punting in vpp.
*/
static int hicn_punting_del_cb(const char *xpath, const sr_val_t *input,
                              const size_t input_cnt, sr_val_t **output,
                              size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn punting del received successfully");
 // allocate memory msg and resp
 vapi_msg_hicn_api_punting_del *msg;
 vapi_msg_hicn_api_punting_del_reply *resp;

 msg = vapi_alloc_hicn_api_punting_del(g_vapi_ctx_instance);
  SRP_LOG_DBG("msg id:%d",msg->header._vl_msg_id);


 if(strcmp(input[0].data.string_val,"-1")){

   struct sockaddr_in sa;
   inet_pton(AF_INET,  input[0].data.string_val, &(sa.sin_addr));
   unsigned char * tmp = (unsigned char *) &sa.sin_addr.s_addr;
   memcpy(&msg->payload.prefix[0],tmp,B32);


 }else if(strcmp(input[1].data.string_val,"-1")){

   void *dst = malloc(sizeof(struct in6_addr));
   inet_pton(AF_INET6, input[1].data.string_val, dst);
   unsigned char * tmp = (unsigned char *) ((struct in6_addr *)dst)->s6_addr;
   memcpy(&msg->payload.prefix[0],tmp,B64);
   memcpy(&msg->payload.prefix[1],tmp+B64,B64);

 }else{
     SRP_LOG_DBG_MSG("Invalid local IP address");
     return SR_ERR_OPERATION_FAILED;
 }


 msg->payload.len = input[2].data.uint8_val;
 msg->payload.swif = input[3].data.uint32_val;

 vapi_msg_hicn_api_punting_del_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_punting_del_reply_ntoh(resp);

 if(!resp->payload.retval){
     SRP_LOG_DBG_MSG("Successfully done");
     return SR_ERR_OK;
 }


 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}

/**
* @brief API to del hicn face ip in vpp.
*/
static int hicn_face_ip_del_cb(const char *xpath, const sr_val_t *input,
                              const size_t input_cnt, sr_val_t **output,
                              size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn face ip del received successfully");
 // allocate memory msg and resp
 vapi_msg_hicn_api_face_ip_del *msg;
 vapi_msg_hicn_api_face_ip_del_reply *resp;

 msg = vapi_alloc_hicn_api_face_ip_del(g_vapi_ctx_instance);
  SRP_LOG_DBG("msg id:%d",msg->header._vl_msg_id);
 msg->payload.faceid = input[0].data.uint32_val;

 vapi_msg_hicn_api_face_ip_del_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_face_ip_del_reply_ntoh(resp);

 if(!resp->payload.retval){
     SRP_LOG_DBG_MSG("Successfully done");
     return SR_ERR_OK;
 }

 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}

/**
* @brief API to del hicn face ip in vpp.
*/
static int hicn_face_ip_add_cb(const char *xpath, const sr_val_t *input,
                              const size_t input_cnt, sr_val_t **output,
                              size_t *output_cnt, void *private_ctx) {

 SRP_LOG_DBG_MSG("hicn face ip add received successfully");


 vapi_msg_hicn_api_face_ip_add *msg;
 vapi_msg_hicn_api_face_ip_add_reply *resp;

 msg = vapi_alloc_hicn_api_face_ip_add(g_vapi_ctx_instance);
 SRP_LOG_DBG("msg id:%d",msg->header._vl_msg_id);
 if(strcmp(input[0].data.string_val,"-1")){
     struct sockaddr_in sa;
     inet_pton(AF_INET,  input[0].data.string_val, &(sa.sin_addr));
     unsigned char * tmp = (unsigned char *) &sa.sin_addr.s_addr;
     memcpy(&msg->payload.local_addr[0],tmp,B32);

 }else if(strcmp(input[1].data.string_val,"-1")){

     void *dst = malloc(sizeof(struct in6_addr));
     inet_pton(AF_INET6, input[1].data.string_val, dst);
     unsigned char * tmp = (unsigned char *) ((struct in6_addr *)dst)->s6_addr;
     memcpy(&msg->payload.local_addr[0],tmp,B64);
     memcpy(&msg->payload.local_addr[1],tmp+B64,B64);

 }else{
     SRP_LOG_DBG_MSG("Invalid local IP address");
     return SR_ERR_OPERATION_FAILED;
 }

 if(strcmp(input[2].data.string_val,"-1")){

     struct sockaddr_in sa;
     inet_pton(AF_INET,  input[2].data.string_val, &(sa.sin_addr));
     unsigned char * tmp = (unsigned char *)&sa.sin_addr.s_addr;
     memcpy(&msg->payload.remote_addr[0],tmp,B32);


 }else if(strcmp(input[3].data.string_val,"-1")){

     void *dst = malloc(sizeof(struct in6_addr));
     inet_pton(AF_INET6, input[3].data.string_val, dst);
     unsigned char * tmp =(unsigned char *) ((struct in6_addr *)dst)->s6_addr;
     memcpy(&msg->payload.remote_addr[0],tmp,B64);
     memcpy(&msg->payload.remote_addr[1],tmp+B64,B64);

 }else{
     SRP_LOG_DBG_MSG("Invalid local IP address");
     return SR_ERR_OPERATION_FAILED;
 }

 msg->payload.swif = input[4].data.uint32_val;  // This is the idx number of interface


 vapi_msg_hicn_api_face_ip_add_hton(msg);
 params_send(msg,resp);
 vapi_msg_hicn_api_face_ip_add_reply_ntoh(resp);

 if(!resp->payload.retval){
     SRP_LOG_DBG_MSG("Successfully done");
     return SR_ERR_OK;
 }

 SRP_LOG_DBG_MSG("Operation failed");
 return SR_ERR_OPERATION_FAILED;
}


static vapi_error_e
hicn_api_face_stats_dump_cb(struct vapi_ctx_s *ctx, void *callback_ctx,
                    vapi_error_e rv, bool is_last,
                    vapi_payload_hicn_api_face_stats_details *reply)
{

   static int counter = 0;
/*
   UNUSED(ctx); UNUSED(rv); UNUSED(is_last);
   //struct elt **stackp;
   ARG_CHECK2(VAPI_EINVAL, callback_ctx, reply);
   stackp = (struct elt**) callback_ctx;
   SRP_LOG_DBG("reply: %d:%d:%d", reply->faceid,reply->dtx_packets,reply->irx_packets);

   vapi_payload_hicn_api_face_stats_details *passed;
   ARG_CHECK2(VAPI_EINVAL, callback_ctx, reply);
   passed = (vapi_payload_hicn_api_face_stats_details *) callback_ctx;
   *passed = *reply;
   SRP_LOG_DBG("reply %d", reply->faceid);*/

   tlock(lfaces);
   if (reply!=NULL){

     current->face.faceid =  reply->faceid;
     current->face.intfc =   1;
     current->face.irx_packets = reply->irx_packets;
     current->face.irx_bytes =   reply->irx_bytes;
     current->face.itx_packets = reply->itx_packets;
     current->face.itx_bytes =   reply->itx_bytes;
     current->face.drx_packets = reply->drx_packets;
     current->face.drx_bytes =   reply->drx_bytes;
     current->face.dtx_packets = reply->dtx_packets;
     current->face.dtx_bytes =   reply->dtx_bytes;
     //hicn_faces->nface++; // Increment the number of faces
     counter++;
     current = current->next;
     //current->next = memalign(MEM_ALIGN, sizeof(hicn_faces_t));
     SRP_LOG_DBG_MSG("---------Face------- \n");
     SRP_LOG_DBG("reply %d", reply->faceid);
     SRP_LOG_DBG("reply %d", reply->drx_bytes);
     SRP_LOG_DBG("reply %d", reply->dtx_bytes);

   }else
   {
     hicn_faces->nface=counter;
     counter=0;
     current=hicn_faces->next;
   }
   tunlock(lfaces);
   return SR_ERR_OK;
}

/**
* @brief API to del hicn face state details in vpp.
*/

static int hicn_face_stats_details_cb(const char *xpath, const sr_val_t *input,
                              const size_t input_cnt, sr_val_t **output,
                              size_t *output_cnt, void *private_ctx) {
 //struct elt* stack=NULL ;
 SRP_LOG_DBG_MSG("hicn face state details received successfully");
 vapi_payload_hicn_api_face_stats_details resp={0};
 vapi_msg_hicn_api_face_stats_dump *msg;
 msg = vapi_alloc_hicn_api_face_stats_dump(g_vapi_ctx_instance);
 vapi_hicn_api_face_stats_dump(g_vapi_ctx_instance, msg, hicn_api_face_stats_dump_cb, &resp);
 return SR_ERR_OK;
}


/**
* @brief Thread to update the state
*/
static void *state_thread(void *arg) {

 // mapping can be retrieved by cpuinfo
 int map = 0;
 cpu_set_t cpuset;
 CPU_ZERO(&cpuset);
 CPU_SET(map, &cpuset);

 // pin the thread to a core
 if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset))
 {
     SRP_LOG_DBG_MSG("Thread pining failed\n");
     exit(1);
 }

 vapi_msg_hicn_api_node_stats_get *msg=NULL;
 vapi_msg_hicn_api_node_stats_get_reply *resp=NULL;
 enum locks_name state;
 state=lstate;

 while(true){

  msg = vapi_alloc_hicn_api_node_stats_get(g_vapi_ctx_instance);
  vapi_msg_hicn_api_node_stats_get_hton(msg);

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
     SRP_LOG_DBG_MSG("Sending msg to VPP failed");
     // Here I should think about a recovery method
     return NULL;
  }

   HICN_VPP_VAPI_RECV;

   vapi_msg_hicn_api_node_stats_get_reply_ntoh(resp);

   if(resp->payload.retval){
       SRP_LOG_DBG_MSG("Error updating state");
       // Here I should think about a recovery method
       return NULL;
   }

   //vapi_payload_hicn_api_face_stats_details  resp_dump={0};
   vapi_msg_hicn_api_face_stats_dump *msg;
   msg = vapi_alloc_hicn_api_face_stats_dump(g_vapi_ctx_instance);
   vapi_hicn_api_face_stats_dump(g_vapi_ctx_instance, msg, hicn_api_face_stats_dump_cb, current);

   tlock(state);
   state_cache(resp);
   SRP_LOG_DBG_MSG("state updated");
   tunlock(state);
   sleep(1);

 }
 return NULL;
}

static int hicn_state_host_cb(const char *xpath, sr_val_t **values,
                        size_t *values_cnt, uint64_t request_id,
                        const char *original_xpath, void *private_ctx) {

 sr_val_t *vals;
 int rc;
 SRP_LOG_DBG("Requesting state data for '%s'", xpath);

 if (!sr_xpath_node_name_eq(xpath, "host")) {
   *values = NULL;
   *values_cnt = 0;
   return SR_ERR_OK;
 }

 rc = sr_new_values(3, &vals);
 if (SR_ERR_OK != rc) {
   return rc;
 }

 SRP_LOG_DBG("Requesting state data for '%s'", xpath);

 host_speed();

 sr_val_set_xpath(&vals[0], "/hicn:hicn-state/host/eth1");
 vals[0].type = SR_UINT64_T;
 vals[0].data.uint64_val = teth1;

 sr_val_set_xpath(&vals[1], "/hicn:hicn-state/host/eth2");
 vals[1].type = SR_UINT64_T;
 vals[1].data.uint64_val = teth2;

 sr_val_set_xpath(&vals[2], "/hicn:hicn-state/host/eth3");
 vals[2].type = SR_UINT64_T;
 vals[2].data.uint64_val = teth3;

 SRP_LOG_DBG("-------->teth1:%d",teth1);
 SRP_LOG_DBG("-------->teth2:%d",teth2);
 SRP_LOG_DBG("-------->teth3:%d",teth3);


 *values = vals;
 *values_cnt = 3;

 return SR_ERR_OK;

}

/**
* @brief helper function for subscribing all hicn APIs.
*/
int hicn_subscribe_events(sr_session_ctx_t *session,
                         sr_subscription_ctx_t **subscription) {
   int rc = SR_ERR_OK;
   SRP_LOG_DBG_MSG("Subscriging hicn.");

   pthread_t state_tid;
   rc = pthread_create((pthread_t *)&state_tid, NULL, state_thread, NULL);
   if (rc != 0) {
         SRP_LOG_DBG_MSG("Error making hicn state thread");
         return SR_ERR_OPERATION_FAILED;
   }
   SRP_LOG_DBG_MSG("State thread created successfully.");

   //Initializing the locks
   for (int i=0; i<NLOCKS; i++)
     ticket_init(i,LOCK_INIT);

   //Initializing the buffer
   rc=init_buffer();
   if(rc!= SR_ERR_OK){
       SRP_LOG_DBG_MSG("Problem in initializing the buffers\n");
       goto error;
   }

   SRP_LOG_DBG_MSG("buffer initialized successfully.");


   rc=init_face_pool(current);

   if(rc!= SR_ERR_OK){
       SRP_LOG_DBG_MSG("Problem in initializing the face pool\n");
       goto error;
   }


   SRP_LOG_DBG_MSG("face pool created successfully.");


   // node state subscriptions

   rc = sr_rpc_subscribe(session, "/hicn:node-params-get", hicn_node_params_get_cb,
   session, SR_SUBSCR_CTX_REUSE, subscription);
   if (rc != SR_ERR_OK) {
     SRP_LOG_DBG_MSG("Problem in subscription node-params-get\n");
     goto error;
   }


   // node state subscriptions

   rc = sr_rpc_subscribe(session, "/hicn:node-stat-get", hicn_node_stat_get_cb,
   session, SR_SUBSCR_CTX_REUSE, subscription);
   if (rc != SR_ERR_OK) {
     SRP_LOG_DBG_MSG("Problem in subscription stat-get\n");
     goto error;
   }

   // strategies subscriptions

   rc = sr_rpc_subscribe(session, "/hicn:strategy-get", hicn_strategy_get_cb,
   session, SR_SUBSCR_CTX_REUSE, subscription);
   if (rc != SR_ERR_OK) {
     SRP_LOG_DBG_MSG("Problem in subscription strategy-get\n");
     goto error;
   }

   rc = sr_rpc_subscribe(session, "/hicn:strategies-get",
   hicn_strategies_get_cb, session, SR_SUBSCR_CTX_REUSE, subscription);
   if (rc!= SR_ERR_OK) {
      SRP_LOG_DBG_MSG("Problem in subscription strategies-get\n");
      goto error;
   }

   // route subscriptions

   rc = sr_rpc_subscribe(session, "/hicn:route-get", hicn_route_get_cb,
   session, SR_SUBSCR_CTX_REUSE, subscription);
   if (rc != SR_ERR_OK) {
     SRP_LOG_DBG_MSG("Problem in subscription route-get\n");
     goto error;
   }

   rc = sr_rpc_subscribe(session, "/hicn:route-del", hicn_route_del_cb,
   session, SR_SUBSCR_CTX_REUSE, subscription);
   if (rc != SR_ERR_OK) {
     SRP_LOG_DBG_MSG("Problem in subscription route-del\n");
     goto error;
   }


   // route nhops subscriptions

   rc = sr_rpc_subscribe(session, "/hicn:route-nhops-add",
   hicn_route_nhops_add_cb, session, SR_SUBSCR_CTX_REUSE, subscription);
    if (rc!= SR_ERR_OK) {
     SRP_LOG_DBG_MSG("Problem in subscription route-nhops-add\n");
     goto error;
   }

   rc = sr_rpc_subscribe(session, "/hicn:route-nhops-del",
   hicn_route_nhops_del_cb, session, SR_SUBSCR_CTX_REUSE, subscription);
    if (rc!= SR_ERR_OK) {
      SRP_LOG_DBG_MSG("Problem in subscription route-nhops-del\n");
      goto error;
   }


   // face ip subscriptions

   rc = sr_rpc_subscribe(session, "/hicn:face-ip-params-get",
   hicn_face_ip_params_get_cb, session, SR_SUBSCR_CTX_REUSE, subscription);
   if (rc != SR_ERR_OK) {
     SRP_LOG_DBG_MSG("Problem in subscription face-ip-params-get\n");
     goto error;
   }


   rc = sr_rpc_subscribe(session, "/hicn:face-ip-add", hicn_face_ip_add_cb,
   session, SR_SUBSCR_CTX_REUSE, subscription);
   if (rc != SR_ERR_OK) {
     SRP_LOG_DBG_MSG("Problem in subscription face-ip-add\n");
     goto error;
   }

   rc = sr_rpc_subscribe(session, "/hicn:face-ip-del", hicn_face_ip_del_cb,
   session, SR_SUBSCR_CTX_REUSE, subscription);
   if (rc != SR_ERR_OK) {
     SRP_LOG_DBG_MSG("Problem in subscription face-ip-del\n");
     goto error;
   }

   // punting subscriptions

   rc = sr_rpc_subscribe(session, "/hicn:punting-add", hicn_punting_add_cb,
   session, SR_SUBSCR_CTX_REUSE, subscription);
   if (rc != SR_ERR_OK) {
     SRP_LOG_DBG_MSG("Problem in subscription punting-add\n");
     goto error;
   }

 rc = sr_rpc_subscribe(session, "/hicn:punting-del", hicn_punting_del_cb,
                       session, SR_SUBSCR_CTX_REUSE, subscription);
 if (rc != SR_ERR_OK) {
   SRP_LOG_DBG_MSG("Problem in subscription punting-del\n");
   goto error;
 }


 rc = sr_rpc_subscribe(session, "/hicn:face-stats-details", hicn_face_stats_details_cb,
                       session, SR_SUBSCR_CTX_REUSE, subscription);
 if (rc != SR_ERR_OK) {
   SRP_LOG_DBG_MSG("Problem in subscription face-stats-details\n");
   goto error;
 }

 // subscripe for edit-config
 rc = sr_subtree_change_subscribe(
     session, "/hicn:hicn-conf", hicn_node_params_set_cb, g_vapi_ctx_instance,
     0, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_EV_ENABLED, subscription);
 if (SR_ERR_OK != rc) {
   SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-conf\n");
   goto error;
 }

 // subscribe as hicn state data provider
 rc = sr_dp_get_items_subscribe(session, "/hicn:hicn-state/states",
                                hicn_state_states_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                subscription);
 if (rc != SR_ERR_OK) {
   SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-state/states\n");
   goto error;
 }

 rc = sr_dp_get_items_subscribe(session, "/hicn:hicn-state/strategies",
                                hicn_state_strategies_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                subscription);
 if (rc != SR_ERR_OK) {
   SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-state/strategies\n");
   goto error;
 }


 rc = sr_dp_get_items_subscribe(session, "/hicn:hicn-state/routes",
                                hicn_state_route_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                subscription);
 if (rc != SR_ERR_OK) {
   SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-state/routes\n");
   goto error;
 }


 rc = sr_dp_get_items_subscribe(session, "/hicn:hicn-state/faces",
                                hicn_state_faces_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                subscription);
 if (rc != SR_ERR_OK) {
   SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-state/faces\n");
   goto error;
 }

 rc = sr_dp_get_items_subscribe(session, "/hicn:hicn-state/host",
                                hicn_state_host_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                subscription);
 if (rc != SR_ERR_OK) {
   SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-state/host\n");
   goto error;
 }

 SRP_LOG_INF_MSG("hicn plugin initialized successfully.");
 return SR_ERR_OK;

error:
 SRP_LOG_ERR_MSG("Error by initialization of the hicn plugin.");
 sr_plugin_cleanup_cb(session, &g_vapi_ctx_instance);
 return rc;
}