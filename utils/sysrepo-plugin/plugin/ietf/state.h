
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

#ifndef __STATE_H__
#define __STATE_H__

#include "../hicn_vpp_comm.h"

DEFINE_VAPI_MSG_IDS_HICN_API_JSON;
vapi_ctx_t g_vapi_ctx_instance;

static void *
state_thread(void *arg)
{

  //  while (1) {

   //   sleep(1);
    vapi_msg_hicn_api_node_stats_get * msg;
    vapi_msg_hicn_api_node_stats_get_reply *resp;
    sr_val_t *val;
    vapi_error_e rv;
    int rc;

    msg=vapi_alloc_hicn_api_node_stats_get(g_vapi_ctx_instance);
    vapi_msg_hicn_api_node_stats_get_hton(msg);

    if (VAPI_OK!=vapi_send(g_vapi_ctx_instance, msg)){
        SRP_LOG_DBG_MSG("Sending msg to VPP failed");
        return SR_ERR_OPERATION_FAILED;
    }

    HICN_VPP_VAPI_RECV;
    vapi_msg_hicn_api_node_stats_get_ntoh(resp);



    rc = sr_new_values(1, &val);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    sr_val_set_xpath(val, "/hicn:hicn-state-data/states/pkts_processed");
    val[0].type = SR_UINT64_T;
    val[0].data.uint64_val = 10;//resp->payload.pkts_processed;

   // *values = val;
    //*values_cnt = 1;
    sr_free_val(val);

    SRP_LOG_DBG_MSG("hicn status receive successfully");

    return NULL;

}

#endif /* __IETF_HICN_H__ */