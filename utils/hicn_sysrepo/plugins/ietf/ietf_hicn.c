/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../hicn_plugin.h"
#include <sysrepo.h>
#include <sysrepo/plugins.h>
#include <sysrepo/values.h>
#include <sysrepo/xpath.h>
#include <vnet/interface.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vapi/interface.api.vapi.h>

/* Hicn headers */

#include "ietf_hicn.h"
#include<vpp_plugins/hicn/hicn.api.vapi.h>

#include "../hicn_vpp_comm.h"

vapi_ctx_t g_vapi_ctx_instance ;

DEFINE_VAPI_MSG_IDS_HICN_API_JSON;

/* hicn state value determining whether the hicn is enabled inside the vpp or not */
volatile int enabled=0;


/**
 * @brief API to enable hicn in vpp.
 */
vapi_error_e hicn_param_set(struct vapi_ctx_s *ctx,
                           void *callback_ctx,
                           vapi_error_e rv,
                           bool is_last,
                           vapi_payload_hicn_api_node_params_set_reply *reply)
{
    hicn_ctx *dctx = callback_ctx; 
    printf("It is done! %d", dctx->last_called);
    fflush(stdout);
    return VAPI_OK;
}

/**
 * @brief API to enable hicn in vpp.
 */
hicn_enable_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                sr_val_t **output, size_t *output_cnt, void *private_ctx)
{

    if (enabled) {
        SRP_LOG_ERR_MSG("hicn is already enabled.");
        return ;
    }

printf("this is my code");
fflush(stdout);
/*
    // allocate memory msg and resp
    vapi_msg_hicn_api_node_params_set * msg;  
    vapi_msg_hicn_api_node_params_set_reply *resp;


    vapi_error_e rv;
    hicn_ctx dctx={false,0,0};
    msg=vapi_alloc_hicn_api_node_params_set(g_vapi_ctx_instance); 
    msg->payload.enable_disable=1;
    rv = vapi_hicn_api_node_params_set(g_vapi_ctx_instance, msg, hicn_param_set, &dctx);   
    SRP_LOG_DBG_MSG("------msg sent------");
 */

/*
    // construct msg 
    SRP_LOG_DBG_MSG("------allocating msg------");
    msg=vapi_alloc_hicn_api_node_params_set(g_vapi_ctx_instance); 
    memset (msg, 0, sizeof (*msg));
    msg->payload.enable_disable=1;

    //printf("Size of msg %d-%d", sizeof(vapi_msg_hicn_api_node_params_set), msg->header._vl_msg_id);
    //fflush(stdout);
    vapi_msg_hicn_api_node_params_set_hton(msg);// for more than one byte 
    // sned msg by the vapi 
    SRP_LOG_DBG_MSG("------sending msg------");
    if (VAPI_OK!=vapi_send(g_vapi_ctx_instance, msg)){
        SRP_LOG_DBG_MSG("*****Sending msg to VPP failed*****");
        return SR_ERR_OPERATION_FAILED;
    }   
*/


/*  Helper 
    vapi_msg_sw_interface_set_flags *msg = vapi_alloc_sw_interface_set_flags(g_vapi_ctx_instance);
    msg->payload.admin_up_down = 1;
    vapi_msg_sw_interface_set_flags_hton(msg);
    vapi_error_e rv = vapi_send (g_vapi_ctx_instance, msg);
*/

    // receive resp by the vapi  
   // SRP_LOG_DBG_MSG("------receiving resp------");
   // SC_VPP_VAPI_RECV;
   // vapi_msg_hicn_api_node_params_set_reply_hton(resp);
    //Free up the memory    
   // vapi_msg_free (g_vapi_ctx_instance, resp);


     vapi_msg_hicn_api_node_params_get * msg;
     vapi_msg_hicn_api_node_params_get_reply * resp;
    vapi_error_e rv;

    msg=vapi_alloc_hicn_api_node_params_get(g_vapi_ctx_instance);
     if (VAPI_OK!=vapi_send(g_vapi_ctx_instance, msg)){
        SRP_LOG_DBG_MSG("*****Sending msg to VPP failed*****");
        return SR_ERR_OPERATION_FAILED;
     } 
     
     HICN_VPP_VAPI_RECV;


    enabled=1;
    SRP_LOG_DBG_MSG("------hicn enabled into the vpp------");
    return SR_ERR_OK;

}

/**
 * @brief Helper function for subscribing all hicn modules.
 */
int
hicn_subscribe_events(sr_session_ctx_t *session,
			      sr_subscription_ctx_t **subscription)
{

    int rc = SR_ERR_OK;
    SRP_LOG_DBG_MSG("Initializing hicn-interfaces plugin.");

    rc = sr_rpc_subscribe(session, "/hicn:hicn-enable", hicn_enable_cb, NULL, SR_SUBSCR_CTX_REUSE, subscription);
    if (rc != SR_ERR_OK) {
        printf("Problem in subscription\n");
        goto error;
    }

    /* Add here one by one more APIs*/


    SRP_LOG_INF_MSG("hicn plugin initialized successfully.");

    return SR_ERR_OK;


error:
    SRP_LOG_ERR_MSG("Error by initialization of the hicn plugin.");
    sr_plugin_cleanup_cb(session, &g_vapi_ctx_instance);
    return rc;

}