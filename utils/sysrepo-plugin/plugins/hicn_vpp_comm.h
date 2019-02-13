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

#ifndef __HICN_VPP_COMMM_H__
#define __HICN_VPP_COMMM_H__
#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
DEFINE_VAPI_MSG_IDS_VPE_API_JSON;

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <sysrepo/plugins.h>   //for HICN_LOG_DBG

#ifndef HICN_THIS_FUNC
#ifdef __FUNCTION__
#define HICN_THIS_FUNC __FUNCTION__
#else
#define HICN_THIS_FUNC __func__
#endif
#endif

#ifndef _NOLOG
#define HICN_LOG_DBG SRP_LOG_DBG
#define HICN_LOG_ERR SRP_LOG_ERR
#define HICN_LOG_DBG_MSG SRP_LOG_DBG_MSG
#define HICN_LOG_ERR_MSG SRP_LOG_ERR_MSG
#else
#define HICN_LOG_DBG //printf
#define HICN_LOG_DBG //SRP_LOG_DBG
#define HICN_LOG_ERR //SRP_LOG_ERR
#define HICN_LOG_DBG_MSG //SRP_LOG_DBG_MSG
#define HICN_LOG_ERR_MSG //SRP_LOG_ERR_MSG
#endif

#define HICN_INVOKE_BEGIN HICN_LOG_DBG("inovke %s bein.",HICN_THIS_FUNC);
#define HICN_INVOKE_END   HICN_LOG_DBG("inovke %s end,with return OK.",HICN_THIS_FUNC);
#define HICN_INVOKE_ENDX(...)  HICN_LOG_DBG("inovke %s end,with %s.",HICN_THIS_FUNC, ##__VA_ARGS__)

#define ARG_CHECK(retval, arg) \
    do \
    { \
        if (NULL == (arg)) \
        { \
            HICN_LOG_ERR_MSG(#arg ":NULL pointer passed."); \
            return (retval); \
        } \
    } \
    while (0)

/**
 * when use tihs must fist DEFINE_VAPI_MSG_IDS_VXLAN_API_JSON
 */
#define HICN_VPP_VAPI_RECV \
do { \
	size_t size; \
	int recv_vapimsgid = -1; \
	rv = vapi_recv (g_vapi_ctx_instance, (void *) &resp, &size, 0, 0); \
	recv_vapimsgid = vapi_lookup_vapi_msg_id_t(g_vapi_ctx_instance, ntohs(resp->header._vl_msg_id) ); \
	if(recv_vapimsgid <= vapi_msg_id_get_next_index_reply \
		|| recv_vapimsgid >= vapi_get_message_count ()) { \
	  HICN_LOG_DBG("***recv error msgid[%d] not in [0-%d) ,try again!***\n", \
					  recv_vapimsgid, vapi_get_message_count ()); \
	} else { \
	  HICN_LOG_DBG("recv msgid [%d]\n", recv_vapimsgid); \
	  break; \
	} \
  } while(1);

#define HICN_REGISTER_RPC_EVT_HANDLER(rpc_evt_handle) \
do { \
	sr_error_t rc = rpc_evt_handle(session, &subscription); \
	if (SR_ERR_OK != rc) \
	{ \
		HICN_LOG_ERR("load plugin failed: %s", sr_strerror(rc)); \
		sr_unsubscribe(session, subscription); \
		HICN_INVOKE_ENDX(sr_strerror(rc)); \
		return rc; \
	} \
} while(0);


int hicn_connect_vpp();
int hicn_disconnect_vpp();
extern vapi_ctx_t g_vapi_ctx_instance;
#endif //__HICN_VPP_COMMM_H__