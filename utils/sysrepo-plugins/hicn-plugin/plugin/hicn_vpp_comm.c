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
#include "hicn_vpp_comm.h"




#define APP_NAME "hicn_plugin"
#define MAX_OUTSTANDING_REQUESTS 4
#define RESPONSE_QUEUE_SIZE 2
vapi_ctx_t g_vapi_ctx_instance=NULL;
DEFINE_VAPI_MSG_IDS_HICN_API_JSON;

int hicn_connect_vpp() {
  HICN_INVOKE_BEGIN;
  if (g_vapi_ctx_instance == NULL) {
    vapi_error_e rv = vapi_ctx_alloc(&g_vapi_ctx_instance);
    rv = vapi_connect(g_vapi_ctx_instance, APP_NAME, NULL,
                      MAX_OUTSTANDING_REQUESTS, RESPONSE_QUEUE_SIZE,
                      VAPI_MODE_BLOCKING, true);
    if (rv != VAPI_OK) {
      HICN_LOG_ERR("*connect %s faild,with return %d", APP_NAME, rv);
      vapi_ctx_free(g_vapi_ctx_instance);
      return -1;
    }
    HICN_LOG_DBG("*connected %s ok", APP_NAME);
  } else {
    HICN_LOG_DBG("connection %s keeping", APP_NAME);
  }
  HICN_INVOKE_END;
  return 0;
}

int hicn_disconnect_vpp() {
  if (NULL != g_vapi_ctx_instance) {
    vapi_disconnect(g_vapi_ctx_instance);
    vapi_ctx_free(g_vapi_ctx_instance);
    g_vapi_ctx_instance = NULL;
  }
  return 0;
}