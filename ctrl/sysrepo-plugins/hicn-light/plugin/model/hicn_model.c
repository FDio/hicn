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
#include <stdio.h>
#include <malloc.h>
#include <sysrepo/xpath.h>

/* Hicn headers */

#include "hicn_model.h"
#include "tlock.h"
#include "../hicn_light.h"
#include "../hicn_light_comm.h"

/**
 * @brief API to del hicn face ip in vpp.
 */
static int hicn_route_add_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data) {

/*

  SRP_LOG_DBG_MSG("hicn route add received successfully");

  hc_route_t * route;

  if(strcmp(input[0].data.string_val,"-1")){

  struct sockaddr_in sa;
  // store this IP address in sa:
  inet_pton(AF_INET,  input[0].data.string_val, &(sa.sin_addr));
  route.family=AF_INET;
  route.face.hicn.local_addr.v4.as_inaddr=sa.sin_addr;


  }else if(strcmp(input[1].data.string_val,"-1")){

    struct in6_addr *dst = malloc(sizeof(struct in6_addr));
    inet_pton(AF_INET6, input[1].data.string_val, dst);
    face.face.hicn.family=AF_INET6;
    face.face.hicn.local_addr.v6.as_in6addr = *dst;

  }else{
      SRP_LOG_DBG_MSG("Invalid local IP address");
      return SR_ERR_OPERATION_FAILED;
  }


hc_route_create(hsocket, route);
*/
 return SR_ERR_OK;
}



int hicn_subscribe_events(sr_session_ctx_t *session,
                          sr_subscription_ctx_t **subscription) {


  int rc;

    rc = sr_rpc_subscribe(session, "/hicn:route-nhops-add",
    hicn_route_add_cb, session, 100,SR_SUBSCR_CTX_REUSE, subscription);
     if (rc!= SR_ERR_OK) {
      SRP_LOG_DBGMSG("Problem in subscription route-nhops-add\n");
      goto error;
    }


  SRP_LOG_DBGMSG("hicn light initialized successfully.");
  return SR_ERR_OK;

error:
  SRP_LOG_ERRMSG("Error by initialization of the hicn plugin.");
  sr_plugin_cleanup_cb(session, hsocket);
  return rc;

}
