/*
 * Copyright (c) 2018 HUACHENTEL and/or its affiliates.
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
#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/interface.api.vapi.h>
#include <vapi/l2.api.vapi.h>
#include <vapi/ip.api.vapi.h>
#include <vapi/tap.api.vapi.h>
#include <vapi/ipsec.api.vapi.h>
#include <vapi/vxlan.api.vapi.h>
#include <vnet/interface.h>
#include <vnet/mpls/mpls_types.h>



#include "hicn_plugin.h"
#include "ietf/ietf_hicn.h"



DEFINE_VAPI_MSG_IDS_VPE_API_JSON;
DEFINE_VAPI_MSG_IDS_L2_API_JSON;
DEFINE_VAPI_MSG_IDS_IP_API_JSON;
DEFINE_VAPI_MSG_IDS_TAP_API_JSON;
DEFINE_VAPI_MSG_IDS_IPSEC_API_JSON;
DEFINE_VAPI_MSG_IDS_VXLAN_API_JSON;
DEFINE_VAPI_MSG_IDS_HICN_API_JSON;

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
  HICN_INVOKE_BEGIN;
  sr_subscription_ctx_t *subscription = NULL;
  int rc = SR_ERR_OK;
  rc = hicn_connect_vpp();
  if (SR_ERR_OK != rc)
    {
      HICN_LOG_ERR("vpp connect error , with return %d.", rc);
      return SR_ERR_INTERNAL;
    }

  //SC_REGISTER_RPC_EVT_HANDLER(sc_ip_subscribe_route_events);
  //SC_REGISTER_RPC_EVT_HANDLER(sc_vxlan_subscribe_tunnel_events);
  //SC_REGISTER_RPC_EVT_HANDLER(sc_l2_bridge_domain_add_del_subscribe_events);
  //SC_REGISTER_RPC_EVT_HANDLER(sc_l2_interface_set_l2_bridge_subscribe_events);
	

  //HICN interface 
  hicn_subscribe_events(session, &subscription);


  /* set subscription as our private context */
  *private_ctx = subscription;
  HICN_INVOKE_END;
  return SR_ERR_OK;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
  HICN_INVOKE_BEGIN;

 // openconfig_plugin_cleanup();

  /* subscription was set as our private context */
  sr_unsubscribe(session, private_ctx);
  HICN_LOG_DBG_MSG("hicn pligin unload plugin ok.");
  sc_disconnect_vpp();
  HICN_LOG_DBG_MSG("hicn plugin disconnect vpp ok.");
  HICN_INVOKE_END;
}


///#############################
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
sr_subscription_ctx_t *subscription = NULL;
volatile int exit_application = 0;

static void
sigint_handler(int signum)
{
  exit_application = 1;
}
int 
subscribe_all_module_events(sr_session_ctx_t *session)
{
  sr_plugin_init_cb(session, (void**)&subscription);
  return 0;
}
int
main(int argc, char **argv)
{
  sr_conn_ctx_t *connection = NULL;
  sr_session_ctx_t *session = NULL;
  int rc = SR_ERR_OK;

  /* connect to vpp */
  rc = hicn_connect_vpp();
  if (-1 == rc){
    fprintf(stderr, "vpp connect error");
    return -1;
  }
    
  /* connect to sysrepo */
  rc = sr_connect("cpe_application", SR_CONN_DEFAULT, &connection);
  if (SR_ERR_OK != rc) {
    fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
    goto cleanup;
  }

  /* start session */
  rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
  if (SR_ERR_OK != rc) {
    fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
    goto cleanup;
  }

  /* subscribe all module events */
  rc = subscribe_all_module_events(session);
  if (SR_ERR_OK != rc) {
    fprintf(stderr, "Error by subscribe module events: %s\n", sr_strerror(rc));
    goto cleanup;
  }
    
  /* loop until ctrl-c is pressed / SIGINT is received */
  signal(SIGINT, sigint_handler);
  signal(SIGPIPE, SIG_IGN);

  while (!exit_application) {
    sleep(2);
  }

  printf("Application exit requested, exiting.\n");

 cleanup:
  if (NULL != subscription) {
    sr_unsubscribe(session, subscription);
  }
  if (NULL != session) {
    sr_session_stop(session);
  }
  if (NULL != connection) {
    sr_disconnect(connection);
  }
  hicn_disconnect_vpp();
  return rc;
}
