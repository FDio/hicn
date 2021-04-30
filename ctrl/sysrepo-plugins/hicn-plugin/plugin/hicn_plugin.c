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
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "hicn_plugin.h"
#include "model/hicn_model.h"
#include "ietf/ietf_interface.h"


sr_subscription_ctx_t *subscription = NULL;
volatile int exit_application = 0;

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx) {

  sr_subscription_ctx_t *subscription = NULL;
  int rc = SR_ERR_OK;
  rc = hicn_connect_vpp();
  if (SR_ERR_OK != rc) {
    return SR_ERR_INTERNAL;
  }

  // HICN subscribe
  hicn_subscribe_events(session, &subscription);

  //sr_subscription_ctx_t *subscription2 = NULL;

  // IETF subscribe
  //ietf_subscribe_events(session, &subscription2);


  /* set subscription as our private context */
  *private_ctx = subscription;

  return SR_ERR_OK;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx) {

  /* subscription was set as our private context */
  sr_unsubscribe(private_ctx);
  hicn_disconnect_vpp();
}

static void sigint_handler(int signum) { exit_application = 1; }
int subscribe_all_module_events(sr_session_ctx_t *session) {
  sr_plugin_init_cb(session, (void **)&subscription);
  return 0;
}

int main(int argc, char **argv) {
  sr_conn_ctx_t *connection = NULL;
  sr_session_ctx_t *session = NULL;
  int rc = SR_ERR_OK;
  /* connect to vpp */
  rc = hicn_connect_vpp();
  if (-1 == rc) {
    fprintf(stderr, "vpp connect error");
    return -1;
  }

  /* connect to sysrepo */
  rc = sr_connect(SR_CONN_DEFAULT, &connection);
  if (SR_ERR_OK != rc) {
    fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
    goto cleanup;
  }

  /* start session */
  rc = sr_session_start(connection, SR_DS_STARTUP, &session);
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
    sr_unsubscribe(subscription);
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