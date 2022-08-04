/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

/**
 * \file fw_interface.c
 * \brief Implementation of fw interface
 */

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/callback.h>
#include <hicn/util/log.h>
#include <hicn/ctrl/fw_interface.h>

const char *fw_state_str[] = {
#define _(x) [FW_STATE_##x] = #x,
    foreach_fw_state
#undef _
};

struct fw_interface_s {
  /*
   * Type of forwarder to which we are connecting/connected : HICNLIGHT, VPP
   */
  forwarder_type_t type;
  fw_state_t state;

  hc_sock_t *sock;
  char *url;

  bool has_subscribe_all;

  hc_enable_callback_t enable_callback;
  hc_state_callback_t state_callback;
  void *state_callback_data;
  hc_result_callback_t result_callback;
  void *result_callback_data;
  hc_notification_callback_t notification_callback;
  void *notification_callback_data;
};

fw_interface_t *fw_interface_create_url(forwarder_type_t type,
                                        const char *url) {
  fw_interface_t *fi = malloc(sizeof(fw_interface_t));
  if (!fi) goto ERR_MALLOC;

  fi->type = type;
  /* Let's assume for now the forwarder is always on */
  fi->state = FW_STATE_AVAILABLE;
  fi->sock = NULL;
  fi->has_subscribe_all = false;
  fi->url = NULL;

  // XXX make a single request to probe for forwarder size?

  return fi;

ERR_MALLOC:
  return NULL;
}

fw_interface_t *fw_interface_create(forwarder_type_t type) {
  return fw_interface_create_url(type, NULL);
}

void fw_interface_free(fw_interface_t *fi) {
  fw_interface_disconnect(fi);
  free(fi);
}

int fw_interface_get_fd(const fw_interface_t *fi) {
  if (!fi) return 0;
  return hc_sock_get_fd(fi->sock);
}

int fw_interface_set_enable_callback(fw_interface_t *fi,
                                     hc_enable_callback_t callback) {
  fi->enable_callback = callback;
  return 0;
}

int fw_interface_set_state_callback(fw_interface_t *fi,
                                    hc_state_callback_t callback,
                                    void *callback_data) {
  fi->state_callback = callback;
  fi->state_callback_data = callback_data;
  return 0;
}

int fw_interface_set_result_callback(fw_interface_t *fi,
                                     hc_result_callback_t callback,
                                     void *callback_data) {
  fi->result_callback = callback;
  fi->result_callback_data = callback_data;
  return 0;
}

int fw_interface_set_notification_callback(fw_interface_t *fi,
                                           hc_notification_callback_t callback,
                                           void *callback_data) {
  fi->notification_callback = callback;
  fi->notification_callback_data = callback_data;
  return 0;
}

int fw_interface_enable(fw_interface_t *fi) {
  // TODO
  return 0;
}

int fw_interface_disable(fw_interface_t *fi) {
  // TODO
  return 0;
}

// XXX blocking or non blocking ?
int fw_interface_reschedule_connect(fw_interface_t *fi) {
  INFO("Scheduling reconnect...");
  // XXX TODO timer
  return 0;
}

int _fw_interface_connect(fw_interface_t *fi, bool reattempt) {
  fi->sock = hc_sock_create(fi->type, fi->url);
  if (!fi->sock) goto ERR_SOCK;

  if (hc_sock_set_async(fi->sock) < 0) goto ERR_ASYNC;

  if (hc_sock_connect(fi->sock) < 0) {
    ERROR("Error connecting to forwarder");
    return -1;
  }

  return 0;

ERR_ASYNC:
  hc_sock_free(fi->sock);
ERR_SOCK:

  if (reattempt) return fw_interface_reschedule_connect(fi);
  return -1;
}

int fw_interface_connect(fw_interface_t *fi) {
  switch (fi->state) {
    case FW_STATE_UNDEFINED:
      // XXX connect, enable, (poll)?
      break;
    case FW_STATE_DISABLED:
      fw_interface_enable(fi);
      break;
    case FW_STATE_REQUESTED:
      // XXX waiting ? polling connect ?
      break;
    case FW_STATE_AVAILABLE:
      _fw_interface_connect(fi, true);
      // XXX
      break;
    case FW_STATE_CONNECTING:
    case FW_STATE_CONNECTED:
    case FW_STATE_READY:
      /* Nothing to do */
      return 0;
    case FW_STATE_N:
      return -1;
  }
  return 0;
}

int _fw_interface_disconnect(fw_interface_t *fi) {
  if (fi->has_subscribe_all) fw_interface_unsubscribe_all(fi);
  hc_sock_free(fi->sock);
  return 0;
}

int fw_interface_disconnect(fw_interface_t *fi) {
  switch (fi->state) {
    case FW_STATE_UNDEFINED:
    case FW_STATE_DISABLED:
    case FW_STATE_REQUESTED:
    case FW_STATE_AVAILABLE:
      /* Nothing to do */
      return 0;
    case FW_STATE_CONNECTING:
    case FW_STATE_CONNECTED:
    case FW_STATE_READY:
      _fw_interface_disconnect(fi);
      return 0;
    case FW_STATE_N:
      return -1;
  }
  return 0;
}

fw_state_t fw_interface_get_state(const fw_interface_t *fi) {
  return fi->state;
}

bool fw_interface_is_connected(const fw_interface_t *fi) {
  return ((fi->state == FW_STATE_CONNECTED) || (fi->state == FW_STATE_READY));
}

bool fw_interface_is_ready(const fw_interface_t *fi) {
  return (fi->state == FW_STATE_READY);
}

int fw_interface_subscribe_all(fw_interface_t *fi) {
  INFO("fw_interface_subscribe_all");
  int rc = hc_execute_async(fi->sock, ACTION_SUBSCRIBE, OBJECT_TYPE_UNDEFINED,
                            NULL, fi->notification_callback,
                            fi->notification_callback_data);
  if (rc < 0) {
    return -1;
  }
  fi->has_subscribe_all = true;
  return 0;
}

int fw_interface_unsubscribe_all(fw_interface_t *fi) {
  fi->has_subscribe_all = false;
  return 0;
}

// face manager : upon completion, same as notification, CREATE/GET FACE
// hproxy  = event = function to call to proceed through state machine (also
// depends if we handle face+route), for notifications, telemetry.
// NOTE we should have a notif for our own events. how to handle ?
// XXX user_data .... or user_callback
int fw_interface_execute(fw_interface_t *fi, hc_action_t action,
                         hc_object_type_t object_type, hc_object_t *object,
                         hc_data_t **pdata) {
  return hc_execute(fi->sock, action, object_type, object, pdata);
}

int fw_interface_execute_async(fw_interface_t *fi, hc_action_t action,
                               hc_object_type_t object_type,
                               hc_object_t *object,
                               hc_result_callback_t callback,
                               void *callback_data) {
  if (!callback) {
    callback = fi->result_callback;
    callback_data = fi->result_callback_data;
  }
  return hc_execute_async(fi->sock, action, object_type, object, callback,
                          callback_data);
}

int fw_interface_on_receive(fw_interface_t *fi, size_t count) {
  return hc_sock_on_receive(fi->sock, count);
}

int fw_interface_get_recv_buffer(fw_interface_t *fi, uint8_t **buffer,
                                 size_t *size) {
  return hc_sock_get_recv_buffer(fi->sock, buffer, size);
}
