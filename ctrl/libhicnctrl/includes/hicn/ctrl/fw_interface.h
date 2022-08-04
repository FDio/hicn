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

#ifndef HICNCTRL_FW_INTERFACE_H
#define HICNCTRL_FW_INTERFACE_H

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/callback.h>

/**
 * \file fw_interface.h
 * \brief Forwarder interface
 *
 * Forwarder interface is designed to be a reusable module (that might be
 * wrapped in a C++ class), providing a fw-agnostic interface with the
 * following goals:
 *  - maintaining a permanent connection to the fw (and keep track of the
 *  fw state, eventually caching some aspects)
 *  - allowing the tracking of multiplexed requests
 *  - supporting a stream of concurrent notifications that might be needed to
 *  synchronize states.
 *
 * It is design to be easily integrated with the different event loops used
 * across the projects (libevent for C, asio for C++).
 */

#define foreach_fw_state                       \
  _(UNDEFINED)                                 \
  _(DISABLED)   /* stack is stopped */         \
  _(REQUESTED)  /* stack is starting */        \
  _(AVAILABLE)  /* forwarder is running */     \
  _(CONNECTING) /* XXX NEW */                  \
  _(CONNECTED)  /* control socket connected */ \
  _(READY)      /* listener is present */      \
  _(N)

typedef enum {
#define _(x) FW_STATE_##x,
  foreach_fw_state
#undef _
} fw_state_t;

extern const char *fw_state_str[];

#define fw_state_str(x) fw_state_str[x]

typedef struct fw_interface_s fw_interface_t;

fw_interface_t *fw_interface_create_url(forwarder_type_t type, const char *url);
fw_interface_t *fw_interface_create(forwarder_type_t type);

void fw_interface_free(fw_interface_t *fi);

int fw_interface_get_fd(const fw_interface_t *fi);

/*
 * Enable the stack
 */
int fw_interface_enable(fw_interface_t *fi);

/*
 * Disable the stack
 */
int fw_interface_disable(fw_interface_t *fi);

/*
 * Request a permanent connection to the forwarder, starting it if needed.
 */
int fw_interface_connect(fw_interface_t *fi);

/*
 * Disconnect from the forwarder
 */
int fw_interface_disconnect(fw_interface_t *fi);

fw_state_t fw_interface_get_state(const fw_interface_t *fi);

int fw_interface_subscribe_all(fw_interface_t *fi);

int fw_interface_unsubscribe_all(fw_interface_t *fi);

int fw_interface_execute(fw_interface_t *fi, hc_action_t action,
                         hc_object_type_t object_type, hc_object_t *object,
                         hc_data_t **pdata);

int fw_interface_execute_async(fw_interface_t *fi, hc_action_t action,
                               hc_object_type_t object_type,
                               hc_object_t *object,
                               hc_result_callback_t callback,
                               void *callback_data);

int fw_interface_set_enable_callback(fw_interface_t *fi,
                                     hc_enable_callback_t callback);

int fw_interface_set_state_callback(fw_interface_t *fi,
                                    hc_state_callback_t callback,
                                    void *callback_data);

int fw_interface_set_result_callback(fw_interface_t *fi,
                                     hc_result_callback_t callback,
                                     void *callback_data);

int fw_interface_set_notification_callback(fw_interface_t *fi,
                                           hc_notification_callback_t callback,
                                           void *callback_data);

// manage stack [android]
//  - not needed for face mgr
// operations
//  - create face/route : facemgr, hproxy
//  - set fw strategy
//  - get listeners, hicn listener port
// subscribe all
// callbacks:
//   - forwarder available/unavailable
// timers & reattempts : clarify
// XXX remove_self on sock disconnect... should be in libhicnctrl

int fw_interface_on_receive(fw_interface_t *fi, size_t count);
int fw_interface_get_recv_buffer(fw_interface_t *fi, uint8_t **buffer,
                                 size_t *size);

#endif /* HICNCTRL_FW_INTERFACE_H */
