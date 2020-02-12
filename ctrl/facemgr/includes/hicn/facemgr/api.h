/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
 * \file facemgr.h
 * \brief Face manager library interface
 */
#ifndef FACEMGR_H
#define FACEMGR_H

#include <hicn/facemgr/cfg.h>
#include <hicn/facemgr/facelet.h>
#include <hicn/util/ip_address.h>
#ifdef __ANDROID__
#include <jni.h>
#endif

/* facemgr callbacks */

typedef enum {
    FACEMGR_CB_TYPE_REGISTER_FD,
    FACEMGR_CB_TYPE_UNREGISTER_FD,
    FACEMGR_CB_TYPE_REGISTER_TIMER,
    FACEMGR_CB_TYPE_UNREGISTER_TIMER,
} facemgr_cb_type_t;

typedef int (*facemgr_cb_t)(void * loop, facemgr_cb_type_t type, void * data);


/*
 * \brief Manual overlay settings (alternative to service discovery)
 */

typedef struct {
    uint16_t local_port;
    ip_address_t remote_addr;
    uint16_t remote_port;
} facemgr_overlay_setting_t;

#define FACEMGR_OVERLAY_SETTING_EMPTY (facemgr_overlay_setting_t) {     \
    .local_port = 0,                                                    \
    .remote_addr = IP_ADDRESS_EMPTY,                                    \
    .remote_port = 0,                                                   \
}

typedef struct {
    facemgr_overlay_setting_t v4;
    facemgr_overlay_setting_t v6;
} facemgr_overlay_t;

#define FACEMGR_OVERLAY_EMPTY (facemgr_overlay_t) {     \
    .v4 = FACEMGR_OVERLAY_SETTING_EMPTY,                \
    .v6 = FACEMGR_OVERLAY_SETTING_EMPTY,                \
}

/*
 * \brief Face manager context
 */
typedef struct facemgr_s facemgr_t;

int facemgr_initialize(facemgr_t *);
int facemgr_finalize(facemgr_t *);
facemgr_t * facemgr_create();
facemgr_t * facemgr_create_with_config(facemgr_cfg_t * cfg);
void facemgr_stop(facemgr_t *);
void facemgr_free(facemgr_t *);


void facemgr_set_callback(facemgr_t * facemgr, void * callback_owner, facemgr_cb_t callback);

int facemgr_set_config(facemgr_t * facemgr, facemgr_cfg_t * cfg);
int facemgr_reset_config(facemgr_t * facemgr);
int facemgr_bootstrap(facemgr_t * facemgr);
#ifdef __ANDROID__
void facemgr_set_jvm(facemgr_t * facemgr, JavaVM *jvm);
#endif /* __ANDROID__ */

typedef int (*facemgr_list_facelets_cb_t)(const facemgr_t * facemgr, const facelet_t * facelet, void * user_data);

void facemgr_list_facelets(const facemgr_t * facemgr, facemgr_list_facelets_cb_t cb, void * user_data);
int facemgr_list_facelets_json(const facemgr_t * facemgr, char ** buffer);

#endif /* FACEMGR_H */
