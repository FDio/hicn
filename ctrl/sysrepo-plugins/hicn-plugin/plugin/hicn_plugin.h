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

/**
 * @file hicn_plugin.h
 * @brief This file contains init and cleanup for the sysrepo.
 */

#ifndef __HICN_PLUGIN_H__
#define __HICN_PLUGIN_H__

#include "hicn_vpp_comm.h"


/**
 * @brief initialize function for sysrepo plugin,
 *  In this function we connect to vpp from one side
 *  and subscribe for all hICN events as well as interface events (if any)
 * @param session  pointer to the sesssion context
 * @param private_ctx  pointer to the context
 * @return in success the function returns SR_ERR_OK otherwise it pass error
 */
int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx);

/**
 * @brief cleanup function for sysrepo,
 * In this function we connect to vpp from one side
 * and and unsubscribe for all hICN events as well as interface events (if any)
 * @param session pointer to the sesssion context
 * @param private_ctx pointer to the  context
 */
void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx);

#endif  //__HICN_PLUGIN_H__