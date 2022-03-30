/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef __VAPI_SAFE__
#define __VAPI_SAFE__

#include <vapi/vapi.h>
#include <pthread.h>

#include <vapi/hicn.api.vapi.h>
#include <vapi/interface.api.vapi.h>
#include <vapi/ip.api.vapi.h>
#include <vapi/memif.api.vapi.h>
#include <vapi/udp.api.vapi.h>

vapi_error_e vapi_connect_safe (vapi_ctx_t *vapi_ctx_ret, int async);
vapi_error_e vapi_disconnect_safe ();
void vapi_lock ();
void vapi_unlock ();

#endif
