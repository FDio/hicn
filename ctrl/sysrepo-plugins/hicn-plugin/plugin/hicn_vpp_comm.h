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
#include <sysrepo.h>
#include <sysrepo/values.h>
#include <vapi/vapi.h>

#ifndef HICN_THIS_FUNC
#ifdef __FUNCTION__
#define HICN_THIS_FUNC __FUNCTION__
#else
#define HICN_THIS_FUNC __func__
#endif
#endif

// ctx vpp connect
extern vapi_ctx_t g_vapi_ctx_instance;

//Here it is the definition

#define VPP_INTFC_NAME_LEN 64
#define VPP_MAC_ADDRESS_LEN 8
#define VPP_IP6_ADDRESS_LEN 16

#define ARG_CHECK(retval, arg)                        \
  do {                                                \
    if (NULL == (arg)) {                              \
      SRP_LOG_DBGMSG("NULL pointer passed.");         \
      return (retval);                                \
    }                                                 \
  } while (0)



#define ARG_CHECK2(retval, arg1, arg2) \
    ARG_CHECK(retval, arg1); \
    ARG_CHECK(retval, arg2)

#define ARG_CHECK7(retval, arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
    ARG_CHECK(retval, arg1); \
    ARG_CHECK(retval, arg2); \
    ARG_CHECK(retval, arg3); \
    ARG_CHECK(retval, arg4); \
    ARG_CHECK(retval, arg5); \
    ARG_CHECK(retval, arg6); \
    ARG_CHECK(retval, arg7)

int hicn_connect_vpp();
int hicn_disconnect_vpp();

#endif  //__HICN_VPP_COMMM_H__
