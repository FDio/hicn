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

#ifndef __HICN_LIGHT_COMMM_H__
#define __HICN_LIGHT_COMMM_H__
#include <sysrepo.h>
#include <sysrepo/plugins.h>
#include <sysrepo/values.h>

#include <hicnctrl.h>

#include <hicnctrl/util/ip_address.h>
#include <hicnctrl/util/token.h>


#ifndef HICN_THIS_FUNC
#ifdef __FUNCTION__
#define HICN_THIS_FUNC __FUNCTION__
#else
#define HICN_THIS_FUNC __func__
#endif
#endif

#ifndef _NOLOG
#define HICN_LOG_DBG SRP_LOG_DBG
#define HICN_LOG_ERR SRP_LOG_ERR
#define HICN_LOG_DBG_MSG SRP_LOG_DBG_MSG
#define HICN_LOG_ERR_MSG SRP_LOG_ERR_MSG
#else
#define HICN_LOG_DBG      // printf
#define HICN_LOG_DBG      // SRP_LOG_DBG
#define HICN_LOG_ERR      // SRP_LOG_ERR
#define HICN_LOG_DBG_MSG  // SRP_LOG_DBG_MSG
#define HICN_LOG_ERR_MSG  // SRP_LOG_ERR_MSG
#endif

//Here it is the definition

#define HICN_INVOKE_BEGIN HICN_LOG_DBG("inovke %s bein.", HICN_THIS_FUNC);
#define HICN_INVOKE_END \
  HICN_LOG_DBG("inovke %s end,with return OK.", HICN_THIS_FUNC);
#define HICN_INVOKE_ENDX(...) \
  HICN_LOG_DBG("inovke %s end,with %s.", HICN_THIS_FUNC, ##__VA_ARGS__)

#define ARG_CHECK(retval, arg)                        \
  do {                                                \
    if (NULL == (arg)) {                              \
      HICN_LOG_ERR_MSG(#arg ":NULL pointer passed."); \
      return (retval);                                \
    }                                                 \
  } while (0)



#define ARG_CHECK2(retval, arg1, arg2) \
    ARG_CHECK(retval, arg1); \
    ARG_CHECK(retval, arg2)

#define ARG_CHECK5(retval, arg1, arg2, arg3, arg4, arg5) \
    ARG_CHECK(retval, arg1); \
    ARG_CHECK(retval, arg2); \
    ARG_CHECK(retval, arg3); \
    ARG_CHECK(retval, arg4); \
    ARG_CHECK(retval, arg5)

int hicn_connect_light();
int hicn_disconnect_light();
extern hc_sock_t * hsocket;
#endif  //__HICN_LIGHT_COMMM_H__