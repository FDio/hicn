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

#ifndef __IETF_HICN_H__
#define __IETF_HICN_H__

#include "../hicn_vpp_comm.h"


typedef struct _hicn_ctx
{
  u8 last_called;
  int num_ifs;
  int capacity;
} hicn_ctx;


//#include <vapi/interface.api.vapi.h>
//#include<vpp_plugins/hicn/hicn.api.vapi.h>


#endif /* __IETF_HICN_H__ */