/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

#ifndef __HICN_H__
#define __HICN_H__

#define ip_address_t hicn_ip_address_t
#define ip_address_cmp hicn_ip_address_cmp
#define ip_prefix_t hicn_ip_prefix_t
#define ip_prefix_cmp hicn_ip_prefix_cmp
#undef ip_prefix_len
#define ip_prefix_len hicn_ip_prefix_len
#include <hicn/hicn.h>
#undef ip_address_t
#undef ip_address_cmp
#undef ip_prefix_t
#undef ip_prefix_cmp
#undef ip_prefix_len
#define ip_prefix_len(_a) (_a)->len

#include "hicn_buffer.h"

#endif /* __HICN_H__ */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
