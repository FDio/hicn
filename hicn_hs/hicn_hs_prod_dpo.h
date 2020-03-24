/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 * @brief The hicn_hs dpo. It will store the 2 hicn_hs input nodes,
 * altogether with the index of the corresponding hicn socket, in order
 * to avoid a double lookup.
 */

#ifndef __HICN_HS_DPO_H__
#define  __HICN_HS_DPO_H__

#include <vnet/dpo/dpo.h>

int dpo_is_hicn_hs(const dpo_id_t *dpo);
u32 hicn_hs_dpo_create(u32 hicn_hs_ctx_idx, u8 is_ip4, dpo_id_t *dpo);
void hicn_hs_dpo_module_init(void);

#endif /* __HICN_HS_DPO_H__ */