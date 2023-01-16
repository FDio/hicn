/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
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

#ifndef __HICN_DPO_LR_H__
#define __HICN_DPO_LR_H__

#include <vnet/dpo/dpo.h>
#include "../strategy_dpo_ctx.h"

/**
 * @file dpo_lr.h
 *
 * This file implements the strategy vtf (see strategy.h) and
 * the dpo vft (see strategy_dpo_manager.h) for the strategy
 * local-remote.
 */

typedef struct hicn_strategy_lr_ctx_s
{
} hicn_strategy_lr_ctx_t;

/**
 * @brief Format the dpo ctx for a human-readable string
 *
 * @param s String to which to append the formatted dpo ctx
 * @param dpo_ctx DPO context
 * @param indent Indentation
 *
 * @result The string with the formatted dpo ctx
 */
u8 *hicn_dpo_strategy_lr_format (u8 *s, hicn_dpo_ctx_t *dpo_ctx, u32 indent);

/**
 * @brief Retrieve an hicn_strategy_lr_ctx object
 *
 * @param indext Index of the hicn_dpo_ctx to retrieve
 * @return The hicn_dpo_ctx object or NULL
 */
hicn_dpo_ctx_t *hicn_strategy_lr_ctx_get (index_t index);

/**
 * @brief Create a new local-remote ctx
 *
 * @param proto The protocol to which the dpo is meant for (see vpp docs)
 * @param next_hop A list of next hops to be inserted in the dpo ctx
 * @param nh_len Size of the list
 * @param dpo_idx index_t that will hold the index of the created dpo ctx
 * @return HICN_ERROR_NONE if the creation was fine, otherwise EINVAL
 */
void hicn_strategy_lr_ctx_create (fib_protocol_t proto,
				  const hicn_face_id_t *next_hop, int nh_len,
				  index_t *dpo_idx);

/**
 * @brief Update existing ctx setting it to local-remote
 *
 * @param hicn_strategy_ctx pointer to the ctx to update
 */
void hicn_strategy_lr_update_ctx_type (hicn_dpo_ctx_t *hicn_strategy_ctx);

/**
 * @brief Add or update a next hop in the dpo ctx.
 *
 * This function is meant to be used in the control plane and not in the data
 * plane, as it is not optimized for the latter.
 *
 * @param nh Next hop to insert in the dpo ctx
 * @param dpo_idx Index of the dpo ctx to update with the new or updated next
 * hop
 * @return HICN_ERROR_NONE if the update or insert was fine,
 * otherwise HICN_ERROR_DPO_CTX_NOT_FOUND
 */
int hicn_strategy_lr_ctx_add_nh (hicn_face_id_t nh, index_t dpo_idx);

/**
 * @brief Delete a next hop in the dpo ctx.
 *
 * @param face_id Face identifier of the next hop
 * @param dpo_idx Index of the dpo ctx to update with the new or updated next
 * hop
 * @return HICN_ERROR_NONE if the update or insert was fine,
 * otherwise HICN_ERROR_DPO_CTS_NOT_FOUND
 */
int hicn_strategy_lr_ctx_del_nh (hicn_face_id_t face_id, index_t dpo_idx);

/**
 * @brief Prefetch a dpo
 *
 * @param dpo_idx Index of the dpo ctx to prefetch
 */
void hicn_strategy_lr_ctx_prefetch (index_t dpo_idx);

/**
 * @brief Return true if the dpo is of type strategy local-remote
 *
 * @param dpo Dpo to check the type
 */
int hicn_dpo_is_type_strategy_lr (const dpo_id_t *dpo);

/**
 * @brief Initialize the local-remote strategy
 */
void hicn_dpo_strategy_lr_module_init (void);

/**
 * @brief Return the dpo type for the local-remote strategy
 */
dpo_type_t hicn_dpo_strategy_lr_get_type (void);

#endif // __HICN_DPO_LR_H__
