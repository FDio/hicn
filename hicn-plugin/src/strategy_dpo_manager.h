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

#ifndef __HICN_STRATEGY_DPO_MANAGER_H__
#define __HICN_STRATEGY_DPO_MANAGER_H__

#include "strategy_dpo_ctx.h"
#include "strategy.h"

/**
 * @brief Definition of the virtual function table for a hICN DPO.
 *
 * An hICN dpo is a combination of a dpo context (hicn_dpo_ctx or struct that
 * extends a hicn_dpo_ctx) and a strategy node. The following virtual function table
 * template that glues together the fuction to interact with the context and the
 * creating the dpo
 */
typedef struct hicn_dpo_vft_s
{
  int (*hicn_dpo_is_type) (const dpo_id_t * dpo);
	/**< Check if the type of the
           hICN DPO is the expected */
    dpo_type_t (*hicn_dpo_get_type) (void);
	/**< Return the type of the hICN dpo */
  void (*hicn_dpo_module_init) (void);			/**< Initialize the hICN dpo */
  void (*hicn_dpo_create) (dpo_proto_t proto, const dpo_id_t * nh, int nh_len, index_t * dpo_idx);			/**< Create the context of the hICN dpo */
  int (*hicn_dpo_add_update_nh) (const dpo_id_t * nh, index_t dpo_idx);				/**< Add a next hop to the hICN dpo context */
  int (*hicn_dpo_del_nh) (hicn_face_id_t face_id, index_t dpo_idx);
u8 *(*hicn_dpo_format) (u8 * s, int, ...);
	/**< Format an hICN dpo*/
} hicn_dpo_vft_t;

/*
 * Default dpo to be used to create fib entry when a strategy is not
 * specified
 */
extern hicn_dpo_vft_t default_dpo;

const static char *const hicn_ip6_nodes[] =
{
 "hicn-iface-ip6-input",		// this is the name you give your node in VLIB_REGISTER_NODE
 NULL,
};

const static char *const hicn_ip4_nodes[] =
{
 "hicn-iface-ip4-input",		// this is the name you give your node in VLIB_REGISTER_NODE
 NULL,
};

const static char *const *const hicn_nodes_strategy[DPO_PROTO_NUM] =
{
 [DPO_PROTO_IP6] = hicn_ip6_nodes,
 [DPO_PROTO_IP4] = hicn_ip4_nodes,
};

/**
 *  @brief Register a new hICN dpo to the manager.
 *
 *  An hICN DPO is a combination of:
 *   - a hICN DPO ctx (context) that holds the structure containing the
 *     information to choose the next hop,
 *   - a strategy containing: (i) the vpp node that processes Interest packets
 *     subjected to such strategy, (ii) the definition of the vft that defines
 *     the hICN strategy functions
 *  Registering a hICN DPO allows the plugin to be aware of the new dpo an be
 *  able to apply it to the FIB entries.
 *
 * @param hicn_nodes A list of vpp to which pass an interest that matches with
 * the FIB entry to which the hICN DPO is applied. This list must contain the
 * name of the strategy node (or nodes in case of differentiation between IPv4
 * and IPv6).
 * @param hicn_dpo_vft The structure holding the virtual function table to
 * interact with the hICN dpo and its context.
 * @param hicn_strategy_vft The structure holding the virtual function table
 * containing the hICN strategy functions.
 * @return the dpo type registered in the VPP Data plane graph.
 */
dpo_type_t
hicn_dpo_register_new_type (const char *const *const *hicn_nodes,
			    const hicn_dpo_vft_t * hicn_dpo_vft,
			    const hicn_strategy_vft_t *
			    hicn_strategy_vft, const dpo_vft_t * dpo_ctx_vft);

/**
 * @brief Check if the type of the dpo is among the list of hicn dpo types
 *
 * Iterate through the list of dpo types registered in the hicn dpo manager.
 *
 * @param dpo The id of the dpo to which check the type
 * @return 1 if there is a match, 0 otherwise.
 */
u32 dpo_is_hicn (const dpo_id_t * dpo);

/**
 * @brief Return the dpo_vtf and strategy_vtf identifier
 *
 * Iterate through the list of dpo types registered in the hicn dpo manager and
 * retrieve the corresponding dpo_vtf/strategy_vtf identifier.
 *
 * @param dpo The id of the dpo to which check the type
 * @return the dpo_vft/strategy_vft id or HICN_ERROR_DPO_NOT_FOUND in case the dpo is not an hICN dpo.
 */
u8 hicn_dpo_get_vft_id (const dpo_id_t * dpo);

/**
 * @brief Get the vft to manage the dpo context.
 *
 * @param The id of the hicn_dpo_vft to retrieve.
 * @return The vft struct that contains the list of callbacks that allows to
 * manage the dpo context.
 */
const hicn_dpo_vft_t *hicn_dpo_get_vft (dpo_type_t vfts_id);

/**
 * @brief Get the vft to manage the dpo context from the strategy id.
 *
 * @param The strategy id of the hicn_dpo_vft to retrieve.
 * @return The vft struct that contains the list of callbacks that allows to
 * manage the dpo context.
 */
const hicn_dpo_vft_t *hicn_dpo_get_vft_from_id (u8 strategy_id);

/**
 * @brief Get the vft with the hICN strategy functions.
 *
 * @param The id of the hicn_strategy_vft to retrieve.
 * @return The vft struct that contains the list hICN strategy functions.
 */
const hicn_strategy_vft_t *hicn_dpo_get_strategy_vft (dpo_type_t vfts_id);

/**
 * @brief Get the vft with the hICN strategy functions from the strategy id.
 *
 * @param The id of the hicn_strategy_vft to retrieve.
 * @return The vft struct that contains the list hICN strategy functions.
 */
const hicn_strategy_vft_t *hicn_dpo_get_strategy_vft_from_id (u8 vfts_id);

/**
 * @brief Initialize all the types hicn dpo registered
 *
 * Call the init functions of all the hicn dpo implemented.
 * This init is called when the plugin bootstrap.
 */
void hicn_dpos_init (void);

/**
 * @brief Print the list of the registered hICN DPO
 *
 * @param s String to which to append the list of hICN DPO (strategies)
 * @param n number of parameters to pass
 *
 * @result The string with the list of hICN DPO (strategies)
 */
u8 *format_hicn_strategy_list (u8 * s, int n, ...);

/**
 * @brief Check if a given id points to a strategy and the corresponding dpo ctx
 *
 * @param The id of the strategy to check.
 *
 * @result HICN_ERROR_NONE is the id is valid, otherwise EINVAL
 */
u8 hicn_dpo_strategy_id_is_valid (int strategy_id);

/**
 * @brief Return the number of available strategies. This number can be used to
 * as an upperbond for valid vfts_id.
 *
 * @result Return the number of available strategies.
 */
int hicn_strategy_get_all_available (void);

/**
 * @brief Registers a module at compilation time to be initialized as part of
 * the ctor.
 */
void hicn_dpo_register (const hicn_dpo_vft_t * hicn_dpo);

#endif /* // __HICN_STRATEGY_DPO_MANAGER_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
