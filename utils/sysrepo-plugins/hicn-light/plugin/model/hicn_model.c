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
#include <stdio.h>
#include <malloc.h>
#include <sysrepo/xpath.h>

/* Hicn headers */

#include "hicn_model.h"
#include "tlock.h"
#include "../hicn_light.h"




// Shared local variables between state and RPCs

volatile hicn_state_t  * hicn_state = NULL;
volatile hicn_strategy_t * hicn_strategy = NULL;
volatile hicn_strategies_t * hicn_strategies =NULL;
volatile hicn_route_t * hicn_route = NULL;
volatile hicn_face_ip_params_t *  hicn_face_ip_params = NULL;

static int init_buffer(void){

  hicn_state = memalign(MEM_ALIGN, sizeof(hicn_state_t) );
  memset((hicn_state_t *)hicn_state, 0 , sizeof(hicn_state_t) );
  hicn_strategy = memalign(MEM_ALIGN, sizeof(hicn_strategy_t) );
  memset((hicn_strategy_t *) hicn_strategy, 0 , sizeof(hicn_strategy_t) );
  hicn_strategies = memalign(MEM_ALIGN, sizeof(hicn_strategies_t) );
  memset((hicn_strategies_t *) hicn_strategies, 0 , sizeof(hicn_strategies_t) );
  hicn_route = memalign(MEM_ALIGN, sizeof(hicn_route_t) );
  memset((hicn_route_t *) hicn_route, 0 , sizeof(hicn_route_t) );
  hicn_face_ip_params = memalign(MEM_ALIGN, sizeof(hicn_face_ip_params_t) );
  memset((hicn_face_ip_params_t *) hicn_face_ip_params, 0 , sizeof(hicn_face_ip_params_t) );
  int retval=-1;
  ARG_CHECK5(retval, hicn_state, hicn_strategy, hicn_strategies, hicn_route, hicn_face_ip_params);
  retval=0;
  return retval;
}

  static inline void  state_update(sr_val_t * vals ){
  sr_val_set_xpath(&vals[0], "/hicn:hicn-state/states/pkts_processed");
  vals[0].type = SR_UINT64_T;
  vals[0].data.uint64_val = hicn_state->pkts_processed;

  sr_val_set_xpath(&vals[1], "/hicn:hicn-state/states/pkts_interest_count");
  vals[1].type = SR_UINT64_T;
  vals[1].data.uint64_val = hicn_state->pkts_interest_count;

  sr_val_set_xpath(&vals[2], "/hicn:hicn-state/states/pkts_data_count");
  vals[2].type = SR_UINT64_T;
  vals[2].data.uint64_val = hicn_state->pkts_data_count;

  sr_val_set_xpath(&vals[3], "/hicn:hicn-state/states/pkts_from_cache_count");
  vals[3].type = SR_UINT64_T;
  vals[3].data.uint64_val = hicn_state->pkts_from_cache_count;

  sr_val_set_xpath(&vals[4], "/hicn:hicn-state/states/pkts_no_pit_count");
  vals[4].type = SR_UINT64_T;
  vals[4].data.uint64_val = hicn_state->pkts_no_pit_count;

  sr_val_set_xpath(&vals[5], "/hicn:hicn-state/states/pit_expired_count");
  vals[5].type = SR_UINT64_T;
  vals[5].data.uint64_val = hicn_state->pit_expired_count;

  sr_val_set_xpath(&vals[6], "/hicn:hicn-state/states/cs_expired_count");
  vals[6].type = SR_UINT64_T;
  vals[6].data.uint64_val = hicn_state->cs_expired_count;

  sr_val_set_xpath(&vals[7], "/hicn:hicn-state/states/cs_lru_count");
  vals[7].type = SR_UINT64_T;
  vals[7].data.uint64_val = hicn_state->cs_lru_count;

  sr_val_set_xpath(&vals[8], "/hicn:hicn-state/states/pkts_drop_no_buf");
  vals[8].type = SR_UINT64_T;
  vals[8].data.uint64_val = hicn_state->pkts_drop_no_buf;

  sr_val_set_xpath(&vals[9], "/hicn:hicn-state/states/interests_aggregated");
  vals[9].type = SR_UINT64_T;
  vals[9].data.uint64_val = hicn_state->interests_aggregated;

  sr_val_set_xpath(&vals[10], "/hicn:hicn-state/states/interests_retx");
  vals[10].type = SR_UINT64_T;
  vals[10].data.uint64_val = hicn_state->interests_retx;

  sr_val_set_xpath(&vals[11],
                   "/hicn:hicn-state/states/interests_hash_collision");
  vals[11].type = SR_UINT64_T;
  vals[11].data.uint64_val = hicn_state->interests_hash_collision;

  sr_val_set_xpath(&vals[12], "/hicn:hicn-state/states/pit_entries_count");
  vals[12].type = SR_UINT64_T;
  vals[12].data.uint64_val = hicn_state->pit_entries_count;

  sr_val_set_xpath(&vals[13], "/hicn:hicn-state/states/cs_entries_count");
  vals[13].type = SR_UINT64_T;
  vals[13].data.uint64_val = hicn_state->cs_entries_count;

  sr_val_set_xpath(&vals[14], "/hicn:hicn-state/states/cs_entries_ntw_count");
  vals[14].type = SR_UINT64_T;
  vals[14].data.uint64_val = hicn_state->cs_entries_ntw_count;
}


static inline void  strategy_update(sr_val_t * vals ){
  sr_val_set_xpath(&vals[0], "/hicn:hicn-state/strategy/description");
  vals[0].type = SR_UINT8_T;
  vals[0].data.uint8_val = hicn_strategy->description[0];
}

static inline void  strategies_update(sr_val_t * vals ){
  sr_val_set_xpath(&vals[0], "/hicn:hicn-state/strategies/n_strategies");
  vals[0].type = SR_UINT8_T;
  vals[0].data.uint8_val = hicn_strategies->n_strategies;

  sr_val_set_xpath(&vals[1], "/hicn:hicn-state/strategies/strategy_id");
  vals[1].type = SR_UINT32_T;
  vals[1].data.uint32_val = hicn_strategies->strategy_id[0];

}

static inline void  route_update(sr_val_t * vals ){
  sr_val_set_xpath(&vals[0], "/hicn:hicn-state/route/faceids");
  vals[0].type = SR_UINT16_T;
  vals[0].data.uint16_val = hicn_route->faceids[0];

  sr_val_set_xpath(&vals[1], "/hicn:hicn-state/route/strategy_id");
  vals[1].type = SR_UINT32_T;
  vals[1].data.uint32_val = hicn_route->strategy_id;
}

static inline void  face_ip_params_update(sr_val_t * vals ){
  sr_val_set_xpath(&vals[0], "/hicn:hicn-state/face-ip-params/nh_addr");
  vals[0].type = SR_UINT64_T;
  vals[0].data.uint64_val = hicn_face_ip_params->nh_addr[0];

  sr_val_set_xpath(&vals[1], "/hicn:hicn-state/face-ip-params/swif");
  vals[1].type = SR_UINT32_T;
  vals[1].data.uint32_val = hicn_face_ip_params->swif;

  sr_val_set_xpath(&vals[2], "/hicn:hicn-state/face-ip-params/flags");
  vals[2].type = SR_UINT32_T;
  vals[2].data.uint32_val = hicn_face_ip_params->flags;
}


static int hicn_state_states_cb(const char *xpath, sr_val_t **values,
                         size_t *values_cnt, uint64_t request_id,
                         const char *original_xpath, void *private_ctx) {
  sr_val_t *vals;
  int rc;
 enum locks_name state;
 state=lstate;
  SRP_LOG_DBG("Requesting state data for '%s'", xpath);

  if (!sr_xpath_node_name_eq(xpath, "states")) {
    *values = NULL;
    *values_cnt = 0;
    return SR_ERR_OK;
  }

  rc = sr_new_values(NSTATE_LEAVES, &vals);
  if (SR_ERR_OK != rc) {
    return rc;
  }

  SRP_LOG_DBG("Requesting state data for '%s'", xpath);
  Ticket_Lock(state);
  state_update(vals);
  Ticket_Unlock(state);

  *values = vals;
  *values_cnt = NSTATE_LEAVES;

  return SR_ERR_OK;
}

static int hicn_state_strategy_cb(const char *xpath, sr_val_t **values,
                         size_t *values_cnt, uint64_t request_id,
                         const char *original_xpath, void *private_ctx) {
  sr_val_t *vals;
  int rc;
  enum locks_name strategy;
  strategy=lstrategy;

  if (!sr_xpath_node_name_eq(xpath, "strategy")) {
    *values = NULL;
    *values_cnt = 0;
    return SR_ERR_OK;
  }


  rc = sr_new_values(NSTRATEGY_LEAVES, &vals);
  if (SR_ERR_OK != rc) {
    return rc;
  }

  SRP_LOG_DBG("Requesting state data for '%s'", xpath);
  Ticket_Lock(strategy);
  strategy_update(vals);
  Ticket_Unlock(strategy);

  *values = vals;
  *values_cnt = NSTRATEGY_LEAVES;
  return SR_ERR_OK;

  }

static int hicn_state_strategies_cb(const char *xpath, sr_val_t **values,
                         size_t *values_cnt, uint64_t request_id,
                         const char *original_xpath, void *private_ctx) {
  sr_val_t *vals;
  int rc;
  enum locks_name strategies;
  strategies=lstrategies;



  if (! sr_xpath_node_name_eq(xpath, "strategies")) {
    SRP_LOG_DBG_MSG("Requesting state is not for strategies");
    *values = NULL;
    *values_cnt = 0;
    return SR_ERR_OK;
  }


  rc = sr_new_values(NSTRATEGIES_LEAVES, &vals);
  if (SR_ERR_OK != rc) {
    return rc;
  }

  SRP_LOG_DBG("Requesting state data for '%s'", xpath);
  Ticket_Lock(strategies);
  strategies_update(vals);
  Ticket_Unlock(strategies);

  *values = vals;
  *values_cnt = NSTRATEGIES_LEAVES;
  return SR_ERR_OK;

  }


static int hicn_state_route_cb(const char *xpath, sr_val_t **values,
                         size_t *values_cnt, uint64_t request_id,
                         const char *original_xpath, void *private_ctx) {

  return SR_ERR_OK;

  }


  static int hicn_state_face_ip_params_cb(const char *xpath, sr_val_t **values,
                         size_t *values_cnt, uint64_t request_id,
                         const char *original_xpath, void *private_ctx) {

  return SR_ERR_OK;

  }

/**
 * @brief Callback to be called by any config change of "/hicn:/" leaf.
 */
static int hicn_node_params_set_cb(sr_session_ctx_t *session, const char *xpath,
                                   sr_notif_event_t event, void *private_ctx) {

  return SR_ERR_OK;
}

/**
 * @brief API to get hicn param in forwarder.
 */
static int hicn_node_params_get_cb(const char *xpath, const sr_val_t *input,
                                   const size_t input_cnt, sr_val_t **output,
                                   size_t *output_cnt, void *private_ctx) {

  return SR_ERR_OK;
}

/**
 * @brief API to get hicn stat in forwarder.
 */
static int hicn_node_stat_get_cb(const char *xpath, const sr_val_t *input,
                                 const size_t input_cnt, sr_val_t **output,
                                 size_t *output_cnt, void *private_ctx) {
  return SR_ERR_OK;
}

/**
 * @brief API to get hicn strategy in forwarder.
 */
static int hicn_strategy_get_cb(const char *xpath, const sr_val_t *input,
                                const size_t input_cnt, sr_val_t **output,
                                size_t *output_cnt, void *private_ctx) {
  return SR_ERR_OK;
}

/**
 * @brief API to get hicn strategies in forwarder.
 */
static int hicn_strategies_get_cb(const char *xpath, const sr_val_t *input,
                                  const size_t input_cnt, sr_val_t **output,
                                  size_t *output_cnt, void *private_ctx) {
  return SR_ERR_OK;
}

/**
 * @brief API to get hicn route in forwarder.
 */
static int hicn_route_get_cb(const char *xpath, const sr_val_t *input,
                             const size_t input_cnt, sr_val_t **output,
                             size_t *output_cnt, void *private_ctx) {

  return SR_ERR_OK;
}

/**
 * @brief API to add hicn route nhops in forwarder.
 */
static int hicn_route_nhops_add_cb(const char *xpath, const sr_val_t *input,
                                   const size_t input_cnt, sr_val_t **output,
                                   size_t *output_cnt, void *private_ctx) {

  return SR_ERR_OK;
}

/**
 * @brief API to del hicn route in forwarder.
 */
static int hicn_route_del_cb(const char *xpath, const sr_val_t *input,
                             const size_t input_cnt, sr_val_t **output,
                             size_t *output_cnt, void *private_ctx) {
  return SR_ERR_OK;
}

/**
 * @brief API to get face ip params in hicn in forwarder.
 */
static int hicn_face_ip_params_get_cb(const char *xpath, const sr_val_t *input,
                                      const size_t input_cnt, sr_val_t **output,
                                      size_t *output_cnt, void *private_ctx) {
  return SR_ERR_OK;
}

/**
 * @brief API to get face ip params in hicn in forwarder.
 */
static int hicn_punting_add_cb(const char *xpath, const sr_val_t *input,
                               const size_t input_cnt, sr_val_t **output,
                               size_t *output_cnt, void *private_ctx) {
  return SR_ERR_OK;
}

/**
 * @brief API to del hicn route nhops in forwarder.
 */
static int hicn_route_nhops_del_cb(const char *xpath, const sr_val_t *input,
                                   const size_t input_cnt, sr_val_t **output,
                                   size_t *output_cnt, void *private_ctx) {
  return SR_ERR_OK;
}

/**
 * @brief API to del hicn punting in forwarder.
 */
static int hicn_punting_del_cb(const char *xpath, const sr_val_t *input,
                               const size_t input_cnt, sr_val_t **output,
                               size_t *output_cnt, void *private_ctx) {
  return SR_ERR_OK;
}

/**
 * @brief API to del hicn face ip in forwarder.
 */
static int hicn_face_ip_del_cb(const char *xpath, const sr_val_t *input,
                               const size_t input_cnt, sr_val_t **output,
                               size_t *output_cnt, void *private_ctx) {
  return SR_ERR_OK;
}

/**
 * @brief API to del hicn face ip in forwarder.
 */
static int hicn_face_ip_add_cb(const char *xpath, const sr_val_t *input,
                               const size_t input_cnt, sr_val_t **output,
                               size_t *output_cnt, void *private_ctx) {
  return SR_ERR_OK;
}

/**
 * @brief Helper function for subscribing all hicn APIs.
 */
int hicn_subscribe_events(sr_session_ctx_t *session,
                          sr_subscription_ctx_t **subscription) {

/*
    int rc = SR_ERR_OK;
    SRP_LOG_DBG_MSG("Subscriging hicn.");


    // node state subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:node-params-get", hicn_node_params_get_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      SRP_LOG_DBG_MSG("Problem in subscription stat-get\n");
      goto error;
    }


    // node state subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:node-stat-get", hicn_node_stat_get_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      SRP_LOG_DBG_MSG("Problem in subscription stat-get\n");
      goto error;
    }

    // strategies subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:strategy-get", hicn_strategy_get_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      SRP_LOG_DBG_MSG("Problem in subscription strategy-get\n");
      goto error;
    }

    rc = sr_rpc_subscribe(session, "/hicn:strategies-get",
    hicn_strategies_get_cb, session, SR_SUBSCR_CTX_REUSE, subscription); if (rc
    != SR_ERR_OK) { SRP_LOG_DBG_MSG("Problem in subscription punting-del\n"); goto error;
    }

    // route subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:route-get", hicn_route_get_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      SRP_LOG_DBG_MSG("Problem in subscription route-get\n");
      goto error;
    }

    rc = sr_rpc_subscribe(session, "/hicn:route-del", hicn_route_del_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      SRP_LOG_DBG_MSG("Problem in subscription route-del\n");
      goto error;
    }


    // route nhops subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:route-nhops-add",
    hicn_route_nhops_add_cb, session, SR_SUBSCR_CTX_REUSE, subscription); if (rc
    != SR_ERR_OK) { SRP_LOG_DBG_MSG("Problem in subscription route-get\n"); goto error;
    }

    rc = sr_rpc_subscribe(session, "/hicn:route-nhops-del",
    hicn_route_nhops_del_cb, session, SR_SUBSCR_CTX_REUSE, subscription); if (rc
    != SR_ERR_OK) { SRP_LOG_DBG_MSG("Problem in subscription route-nhops-del\n"); goto
    error;
    }


    // face ip subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:face-ip-params-get",
    hicn_face_ip_params_get_cb, session, SR_SUBSCR_CTX_REUSE, subscription); if
    (rc != SR_ERR_OK) { SRP_LOG_DBG_MSG("Problem in subscription face-ip-params-get\n");
      goto error;
    }


    rc = sr_rpc_subscribe(session, "/hicn:face-ip-add", hicn_face_ip_add_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      SRP_LOG_DBG_MSG("Problem in subscription punting-del\n");
      goto error;
    }

    rc = sr_rpc_subscribe(session, "/hicn:face-ip-del", hicn_face_ip_del_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      SRP_LOG_DBG_MSG("Problem in subscription punting-del\n");
      goto error;
    }

    // punting subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:punting-add", hicn_punting_add_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      SRP_LOG_DBG_MSG("Problem in subscription punting-add\n");
      goto error;
    }

  rc = sr_rpc_subscribe(session, "/hicn:punting-del", hicn_punting_del_cb,
                        session, SR_SUBSCR_CTX_REUSE, subscription);
  if (rc != SR_ERR_OK) {
    SRP_LOG_DBG_MSG("Problem in subscription punting-del\n");
    goto error;
  }

  rc = sr_subtree_change_subscribe(
      session, "/hicn:hicn-conf", hicn_node_params_set_cb, g_vapi_ctx_instance,
      100, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_EV_ENABLED, subscription);
  if (SR_ERR_OK != rc) {
    SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-conf\n");
    goto error;
  }

  // subscribe as hicn state data provider
  rc = sr_dp_get_items_subscribe(session, "/hicn:hicn-state/states",
                                 hicn_state_states_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                 subscription);
  if (rc != SR_ERR_OK) {
    SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-state/states\n");
    goto error;
  }



  rc = sr_dp_get_items_subscribe(session, "/hicn:hicn-state/strategy",
                                 hicn_state_strategy_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                 subscription);
  if (rc != SR_ERR_OK) {
    SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-state/strategy\n");
    goto error;
  }



  rc = sr_dp_get_items_subscribe(session, "/hicn:hicn-state/strategies",
                                 hicn_state_strategies_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                 subscription);
  if (rc != SR_ERR_OK) {
    SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-state/strategies\n");
    goto error;
  }


  rc = sr_dp_get_items_subscribe(session, "/hicn:hicn-state/route",
                                 hicn_state_route_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                 subscription);
  if (rc != SR_ERR_OK) {
    SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-state/route\n");
    goto error;
  }


  rc = sr_dp_get_items_subscribe(session, "/hicn:hicn-state/face-ip-params",
                                 hicn_state_face_ip_params_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                 subscription);
  if (rc != SR_ERR_OK) {
    SRP_LOG_DBG_MSG("Problem in subscription /hicn:hicn-state/face-ip-params\n");
    goto error;
  }
*/

  SRP_LOG_INF_MSG("hicn light plugin initialized successfully.");
  return SR_ERR_OK;
/*
error:
  SRP_LOG_ERR_MSG("Error by initialization of the hicn plugin.");
  sr_plugin_cleanup_cb(session, *subscription);
  return rc;
*/
}