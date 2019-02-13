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
#include <sysrepo/xpath.h>

/* Hicn headers */

#include <vapi/hicn.api.vapi.h>
#include "../hicn_plugin.h"
#include "../hicn_vpp_comm.h"
#include "ietf_hicn.h"
#include "state.h"

vapi_ctx_t g_vapi_ctx_instance;

DEFINE_VAPI_MSG_IDS_HICN_API_JSON;

volatile uint64_t test_state = 15;

/* hicn state value determining whether the hicn is enabled inside the vpp or
 * not */
volatile int enabled = 0;

// Shared local variables between state and operational data

static int hicn_state_cb(const char *xpath, sr_val_t **values,
                         size_t *values_cnt, uint64_t request_id,
                         const char *original_xpath, void *private_ctx) {
  sr_val_t *vals;
  int rc;

  SRP_LOG_DBG("Requesting state data for '%s'", xpath);
  /*
      if (! sr_xpath_node_name_eq(xpath, "states")) {
        SRP_LOG_DBG_MSG("Requesting state is not for pkts_processed");
        *values = NULL;
        *values_cnt = 0;
        return SR_ERR_OK;
      }

  */
  rc = sr_new_values(17, &vals);
  if (SR_ERR_OK != rc) {
    return rc;
  }

  /*
      sr_val_build_xpath(&vals[0], "/hicn:hicn-state/states/pkts_processed");
      sr_val_set_str_data(&vals[0], SR_UINT64_T, "10");
  */

  sr_val_set_xpath(&vals[0], "/hicn:hicn-state/states/pkts_processed");
  vals[0].type = SR_UINT64_T;
  vals[0].data.uint64_val = 12;

  sr_val_set_xpath(&vals[1], "/hicn:hicn-state/states/pkts_interest_count");
  vals[1].type = SR_UINT64_T;
  vals[1].data.uint64_val = test_state;

  sr_val_set_xpath(&vals[2], "/hicn:hicn-state/states/pkts_data_count");
  vals[2].type = SR_UINT64_T;
  vals[2].data.uint64_val = test_state;

  sr_val_set_xpath(&vals[3], "/hicn:hicn-state/states/pkts_from_cache_count");
  vals[3].type = SR_UINT64_T;
  vals[3].data.uint64_val = test_state;

  sr_val_set_xpath(&vals[4], "/hicn:hicn-state/states/pkts_no_pit_count");
  vals[4].type = SR_UINT64_T;
  vals[4].data.uint64_val = test_state;

  sr_val_set_xpath(&vals[5], "/hicn:hicn-state/states/pit_expired_count");
  vals[5].type = SR_UINT64_T;
  vals[5].data.uint64_val = 10;

  sr_val_set_xpath(&vals[6], "/hicn:hicn-state/states/pkts_processed");
  vals[6].type = SR_UINT64_T;
  vals[6].data.uint64_val = 10;

  sr_val_set_xpath(&vals[7], "/hicn:hicn-state/states/cs_expired_count");
  vals[7].type = SR_UINT64_T;
  vals[7].data.uint64_val = 10;

  sr_val_set_xpath(&vals[8], "/hicn:hicn-state/states/cs_lru_count");
  vals[8].type = SR_UINT64_T;
  vals[8].data.uint64_val = 10;

  sr_val_set_xpath(&vals[9], "/hicn:hicn-state/states/pkts_drop_no_buf");
  vals[9].type = SR_UINT64_T;
  vals[9].data.uint64_val = 10;

  sr_val_set_xpath(&vals[10], "/hicn:hicn-state/states/interests_aggregated");
  vals[10].type = SR_UINT64_T;
  vals[10].data.uint64_val = 10;

  sr_val_set_xpath(&vals[11], "/hicn:hicn-state/states/interests_retx");
  vals[11].type = SR_UINT64_T;
  vals[11].data.uint64_val = 10;

  sr_val_set_xpath(&vals[12],
                   "/hicn:hicn-state/states/interests_hash_collision");
  vals[12].type = SR_UINT64_T;
  vals[12].data.uint64_val = 10;

  sr_val_set_xpath(&vals[13], "/hicn:hicn-state/states/pit_entries_count");
  vals[13].type = SR_UINT64_T;
  vals[13].data.uint64_val = 10;

  sr_val_set_xpath(&vals[14], "/hicn:hicn-state/states/cs_entries_count");
  vals[14].type = SR_UINT64_T;
  vals[14].data.uint64_val = 10;

  sr_val_set_xpath(&vals[15], "/hicn:hicn-state/states/cs_entries_count");
  vals[15].type = SR_UINT64_T;
  vals[15].data.uint64_val = 10;

  sr_val_set_xpath(&vals[16], "/hicn:hicn-state/states/cs_entries_ntw_count");
  vals[16].type = SR_UINT64_T;
  vals[16].data.uint64_val = 10;

  *values = vals;
  *values_cnt = 17;
  //  sr_free_val(vals);

  /*
       pthread_t state_tid;
       rc = pthread_create((pthread_t *)&state_tid, NULL, state_thread, NULL);
       if (rc != 0) {
              SRP_LOG_DBG_MSG("Error making hicn state thread");
              return SR_ERR_OPERATION_FAILED;
       }
  */

  return SR_ERR_OK;
}

static int params_send(vapi_msg_hicn_api_node_params_set *msg,
                       vapi_msg_hicn_api_node_params_set_reply *resp) {
  vapi_msg_hicn_api_node_params_set_hton(msg);
  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }
  HICN_VPP_VAPI_RECV;
  SRP_LOG_DBG_MSG("state data are updated successfully");
  return SR_ERR_OK;
}

/**
 * @brief Callback to be called by any config change of "/hicn:/" leaf.
 */
static int hicn_node_params_set_cb(sr_session_ctx_t *session, const char *xpath,
                                   sr_notif_event_t event, void *private_ctx) {
  sr_change_iter_t *iter = NULL;
  sr_change_oper_t op = SR_OP_CREATED;
  sr_val_t *old_val = NULL;
  sr_val_t *new_val = NULL;
  sr_xpath_ctx_t xpath_ctx = {
      0,
  };
  int rc = SR_ERR_OK, op_rc = SR_ERR_OK;
  // no-op for apply, we only care about SR_EV_ENABLED, SR_EV_VERIFY,
  // SR_EV_ABORT
  if (SR_EV_APPLY == event) {
    return SR_ERR_OK;
  }

  // get changes iterator
  rc = sr_get_changes_iter(session, xpath, &iter);
  if (SR_ERR_OK != rc) {
    SRP_LOG_ERR("Unable to retrieve change iterator: %s", sr_strerror(rc));
    return rc;
  }

  vapi_msg_hicn_api_node_params_set *msg;
  vapi_msg_hicn_api_node_params_set_reply *resp = NULL;
  msg = vapi_alloc_hicn_api_node_params_set(g_vapi_ctx_instance);
  // iterate over all changes
  while ((SR_ERR_OK == op_rc || event == SR_EV_ABORT) &&
         (SR_ERR_OK ==
          (rc = sr_get_change_next(session, iter, &op, &old_val, &new_val)))) {
    if (!strcmp(new_val->xpath, "/hicn:hicn-conf/params/enable_disable")) {
      SRP_LOG_DBG("A change detected in '%s', op=%d",
                  new_val ? new_val->xpath : old_val->xpath,
                  new_val->data.bool_val);
      msg->payload.enable_disable = new_val->data.bool_val;
    } else if (!strcmp(new_val->xpath, "/hicn:hicn-conf/params/pit_max_size")) {
      SRP_LOG_DBG("A change detected in '%s', op=%d",
                  new_val ? new_val->xpath : old_val->xpath,
                  new_val->data.int32_val);
      msg->payload.pit_max_size = new_val->data.int32_val;
    } else if (!strcmp(new_val->xpath, "/hicn:hicn-conf/params/cs_max_size")) {
      SRP_LOG_DBG("A change detected in '%s', op=%d",
                  new_val ? new_val->xpath : old_val->xpath,
                  new_val->data.int32_val);
      msg->payload.cs_max_size = new_val->data.int32_val;
    } else if (!strcmp(new_val->xpath,
                       "/hicn:hicn-conf/params/cs_reserved_app")) {
      SRP_LOG_DBG("A change detected in '%s', op=%d",
                  new_val ? new_val->xpath : old_val->xpath,
                  new_val->data.int32_val);
      msg->payload.cs_reserved_app = new_val->data.int32_val;
    } else if (!strcmp(new_val->xpath,
                       "/hicn:hicn-conf/params/pit_dflt_lifetime_sec")) {
      SRP_LOG_DBG("A change detected in '%s', op=%d",
                  new_val ? new_val->xpath : old_val->xpath,
                  new_val->data.decimal64_val);
      msg->payload.pit_dflt_lifetime_sec = new_val->data.decimal64_val;
    } else if (!strcmp(new_val->xpath,
                       "/hicn:hicn-conf/params/pit_min_lifetime_sec")) {
      SRP_LOG_DBG("A change detected in '%s', op=%d",
                  new_val ? new_val->xpath : old_val->xpath,
                  new_val->data.decimal64_val);
      msg->payload.pit_min_lifetime_sec = new_val->data.decimal64_val;
    } else if (!strcmp(new_val->xpath,
                       "/hicn:hicn-conf/params/pit_max_lifetime_sec")) {
      SRP_LOG_DBG("A change detected in '%s', op=%d",
                  new_val ? new_val->xpath : old_val->xpath,
                  new_val->data.decimal64_val);
      msg->payload.pit_max_lifetime_sec = new_val->data.decimal64_val;
    }

    switch (op) {
      case SR_OP_CREATED:
      case SR_OP_MODIFIED:
        op_rc = 0;  // OK
        break;
      case SR_OP_DELETED:
        op_rc = 1;  // ERROR
        break;
      default:
        break;
    }
    sr_xpath_recover(&xpath_ctx);
    if (SR_ERR_INVAL_ARG == op_rc) {
      sr_set_error(session, "You are not allowed to change the schema.",
                   new_val ? new_val->xpath : old_val->xpath);
    }
    sr_free_val(old_val);
    sr_free_val(new_val);
  }

  params_send(msg, resp);

  /*
      sr_val_t value = { 0 };
      value.type = SR_INT32_T;
      value.data.int32_val = 20;
      rc = sr_set_item(session, "/hicn:hicn-conf/params/pit_max_lifetime_sec",
     &value, SR_EDIT_DEFAULT); if (SR_ERR_OK != rc) { printf("Error by
     sr_set_item: %s\n", sr_strerror(rc));
      }

  */

  sr_free_change_iter(iter);
  SRP_LOG_DBG_MSG("Configuration applied successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to get hicn param in vpp.
 */
static int hicn_node_params_get_cb(const char *xpath, const sr_val_t *input,
                                   const size_t input_cnt, sr_val_t **output,
                                   size_t *output_cnt, void *private_ctx) {
  vapi_msg_hicn_api_node_params_get *msg;
  vapi_msg_hicn_api_node_params_get_reply *resp;

  msg = vapi_alloc_hicn_api_node_params_get(g_vapi_ctx_instance);
  vapi_msg_hicn_api_node_params_get_hton(msg);

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_node_params_get_ntoh(resp);

  SRP_LOG_DBG_MSG("hicn parameter receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to get hicn stat in vpp.
 */
static int hicn_node_stat_get_cb(const char *xpath, const sr_val_t *input,
                                 const size_t input_cnt, sr_val_t **output,
                                 size_t *output_cnt, void *private_ctx) {
  vapi_msg_hicn_api_node_stats_get *msg;
  vapi_msg_hicn_api_node_stats_get_reply *resp;

  msg = vapi_alloc_hicn_api_node_stats_get(g_vapi_ctx_instance);
  vapi_msg_hicn_api_node_stats_get_hton(msg);

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_node_stats_get_ntoh(resp);
  SRP_LOG_DBG_MSG("hicn status receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to get hicn strategy in vpp.
 */
static int hicn_strategy_get_cb(const char *xpath, const sr_val_t *input,
                                const size_t input_cnt, sr_val_t **output,
                                size_t *output_cnt, void *private_ctx) {
  // allocate memory msg and resp
  vapi_msg_hicn_api_strategy_get *msg;
  vapi_msg_hicn_api_strategy_get_reply *resp;

  msg = vapi_alloc_hicn_api_strategy_get(g_vapi_ctx_instance);
  vapi_msg_hicn_api_strategy_get_hton(msg);

  msg->payload.strategy_id = input[0].data.uint32_val;

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_strategy_get_ntoh(resp);

  SRP_LOG_DBG_MSG("hicn strategy receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to get hicn strategies in vpp.
 */
static int hicn_strategies_get_cb(const char *xpath, const sr_val_t *input,
                                  const size_t input_cnt, sr_val_t **output,
                                  size_t *output_cnt, void *private_ctx) {
  // allocate memory msg and resp
  vapi_msg_hicn_api_strategies_get *msg;
  vapi_msg_hicn_api_strategies_get_reply *resp;

  msg = vapi_alloc_hicn_api_strategies_get(g_vapi_ctx_instance);
  vapi_msg_hicn_api_strategies_get_hton(msg);

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_strategies_get_ntoh(resp);

  SRP_LOG_DBG_MSG("hicn strategy receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to get hicn route in vpp.
 */
static int hicn_route_get_cb(const char *xpath, const sr_val_t *input,
                             const size_t input_cnt, sr_val_t **output,
                             size_t *output_cnt, void *private_ctx) {
  // allocate memory msg and resp
  vapi_msg_hicn_api_route_get *msg;
  vapi_msg_hicn_api_route_get_reply *resp;

  msg = vapi_alloc_hicn_api_route_get(g_vapi_ctx_instance);
  vapi_msg_hicn_api_route_get_hton(msg);

  msg->payload.prefix[0] = input[0].data.uint64_val;
  msg->payload.prefix[1] = input[1].data.uint64_val;
  msg->payload.len = input[2].data.uint8_val;

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_route_get_ntoh(resp);

  SRP_LOG_DBG_MSG("hicn strategy receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to add hicn route nhops in vpp.
 */
static int hicn_route_nhops_add_cb(const char *xpath, const sr_val_t *input,
                                   const size_t input_cnt, sr_val_t **output,
                                   size_t *output_cnt, void *private_ctx) {
  // allocate memory msg and resp
  vapi_msg_hicn_api_route_nhops_add *msg;
  vapi_msg_hicn_api_route_nhops_add_reply *resp;

  msg = vapi_alloc_hicn_api_route_nhops_add(g_vapi_ctx_instance);
  vapi_msg_hicn_api_route_nhops_add_hton(msg);

  msg->payload.prefix[0] = input[0].data.uint64_val;
  msg->payload.prefix[1] = input[1].data.uint64_val;
  msg->payload.len = input[2].data.uint8_val;
  msg->payload.face_ids[0] = input[3].data.uint32_val;
  msg->payload.face_ids[1] = input[4].data.uint32_val;
  msg->payload.face_ids[2] = input[5].data.uint32_val;
  msg->payload.face_ids[3] = input[6].data.uint32_val;
  msg->payload.face_ids[4] = input[7].data.uint32_val;
  msg->payload.face_ids[5] = input[8].data.uint32_val;
  msg->payload.face_ids[6] = input[9].data.uint32_val;

  msg->payload.n_faces = input[10].data.uint8_val;

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_route_nhops_add_ntoh(resp);

  SRP_LOG_DBG_MSG("hicn strategy receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to del hicn route in vpp.
 */
static int hicn_route_del_cb(const char *xpath, const sr_val_t *input,
                             const size_t input_cnt, sr_val_t **output,
                             size_t *output_cnt, void *private_ctx) {
  // allocate memory msg and resp
  vapi_msg_hicn_api_route_del *msg;
  vapi_msg_hicn_api_route_del_reply *resp;

  msg = vapi_alloc_hicn_api_route_del(g_vapi_ctx_instance);
  vapi_msg_hicn_api_route_del_hton(msg);

  msg->payload.prefix[0] = input[0].data.uint64_val;
  msg->payload.prefix[1] = input[1].data.uint64_val;
  msg->payload.len = input[2].data.uint8_val;

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_route_del_ntoh(resp);

  SRP_LOG_DBG_MSG("hicn strategy receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to get face ip params in hicn in vpp.
 */
static int hicn_face_ip_params_get_cb(const char *xpath, const sr_val_t *input,
                                      const size_t input_cnt, sr_val_t **output,
                                      size_t *output_cnt, void *private_ctx) {
  // allocate memory msg and resp
  vapi_msg_hicn_api_face_ip_params_get *msg;
  vapi_msg_hicn_api_face_ip_params_get_reply *resp;

  msg = vapi_alloc_hicn_api_face_ip_params_get(g_vapi_ctx_instance);
  vapi_msg_hicn_api_face_ip_params_get_hton(msg);

  msg->payload.faceid = input[0].data.uint16_val;

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_face_ip_params_get_ntoh(resp);

  SRP_LOG_DBG_MSG("hicn strategy receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to get face ip params in hicn in vpp.
 */
static int hicn_punting_add_cb(const char *xpath, const sr_val_t *input,
                               const size_t input_cnt, sr_val_t **output,
                               size_t *output_cnt, void *private_ctx) {
  // allocate memory msg and resp
  vapi_msg_hicn_api_punting_add *msg;
  vapi_msg_hicn_api_punting_add_reply *resp;

  msg = vapi_alloc_hicn_api_punting_add(g_vapi_ctx_instance);
  vapi_msg_hicn_api_punting_add_hton(msg);

  msg->payload.prefix[0] = input[0].data.uint64_val;
  msg->payload.prefix[1] = input[1].data.uint64_val;
  msg->payload.len = input[2].data.uint8_val;
  msg->payload.swif = input[3].data.uint32_val;

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_punting_add_ntoh(resp);

  SRP_LOG_DBG_MSG("hicn strategy receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to del hicn route nhops in vpp.
 */
static int hicn_route_nhops_del_cb(const char *xpath, const sr_val_t *input,
                                   const size_t input_cnt, sr_val_t **output,
                                   size_t *output_cnt, void *private_ctx) {
  // allocate memory msg and resp
  vapi_msg_hicn_api_route_nhop_del *msg;
  vapi_msg_hicn_api_route_nhop_del_reply *resp;

  msg = vapi_alloc_hicn_api_route_nhop_del(g_vapi_ctx_instance);
  vapi_msg_hicn_api_route_nhop_del_hton(msg);

  msg->payload.prefix[0] = input[0].data.uint64_val;
  msg->payload.prefix[1] = input[1].data.uint64_val;
  msg->payload.len = input[2].data.uint8_val;
  msg->payload.faceid = input[3].data.uint16_val;

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_route_nhop_del_ntoh(resp);

  SRP_LOG_DBG_MSG("hicn strategy receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to del hicn punting in vpp.
 */
static int hicn_punting_del_cb(const char *xpath, const sr_val_t *input,
                               const size_t input_cnt, sr_val_t **output,
                               size_t *output_cnt, void *private_ctx) {
  // allocate memory msg and resp
  vapi_msg_hicn_api_punting_del *msg;
  vapi_msg_hicn_api_punting_del_reply *resp;

  msg = vapi_alloc_hicn_api_punting_del(g_vapi_ctx_instance);
  vapi_msg_hicn_api_punting_del_hton(msg);

  msg->payload.prefix[0] = input[0].data.uint64_val;
  msg->payload.prefix[1] = input[1].data.uint64_val;
  msg->payload.len = input[2].data.uint8_val;
  msg->payload.swif = input[3].data.uint32_val;

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_punting_del_ntoh(resp);

  test_state = 30;

  SRP_LOG_DBG_MSG("hicn strategy receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to del hicn face ip in vpp.
 */
static int hicn_face_ip_del_cb(const char *xpath, const sr_val_t *input,
                               const size_t input_cnt, sr_val_t **output,
                               size_t *output_cnt, void *private_ctx) {
  // allocate memory msg and resp
  vapi_msg_hicn_api_face_ip_del *msg;
  vapi_msg_hicn_api_face_ip_del_reply *resp;

  msg = vapi_alloc_hicn_api_face_ip_del(g_vapi_ctx_instance);
  vapi_msg_hicn_api_face_ip_del_hton(msg);

  msg->payload.faceid = input[0].data.uint16_val;

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_face_ip_del_ntoh(resp);

  SRP_LOG_DBG_MSG("hicn strategy receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief API to del hicn face ip in vpp.
 */
static int hicn_face_ip_add_cb(const char *xpath, const sr_val_t *input,
                               const size_t input_cnt, sr_val_t **output,
                               size_t *output_cnt, void *private_ctx) {
  // allocate memory msg and resp
  vapi_msg_hicn_api_face_ip_add *msg;
  vapi_msg_hicn_api_face_ip_add_reply *resp;

  msg = vapi_alloc_hicn_api_face_ip_add(g_vapi_ctx_instance);
  vapi_msg_hicn_api_face_ip_add_hton(msg);

  msg->payload.nh_addr[0] = input[0].data.uint64_val;
  msg->payload.nh_addr[1] = input[1].data.uint64_val;
  msg->payload.swif = input[2].data.uint32_val;

  if (VAPI_OK != vapi_send(g_vapi_ctx_instance, msg)) {
    SRP_LOG_DBG_MSG("Sending msg to VPP failed");
    return SR_ERR_OPERATION_FAILED;
  }

  HICN_VPP_VAPI_RECV;

  vapi_msg_hicn_api_face_ip_add_ntoh(resp);

  SRP_LOG_DBG_MSG("hicn strategy receive successfully");
  return SR_ERR_OK;
}

/**
 * @brief Helper function for subscribing all hicn APIs.
 */
int hicn_subscribe_events(sr_session_ctx_t *session,
                          sr_subscription_ctx_t **subscription) {
  int rc = SR_ERR_OK;
  SRP_LOG_DBG_MSG("Initializing hicn-interfaces plugin.");

  /*
    // Params subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:node-params-set",
    hicn_node_params_set_cb, session, SR_SUBSCR_CTX_REUSE, subscription); if (rc
    != SR_ERR_OK) { printf("Problem in subscription params-set\n"); goto error;
    }

    // Params subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:node-params-set",
    hicn_node_params_set_cb, session, SR_SUBSCR_CTX_REUSE, subscription); if (rc
    != SR_ERR_OK) { printf("Problem in subscription params-set\n"); goto error;
    }

    rc = sr_rpc_subscribe(session, "/hicn:node-params-get",
    hicn_node_params_get_cb, session, SR_SUBSCR_CTX_REUSE, subscription); if (rc
    != SR_ERR_OK) { printf("Problem in subscription params-get\n"); goto error;
    }

    // node state subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:node-stat-get", hicn_node_stat_get_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      printf("Problem in subscription stat-get\n");
      goto error;
    }

    // strategies subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:strategy-get", hicn_strategy_get_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      printf("Problem in subscription strategy-get\n");
      goto error;
    }

    rc = sr_rpc_subscribe(session, "/hicn:strategies-get",
    hicn_strategies_get_cb, session, SR_SUBSCR_CTX_REUSE, subscription); if (rc
    != SR_ERR_OK) { printf("Problem in subscription punting-del\n"); goto error;
    }

    // route subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:route-get", hicn_route_get_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      printf("Problem in subscription route-get\n");
      goto error;
    }

    rc = sr_rpc_subscribe(session, "/hicn:route-del", hicn_route_del_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      printf("Problem in subscription route-del\n");
      goto error;
    }


    // route nhops subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:route-nhops-add",
    hicn_route_nhops_add_cb, session, SR_SUBSCR_CTX_REUSE, subscription); if (rc
    != SR_ERR_OK) { printf("Problem in subscription route-get\n"); goto error;
    }

    rc = sr_rpc_subscribe(session, "/hicn:route-nhops-del",
    hicn_route_nhops_del_cb, session, SR_SUBSCR_CTX_REUSE, subscription); if (rc
    != SR_ERR_OK) { printf("Problem in subscription route-nhops-del\n"); goto
    error;
    }


    // face ip subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:face-ip-params-get",
    hicn_face_ip_params_get_cb, session, SR_SUBSCR_CTX_REUSE, subscription); if
    (rc != SR_ERR_OK) { printf("Problem in subscription face-ip-params-get\n");
      goto error;
    }


    rc = sr_rpc_subscribe(session, "/hicn:face-ip-add", hicn_face_ip_add_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      printf("Problem in subscription punting-del\n");
      goto error;
    }

    rc = sr_rpc_subscribe(session, "/hicn:face-ip-del", hicn_face_ip_del_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      printf("Problem in subscription punting-del\n");
      goto error;
    }

    // punting subscriptions

    rc = sr_rpc_subscribe(session, "/hicn:punting-add", hicn_punting_add_cb,
    session, SR_SUBSCR_CTX_REUSE, subscription); if (rc != SR_ERR_OK) {
      printf("Problem in subscription punting-add\n");
      goto error;
    }
  */
  rc = sr_rpc_subscribe(session, "/hicn:punting-del", hicn_punting_del_cb,
                        session, SR_SUBSCR_CTX_REUSE, subscription);
  if (rc != SR_ERR_OK) {
    printf("Problem in subscription punting-del\n");
    goto error;
  }

  rc = sr_subtree_change_subscribe(
      session, "/hicn:hicn-conf", hicn_node_params_set_cb, g_vapi_ctx_instance,
      100, SR_SUBSCR_CTX_REUSE | SR_SUBSCR_EV_ENABLED, subscription);
  if (SR_ERR_OK != rc) {
    printf("Problem in subscription /hicn:hicn-conf\n");
    goto error;
  }

  // subscribe as hicn state data provider
  rc = sr_dp_get_items_subscribe(session, "/hicn:hicn-state/states",
                                 hicn_state_cb, NULL, SR_SUBSCR_CTX_REUSE,
                                 subscription);
  if (rc != SR_ERR_OK) {
    goto error;
  }

  SRP_LOG_INF_MSG("hicn plugin initialized successfully.");
  return SR_ERR_OK;

error:
  SRP_LOG_ERR_MSG("Error by initialization of the hicn plugin.");
  sr_plugin_cleanup_cb(session, &g_vapi_ctx_instance);
  return rc;
}