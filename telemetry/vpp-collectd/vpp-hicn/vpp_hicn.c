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

#if !HAVE_CONFIG_H
#include <stdlib.h>
#include <string.h>

#ifndef __USE_ISOC99 /* required for NAN */
#define DISABLE_ISOC99 1
#define __USE_ISOC99 1
#endif /* !defined(__USE_ISOC99) */

#if DISABLE_ISOC99
#undef DISABLE_ISOC99
#undef __USE_ISOC99
#endif /* DISABLE_ISOC99 */
#endif /* ! HAVE_CONFIG */

/* Keep order as it is */
#include <config.h>
#include <collectd.h>
#include <common.h>
#include <plugin.h>

#define counter_t vpp_counter_t
#include <vapi/hicn.api.vapi.h>
#include <vapi/vapi_safe.h>
#undef counter_t

DEFINE_VAPI_MSG_IDS_HICN_API_JSON
vapi_ctx_t vapi_ctx;

/************** OPTIONS ***********************************/
static const char *config_keys[2] = {
    "Verbose",
    "Tag",
};
static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);
static bool verbose = false;
static char *tag = NULL;

/************** DATA SOURCES ******************************/
static data_source_t packets_dsrc[1] = {
    {"packets", DS_TYPE_GAUGE, 0, NAN},
};

static data_source_t interests_dsrc[1] = {
    {"interests", DS_TYPE_GAUGE, 0, NAN},
};

static data_source_t data_dsrc[1] = {
    {"data", DS_TYPE_GAUGE, 0, NAN},
};

static data_source_t combined_dsrc[2] = {
    {"packets", DS_TYPE_DERIVE, 0, NAN},
    {"bytes", DS_TYPE_DERIVE, 0, NAN},
};

/************** DATA SETS NODE ****************************/
static data_set_t pkts_processed_ds = {
    "pkts_processed",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

static data_set_t pkts_interest_count_ds = {
    "pkts_interest_count",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

static data_set_t pkts_data_count_ds = {
    "pkts_data_count",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

static data_set_t pkts_from_cache_count_ds = {
    "pkts_from_cache_count",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

static data_set_t pkts_no_pit_count_ds = {
    "pkts_no_pit_count",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

static data_set_t pit_expired_count_ds = {
    "pit_expired_count",
    STATIC_ARRAY_SIZE(interests_dsrc),
    interests_dsrc,
};

static data_set_t cs_expired_count_ds = {
    "cs_expired_count",
    STATIC_ARRAY_SIZE(data_dsrc),
    data_dsrc,
};

static data_set_t cs_lru_count_ds = {
    "cs_lru_count",
    STATIC_ARRAY_SIZE(data_dsrc),
    data_dsrc,
};

static data_set_t pkts_drop_no_buf_ds = {
    "pkts_drop_no_buf",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

static data_set_t interests_aggregated_ds = {
    "interests_aggregated",
    STATIC_ARRAY_SIZE(interests_dsrc),
    interests_dsrc,
};

static data_set_t interests_retx_ds = {
    "interests_retx",
    STATIC_ARRAY_SIZE(interests_dsrc),
    interests_dsrc,
};

static data_set_t interests_hash_collision_ds = {
    "interests_hash_collision",
    STATIC_ARRAY_SIZE(interests_dsrc),
    interests_dsrc,
};

static data_set_t pit_entries_count_ds = {
    "pit_entries_count",
    STATIC_ARRAY_SIZE(interests_dsrc),
    interests_dsrc,
};

static data_set_t cs_entries_count_ds = {
    "cs_entries_count",
    STATIC_ARRAY_SIZE(data_dsrc),
    data_dsrc,
};

static data_set_t cs_entries_ntw_count_ds = {
    "cs_entries_ntw_count",
    STATIC_ARRAY_SIZE(data_dsrc),
    data_dsrc,
};

/************** DATA SETS FACE ****************************/
static data_set_t irx_ds = {
    "irx",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

static data_set_t itx_ds = {
    "itx",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

static data_set_t drx_ds = {
    "drx",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

static data_set_t dtx_ds = {
    "dtx",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

/**********************************************************/
/********** UTILITY FUNCTIONS *****************************/
/**********************************************************/

/*
 * Utility function used by the read callback to populate a
 * value_list_t and pass it to plugin_dispatch_values.
 */
static int submit(const char *plugin_instance, const char *type,
                  value_t *values, size_t values_len, cdtime_t *timestamp) {
  value_list_t vl = VALUE_LIST_INIT;
  vl.values = values;
  vl.values_len = values_len;

  if (timestamp != NULL) {
    vl.time = *timestamp;
  }

  sstrncpy(vl.plugin, "vpp_hicn", sizeof(vl.plugin));
  sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));
  sstrncpy(vl.type, type, sizeof(vl.type));

  if (tag != NULL)
    sstrncpy(vl.type_instance, tag, sizeof(vl.type_instance));

  return plugin_dispatch_values(&vl);
}

/**********************************************************/
/********** CALLBACK FUNCTIONS ****************************/
/**********************************************************/

/*
 * This function is called for each configuration item.
 */
static int vpp_hicn_config(const char *key, const char *value) {
  if (strcasecmp(key, "Verbose") == 0) {
    verbose = IS_TRUE(value);
  } else if (strcasecmp(key, "Tag") == 0) {
    if (tag != NULL) {
      free(tag);
      tag = NULL;
    }

    if (strcasecmp(value, "None")) {
      tag = strdup(value);
    }
  } else {
    return 1;
  }

  return 0;
}

/*
 * Callback called by the hICN plugin API when node stats are ready.
 */
static vapi_error_e
parse_node_stats(vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv,
                 bool is_last,
                 vapi_payload_hicn_api_node_stats_get_reply *reply) {
  if (reply == NULL || rv != VAPI_OK)
    return rv;

  if (reply->retval != VAPI_OK)
    return reply->retval;

  char *node_name = "node";
  value_t values[1];
  cdtime_t timestamp = cdtime();

  values[0] = (value_t){.gauge = reply->pkts_processed};
  submit(node_name, pkts_processed_ds.type, values, 1, &timestamp);
  values[0] = (value_t){.gauge = reply->pkts_interest_count};
  submit(node_name, pkts_interest_count_ds.type, values, 1, &timestamp);
  values[0] = (value_t){.gauge = reply->pkts_data_count};
  submit(node_name, pkts_data_count_ds.type, values, 1, &timestamp);
  values[0] = (value_t){.gauge = reply->interests_retx};
  submit(node_name, interests_retx_ds.type, values, 1, &timestamp);
  values[0] = (value_t){.gauge = reply->pit_entries_count};
  submit(node_name, pit_entries_count_ds.type, values, 1, &timestamp);
  values[0] = (value_t){.gauge = reply->cs_entries_count};
  submit(node_name, cs_entries_count_ds.type, values, 1, &timestamp);

  if (verbose) {
    values[0] = (value_t){.gauge = reply->pkts_from_cache_count};
    submit(node_name, pkts_from_cache_count_ds.type, values, 1, &timestamp);
    values[0] = (value_t){.gauge = reply->interests_aggregated};
    submit(node_name, interests_aggregated_ds.type, values, 1, &timestamp);
    values[0] = (value_t){.gauge = reply->cs_expired_count};
    submit(node_name, cs_expired_count_ds.type, values, 1, &timestamp);
    values[0] = (value_t){.gauge = reply->cs_lru_count};
    submit(node_name, cs_lru_count_ds.type, values, 1, &timestamp);
    values[0] = (value_t){.gauge = reply->pit_expired_count};
    submit(node_name, pit_expired_count_ds.type, values, 1, &timestamp);
    values[0] = (value_t){.gauge = reply->pkts_no_pit_count};
    submit(node_name, pkts_no_pit_count_ds.type, values, 1, &timestamp);
    values[0] = (value_t){.gauge = reply->pkts_drop_no_buf};
    submit(node_name, pkts_drop_no_buf_ds.type, values, 1, &timestamp);
    values[0] = (value_t){.gauge = reply->interests_hash_collision};
    submit(node_name, interests_hash_collision_ds.type, values, 1, &timestamp);
    values[0] = (value_t){.gauge = reply->cs_entries_ntw_count};
    submit(node_name, cs_entries_ntw_count_ds.type, values, 1, &timestamp);
  }

  return VAPI_OK;
}

/*
 * Callback called by the hICN plugin API when face stats are ready.
 */
static vapi_error_e
parse_face_stats(vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv,
                 bool is_last,
                 vapi_payload_hicn_api_face_stats_details *reply) {
  if (reply == NULL || rv != VAPI_OK)
    return rv;

  if (reply->retval != VAPI_OK)
    return reply->retval;

  char face_name[10];
  snprintf(face_name, 10, "face%u", reply->faceid);
  value_t values[2];
  cdtime_t timestamp = cdtime();

  values[0] = (value_t){.derive = reply->irx_packets};
  values[1] = (value_t){.derive = reply->irx_bytes};
  submit(face_name, irx_ds.type, values, 2, &timestamp);
  values[0] = (value_t){.derive = reply->itx_packets};
  values[1] = (value_t){.derive = reply->itx_bytes};
  submit(face_name, itx_ds.type, values, 2, &timestamp);
  values[0] = (value_t){.derive = reply->drx_packets};
  values[1] = (value_t){.derive = reply->drx_bytes};
  submit(face_name, drx_ds.type, values, 2, &timestamp);
  values[0] = (value_t){.derive = reply->dtx_packets};
  values[1] = (value_t){.derive = reply->dtx_bytes};
  submit(face_name, dtx_ds.type, values, 2, &timestamp);

  return VAPI_OK;
}

/*
 * This function is called once upon startup to initialize the plugin.
 */
static int vpp_hicn_init(void) {
  int ret = vapi_connect_safe(&vapi_ctx, 0);

  if (ret)
    plugin_log(LOG_ERR, "vpp_hicn plugin: vapi_connect_safe failed");

  return ret;
}

/*
 * This function is called in regular intervalls to collect the data.
 */
static int vpp_hicn_read(void) {
  int err = VAPI_OK;

  vapi_lock();

  // NODE
  vapi_msg_hicn_api_node_stats_get *hicn_node_stats_msg;
  hicn_node_stats_msg = vapi_alloc_hicn_api_node_stats_get(vapi_ctx);

  if (!hicn_node_stats_msg) {
    plugin_log(LOG_ERR,
               "vpp_hicn plugin: could not create hicn_node_stats message");
    err = VAPI_ENOMEM;
    goto END;
  }

  err = vapi_hicn_api_node_stats_get(vapi_ctx, hicn_node_stats_msg,
                                     parse_node_stats, NULL);

  if (err) {
    plugin_log(LOG_ERR,
               "vpp_hicn plugin: query of node stats failed with error %d",
               err);
    goto END;
  }

  // FACES
  vapi_msg_hicn_api_face_stats_dump *hicn_face_stats_msg;
  hicn_face_stats_msg = vapi_alloc_hicn_api_face_stats_dump(vapi_ctx);

  if (!hicn_face_stats_msg) {
    plugin_log(LOG_ERR,
               "vpp_hicn plugin: could not create hicn_face_stats message");
    err = VAPI_ENOMEM;
    goto END;
  }

  err = vapi_hicn_api_face_stats_dump(vapi_ctx, hicn_face_stats_msg,
                                      parse_face_stats, NULL);

  if (err) {
    plugin_log(LOG_ERR,
               "vpp_hicn plugin: query of face stats failed with error %d",
               err);
    goto END;
  }

END:
  vapi_unlock();

  return err;
}

/*
 * This function is called when plugin_log () has been used.
 */
static void vpp_hicn_log(int severity, const char *msg, user_data_t *ud) {
  printf("[LOG %i] %s\n", severity, msg);
  return;
}

/*
 * This function is called before shutting down collectd.
 */
static int vpp_hicn_shutdown(void) {
  plugin_log(LOG_INFO, "vpp_hicn plugin: shutting down");

  int ret = vapi_disconnect_safe();
  plugin_log(LOG_INFO, "vpp_hicn plugin: disconnect vapi %s",
             ret == 0 ? "ok" : "error");

  if (tag != NULL) {
    free(tag);
    tag = NULL;
  }

  return ret;
}

/*
 * This function is called after loading the plugin to register it with
 * collectd.
 */
void module_register(void) {
  // data sets face
  plugin_register_data_set(&irx_ds);
  plugin_register_data_set(&itx_ds);
  plugin_register_data_set(&drx_ds);
  plugin_register_data_set(&dtx_ds);
  // data sets node
  plugin_register_data_set(&pkts_processed_ds);
  plugin_register_data_set(&pkts_interest_count_ds);
  plugin_register_data_set(&pkts_data_count_ds);
  plugin_register_data_set(&pkts_from_cache_count_ds);
  plugin_register_data_set(&pkts_no_pit_count_ds);
  plugin_register_data_set(&pit_expired_count_ds);
  plugin_register_data_set(&cs_expired_count_ds);
  plugin_register_data_set(&cs_lru_count_ds);
  plugin_register_data_set(&pkts_drop_no_buf_ds);
  plugin_register_data_set(&interests_aggregated_ds);
  plugin_register_data_set(&interests_retx_ds);
  plugin_register_data_set(&interests_hash_collision_ds);
  plugin_register_data_set(&pit_entries_count_ds);
  plugin_register_data_set(&cs_entries_count_ds);
  plugin_register_data_set(&cs_entries_ntw_count_ds);
  // callbacks
  plugin_register_log("vpp_hicn", vpp_hicn_log, /* user data */ NULL);
  plugin_register_config("vpp_hicn", vpp_hicn_config, config_keys,
                         config_keys_num);
  plugin_register_init("vpp_hicn", vpp_hicn_init);
  plugin_register_read("vpp_hicn", vpp_hicn_read);
  plugin_register_shutdown("vpp_hicn", vpp_hicn_shutdown);
  return;
}
