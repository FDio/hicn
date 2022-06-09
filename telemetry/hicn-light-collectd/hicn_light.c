/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
 */

#define ntohll hicn_ntohll  // Rename to avoid collision
#include <hicn/ctrl/api.h>
#include <hicn/ctrl/hicn-light-ng.h>
#include <hicn/util/sstrncpy.h>
#undef ntohll

#include "../data_model.h"
#include "collectd.h"
#include "plugin.h"
#include "utils/common/common.h"

#define PLUGIN_NAME "hicn_light"

static hc_sock_t *s = NULL;

static void submit(const char *type, value_t *values, size_t values_len,
                   meta_data_t *meta) {
  assert(type != NULL && values != NULL && values_len != 0);

  value_list_t vl = {.values = values, .values_len = values_len};
  if (meta) vl.meta = meta;

  int rc = strcpy_s(vl.plugin, sizeof(vl.plugin), PLUGIN_NAME);
  _ASSERT(rc == EOK);
  rc = strcpy_s(vl.type, sizeof(vl.type), type);
  _ASSERT(rc == EOK);
  rc = strcpy_s(vl.host, sizeof(vl.host), hostname_g);
  _ASSERT(rc == EOK);

  plugin_dispatch_values(&vl);
}

static int read_forwarder_global_stats(hc_data_t **pdata, meta_data_t *meta) {
  // Retrieve global stats from forwarder
  int rc = hc_stats_get(s, pdata);
  if (rc < 0) {
    plugin_log(LOG_ERR, "Could not read global stats from forwarder");
    return -1;
  }
  hicn_light_stats_t stats = *((hicn_light_stats_t *)(*pdata)->buffer);

  // Submit values
  value_t values[1];
  values[0] = (value_t){.gauge = stats.forwarder.countReceived};
  submit(pkts_processed_ds.type, values, 1, meta);
  values[0] = (value_t){.gauge = stats.forwarder.countInterestsReceived};
  submit(pkts_interest_count_ds.type, values, 1, meta);
  values[0] = (value_t){.gauge = stats.forwarder.countObjectsReceived};
  submit(pkts_data_count_ds.type, values, 1, meta);
  values[0] =
      (value_t){.gauge = stats.forwarder.countInterestsSatisfiedFromStore};
  submit(pkts_from_cache_count_ds.type, values, 1, meta);
  values[0] = (value_t){.gauge = stats.forwarder.countDroppedNoReversePath};
  submit(pkts_no_pit_count_ds.type, values, 1, meta);
  values[0] = (value_t){.gauge = stats.forwarder.countInterestsExpired};
  submit(pit_expired_count_ds.type, values, 1, meta);
  values[0] = (value_t){.gauge = stats.forwarder.countDataExpired};
  submit(cs_expired_count_ds.type, values, 1, meta);
  values[0] = (value_t){.gauge = stats.pkt_cache.n_lru_evictions};
  submit(cs_lru_count_ds.type, values, 1, meta);
  values[0] = (value_t){.gauge = stats.forwarder.countDropped};
  submit(pkts_drop_no_buf_ds.type, values, 1, meta);
  values[0] = (value_t){.gauge = stats.forwarder.countInterestsAggregated};
  submit(interests_aggregated_ds.type, values, 1, meta);
  values[0] = (value_t){.gauge = stats.forwarder.countInterestsRetransmitted};
  submit(interests_retx_ds.type, values, 1, meta);
  values[0] = (value_t){.gauge = stats.pkt_cache.n_pit_entries};
  submit(pit_entries_count_ds.type, values, 1, meta);
  values[0] = (value_t){.gauge = stats.pkt_cache.n_cs_entries};
  submit(cs_entries_count_ds.type, values, 1, meta);

  return 0;
}

static int read_forwarder_per_face_stats(hc_data_t **pdata, meta_data_t *meta) {
  // Retrieve per-face stats from forwarder
  int rc = hc_stats_list(s, pdata);
  if (rc < 0) {
    plugin_log(LOG_ERR, "Could not read face stats from forwarder");
    return -1;
  }
  hc_data_t *data = *pdata;
  cmd_stats_list_item_t *conn_stats = (cmd_stats_list_item_t *)data->buffer;
  cmd_stats_list_item_t *end =
      (cmd_stats_list_item_t *)(data->buffer +
                                data->size * data->out_element_size);

  // Submit values
  while (conn_stats < end) {
    rc = meta_data_add_unsigned_int(meta, "face_id", conn_stats->id);
    assert(rc == 0);

    value_t values[2];
    values[0] = (value_t){.derive = conn_stats->stats.interests.rx_pkts};
    values[1] = (value_t){.derive = conn_stats->stats.interests.rx_bytes};
    submit(irx_ds.type, values, 2, meta);
    values[0] = (value_t){.derive = conn_stats->stats.interests.tx_pkts};
    values[1] = (value_t){.derive = conn_stats->stats.interests.tx_bytes};
    submit(itx_ds.type, values, 2, meta);
    values[0] = (value_t){.derive = conn_stats->stats.data.rx_pkts};
    values[1] = (value_t){.derive = conn_stats->stats.data.rx_bytes};
    submit(drx_ds.type, values, 2, meta);
    values[0] = (value_t){.derive = conn_stats->stats.data.tx_pkts};
    values[1] = (value_t){.derive = conn_stats->stats.data.tx_bytes};
    submit(dtx_ds.type, values, 2, meta);

    conn_stats++;
  }

  return 0;
}

static int read_forwarder_stats() {
  // Create metadata
  meta_data_t *meta = meta_data_create();
  int rc = meta_data_add_string(meta, KAFKA_TOPIC_KEY, KAFKA_STREAM_TOPIC);
  assert(rc == 0);

  hc_data_t *data = NULL;
  rc = read_forwarder_global_stats(&data, meta);
  if (rc < 0) goto READ_ERROR;
  rc = read_forwarder_per_face_stats(&data, meta);

READ_ERROR:
  meta_data_destroy(meta);
  hc_data_free(data);
  return rc;
}

static int connect_to_forwarder() {
  plugin_log(LOG_INFO, "Connecting to forwarder");
  s = hc_sock_create_forwarder(HICNLIGHT_NG);
  if (!s) {
    plugin_log(LOG_ERR, "Could not create socket");
    return -1;
  }

  int rc = hc_sock_connect(s);
  if (rc < 0) {
    plugin_log(LOG_ERR, "Could not establish connection to forwarder");
    hc_sock_free(s);
    s = NULL;
    return -1;
  }

  return 0;
}

static int disconnect_from_forwarder() {
  plugin_log(LOG_INFO, "Disconnecting from forwarder");

  if (s == NULL) {
    plugin_log(LOG_ERR, "Forwarder not connected");
    return -1;
  }

  hc_command_t command = {0};
  command.object.connection.id = 0;
  int rc = strcpy_s(command.object.connection.name,
                    sizeof(command.object.connection.name), "SELF");
  if (rc != EOK || hc_connection_delete(s, &command.object.connection) < 0) {
    rc = -1;
    plugin_log(LOG_ERR, "Error removing local connection to forwarder");
  }

  hc_sock_free(s);
  return rc;
}

void module_register() {
  // Data sets
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
  plugin_register_data_set(&irx_ds);
  plugin_register_data_set(&itx_ds);
  plugin_register_data_set(&drx_ds);
  plugin_register_data_set(&dtx_ds);

  // Callbacks
  plugin_register_init(PLUGIN_NAME, connect_to_forwarder);
  plugin_register_read(PLUGIN_NAME, read_forwarder_stats);
  plugin_register_shutdown(PLUGIN_NAME, disconnect_from_forwarder);
}