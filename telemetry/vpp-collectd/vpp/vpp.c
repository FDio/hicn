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
#include <vpp-api/client/stat_client.h>
#include <vppinfra/vec.h>
#undef counter_t

/************** OPTIONS ***********************************/
static const char *config_keys[2] = {
    "Verbose",
    "Tag",
};
static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);
static bool verbose = false;
static char *tag = NULL;

/************** DATA SOURCES ******************************/
static data_source_t combined_dsrc[2] = {
    {"packets", DS_TYPE_DERIVE, 0, NAN},
    {"bytes", DS_TYPE_DERIVE, 0, NAN},
};

static data_source_t simple_dsrc[1] = {
    {"packets", DS_TYPE_DERIVE, 0, NAN},
};

/************** DATA SETS *********************************/
static data_set_t if_drops_ds = {
    "if_drops",
    STATIC_ARRAY_SIZE(simple_dsrc),
    simple_dsrc,
};

static data_set_t if_punt_ds = {
    "if_punt",
    STATIC_ARRAY_SIZE(simple_dsrc),
    simple_dsrc,
};

static data_set_t if_ip4_ds = {
    "if_ip4",
    STATIC_ARRAY_SIZE(simple_dsrc),
    simple_dsrc,
};

static data_set_t if_ip6_ds = {
    "if_ip6",
    STATIC_ARRAY_SIZE(simple_dsrc),
    simple_dsrc,
};

static data_set_t if_rx_no_buf_ds = {
    "if_rx_no_buf",
    STATIC_ARRAY_SIZE(simple_dsrc),
    simple_dsrc,
};

static data_set_t if_rx_miss_ds = {
    "if_rx_miss",
    STATIC_ARRAY_SIZE(simple_dsrc),
    simple_dsrc,
};

static data_set_t if_rx_error_ds = {
    "if_rx_error",
    STATIC_ARRAY_SIZE(simple_dsrc),
    simple_dsrc,
};

static data_set_t if_tx_error_ds = {
    "if_tx_error",
    STATIC_ARRAY_SIZE(simple_dsrc),
    simple_dsrc,
};

static data_set_t if_mpls_ds = {
    "if_mpls",
    STATIC_ARRAY_SIZE(simple_dsrc),
    simple_dsrc,
};

static data_set_t if_rx_ds = {
    "if_rx",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

static data_set_t if_rx_unicast_ds = {
    "if_rx_unicast",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

static data_set_t if_rx_multicast_ds = {
    "if_rx_multicast",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

static data_set_t if_rx_broadcast_ds = {
    "if_rx_broadcast",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

static data_set_t if_tx_ds = {
    "if_tx",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

static data_set_t if_tx_unicast_ds = {
    "if_tx_unicast",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

static data_set_t if_tx_multicast_ds = {
    "if_tx_multicast",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

static data_set_t if_tx_broadcast_ds = {
    "if_tx_broadcast",
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

  sstrncpy(vl.plugin, "vpp", sizeof(vl.plugin));
  sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));
  sstrncpy(vl.type, type, sizeof(vl.type));

  if (tag != NULL)
    sstrncpy(vl.type_instance, tag, sizeof(vl.type_instance));

  return plugin_dispatch_values(&vl);
}

/*
 * Utility function to fetch the data set corresponding to the stat name.
 */
static int get_data_set(const char *stat_name, data_set_t *data_set_ptr) {
  if (data_set_ptr == NULL) {
    return 1;
  }

  if (strcmp(stat_name, "/if/rx") == 0) {
    *data_set_ptr = if_rx_ds;
  } else if (strcmp(stat_name, "/if/tx") == 0) {
    *data_set_ptr = if_tx_ds;
  } else if (strcmp(stat_name, "/if/ip4") == 0) {
    *data_set_ptr = if_ip4_ds;
  } else if (strcmp(stat_name, "/if/ip6") == 0) {
    *data_set_ptr = if_ip6_ds;
  } else if (strcmp(stat_name, "/if/drops") == 0) {
    *data_set_ptr = if_drops_ds;
  } else if (!verbose) {
    return 1;
  }

  if (verbose) {
    if (strcmp(stat_name, "/if/punt") == 0) {
      *data_set_ptr = if_punt_ds;
    } else if (strcmp(stat_name, "/if/mpls") == 0) {
      *data_set_ptr = if_mpls_ds;
    } else if (strcmp(stat_name, "/if/rx-no-buf") == 0) {
      *data_set_ptr = if_rx_no_buf_ds;
    } else if (strcmp(stat_name, "/if/rx-miss") == 0) {
      *data_set_ptr = if_rx_miss_ds;
    } else if (strcmp(stat_name, "/if/rx-error") == 0) {
      *data_set_ptr = if_rx_error_ds;
    } else if (strcmp(stat_name, "/if/rx-unicast") == 0) {
      *data_set_ptr = if_rx_unicast_ds;
    } else if (strcmp(stat_name, "/if/rx-multicast") == 0) {
      *data_set_ptr = if_rx_multicast_ds;
    } else if (strcmp(stat_name, "/if/rx-broadcast") == 0) {
      *data_set_ptr = if_rx_broadcast_ds;
    } else if (strcmp(stat_name, "/if/tx-error") == 0) {
      *data_set_ptr = if_tx_error_ds;
    } else if (strcmp(stat_name, "/if/tx-unicast") == 0) {
      *data_set_ptr = if_tx_unicast_ds;
    } else if (strcmp(stat_name, "/if/tx-multicast") == 0) {
      *data_set_ptr = if_tx_multicast_ds;
    } else if (strcmp(stat_name, "/if/tx-broadcast") == 0) {
      *data_set_ptr = if_tx_broadcast_ds;
    } else {
      return 1;
    }
  }

  return 0;
}

/**********************************************************/
/********** CALLBACK FUNCTIONS ****************************/
/**********************************************************/

/*
 * This function is called for each configuration item.
 */
static int vpp_config(const char *key, const char *value) {
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
 * This function is called once upon startup to initialize the plugin.
 */
static int vpp_init(void) {
  u8 *stat_segment_name = (u8 *)STAT_SEGMENT_SOCKET_FILE;
  int ret = stat_segment_connect((char *)stat_segment_name);

  if (ret)
    plugin_log(LOG_ERR, "vpp plugin: connecting to segment failed");

  return ret;
}

/*
 * This function is called in regular intervalls to collect the data.
 */
static int vpp_read(void) {
  uint8_t **patterns = {0};
  char **interfaces = {0};

  vec_add1(patterns, (uint8_t *)"^/if");
  vec_add1(patterns, (uint8_t *)"ip4-input");

  uint32_t *dir = stat_segment_ls(patterns);
  stat_segment_data_t *res = stat_segment_dump(dir);

  /* Read all available interfaces */
  for (int k = 0; k < vec_len(res); k++) {
    if (res[k].type == STAT_DIR_TYPE_NAME_VECTOR) {
      for (int i = 0; i < vec_len(res[k].name_vector); i++) {
        if (res[k].name_vector[i]) {
          vec_add1(interfaces, (char *)res[k].name_vector[i]);
        }
      }
      break;
    }
  }

  cdtime_t timestamp = cdtime();
  data_set_t data_set;
  int err = 0;

  /* Collect results for each interface and submit them */
  for (int i = 0; i < vec_len(res); i++) {
    switch (res[i].type) {
    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      for (int k = 0; k < vec_len(res[i].simple_counter_vec); k++) {
        for (int j = 0; j < vec_len(res[i].simple_counter_vec[k]); j++) {
          value_t values[1] = {
              (value_t){.derive = res[i].simple_counter_vec[k][j]}};

          if (get_data_set(res[i].name, &data_set)) {
            plugin_log(LOG_INFO, "vpp plugin: ignored stat name %s",
                       res[i].name);
            continue;
          }

          err = submit(interfaces[j], data_set.type, values, 1, &timestamp);

          if (err)
            goto END;
        }
      }
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      for (int k = 0; k < vec_len(res[i].combined_counter_vec); k++) {
        for (int j = 0; j < vec_len(res[i].combined_counter_vec[k]); j++) {
          value_t values[2] = {
              (value_t){.derive = res[i].combined_counter_vec[k][j].packets},
              (value_t){.derive = res[i].combined_counter_vec[k][j].bytes},
          };

          if (get_data_set(res[i].name, &data_set)) {
            plugin_log(LOG_INFO, "vpp plugin: ignored stat name %s",
                       res[i].name);
            continue;
          }

          err = submit(interfaces[j], data_set.type, values, 2, &timestamp);

          if (err)
            goto END;
        }
      }
      break;

    case STAT_DIR_TYPE_SCALAR_INDEX:
      plugin_log(LOG_INFO, "vpp plugin: %.2f %s", res[i].scalar_value,
                 res[i].name);
      break;

    case STAT_DIR_TYPE_NAME_VECTOR:
      break;

    case STAT_DIR_TYPE_ERROR_INDEX:
      break;

    default:
      plugin_log(LOG_WARNING, "vpp plugin: unknown stat type %d", res[i].type);
      break;
    }
  }

END:
  if (err)
    plugin_log(LOG_ERR,
               "vpp plugin: dispatching of results failed with error code %d.",
               err);

  stat_segment_data_free(res);

  return err;
}

/*
 * This function is called when plugin_log () has been used.
 */
static void vpp_log(int severity, const char *msg, user_data_t *ud) {
  printf("[LOG %i] %s\n", severity, msg);
  return;
}

/*
 * This function is called before shutting down collectd.
 */
static int vpp_shutdown(void) {
  plugin_log(LOG_INFO, "vpp plugin: shutting down");

  if (tag != NULL) {
    free(tag);
    tag = NULL;
  }

  stat_segment_disconnect();

  return 0;
}

/*
 * This function is called after loading the plugin to register it with
 * collectd.
 */
void module_register(void) {
  plugin_register_data_set(&if_drops_ds);
  plugin_register_data_set(&if_punt_ds);
  plugin_register_data_set(&if_ip4_ds);
  plugin_register_data_set(&if_ip6_ds);
  plugin_register_data_set(&if_rx_no_buf_ds);
  plugin_register_data_set(&if_rx_miss_ds);
  plugin_register_data_set(&if_rx_error_ds);
  plugin_register_data_set(&if_tx_error_ds);
  plugin_register_data_set(&if_mpls_ds);
  plugin_register_data_set(&if_rx_ds);
  plugin_register_data_set(&if_rx_unicast_ds);
  plugin_register_data_set(&if_rx_multicast_ds);
  plugin_register_data_set(&if_rx_broadcast_ds);
  plugin_register_data_set(&if_tx_ds);
  plugin_register_data_set(&if_tx_unicast_ds);
  plugin_register_data_set(&if_tx_multicast_ds);
  plugin_register_data_set(&if_tx_broadcast_ds);
  plugin_register_log("vpp", vpp_log, /* user data */ NULL);
  plugin_register_config("vpp", vpp_config, config_keys, config_keys_num);
  plugin_register_init("vpp", vpp_init);
  plugin_register_read("vpp", vpp_read);
  plugin_register_shutdown("vpp", vpp_shutdown);
  return;
}
