/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */

#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <ctype.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hicn/core/connection.h>
#include <hicn/core/connection_table.h>
#include <hicn/core/forwarder.h>
//#include <hicn/core/system.h>
#ifdef WITH_MAPME
#include <hicn/core/mapme.h>
#endif /* WITH_MAPME */

#include <hicn/core/listener.h>  //the listener list
#include <hicn/core/listener_table.h>
#include <hicn/ctrl/hicn-light.h>
//#include <hicn/utils/utils.h>
#include <hicn/utils/punting.h>
#include <hicn/util/log.h>
#include <hicn/face.h>

#include "configuration.h"

#define ETHERTYPE 0x0801
#define DEFAULT_COST 1
#define DEFAULT_PORT 1234
#define DEFAULT_LOGLEVEL "info"
#define DEFAULT_CS_CAPACITY 100000

#define msg_malloc_list(msg, N, seq_number)                           \
  do {                                                                \
    msg = malloc(sizeof((msg)->header) + N * sizeof((msg)->payload)); \
    (msg)->header.message_type = RESPONSE_LIGHT;                      \
    (msg)->header.length = (uint16_t)(N);                             \
    (msg)->header.seq_num = (seq_number);                             \
  } while (0);

struct configuration_s {
  const char *fn_config;
  uint16_t port;
  uint16_t configuration_port;
  size_t cs_capacity;
  int loglevel;
  const char *logfile;
  int logfile_fd;
  bool daemon;
  kh_strategy_map_t *strategy_map;
  size_t n_suffixes_per_split;
  int_manifest_split_strategy_t split_strategy;
};

configuration_t *configuration_create() {
  configuration_t *config = malloc(sizeof(configuration_t));
  if (!config) return NULL;

  config->fn_config = NULL;
  config->port = PORT_NUMBER;
  config->configuration_port = 2001;  // TODO(eloparco): What is this?
  config->cs_capacity = DEFAULT_CS_CAPACITY;
  config->logfile = NULL;
  config->logfile_fd = -1;
#ifndef _WIN32
  config->daemon = false;
#else
  WSADATA wsaData = {0};
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
  configuration_set_loglevel(config, loglevel_from_str(DEFAULT_LOGLEVEL));
  config->strategy_map = kh_init_strategy_map();
  config->n_suffixes_per_split = DEFAULT_N_SUFFIXES_PER_SPLIT;
  config->split_strategy = DEFAULT_DISAGGREGATION_STRATEGY;

  return config;
}

void configuration_free(configuration_t *config) {
  assert(config);

  const char *k_prefix;
  unsigned _;
  (void)_;

  // Free the strategy hashmap
  kh_foreach(config->strategy_map, k_prefix, _, { free((char *)k_prefix); });
  kh_destroy_strategy_map(config->strategy_map);

  free(config);
}

size_t configuration_get_cs_size(const configuration_t *config) {
  return config->cs_capacity;
}

void configuration_set_cs_size(configuration_t *config, size_t size) {
  config->cs_capacity = size;
}

const char *configuration_get_fn_config(const configuration_t *config) {
  return config->fn_config;
}

void configuration_set_fn_config(configuration_t *config,
                                 const char *fn_config) {
  config->fn_config = fn_config;
}

void configuration_set_suffixes_per_split(configuration_t *config,
                                          size_t n_suffixes_per_split) {
  config->n_suffixes_per_split = n_suffixes_per_split;
}

size_t configuration_get_suffixes_per_split(const configuration_t *config) {
  return config->n_suffixes_per_split;
}

void configuration_set_split_strategy(
    configuration_t *config, int_manifest_split_strategy_t split_strategy) {
  config->split_strategy = split_strategy;
}

int_manifest_split_strategy_t configuration_get_split_strategy(
    const configuration_t *config) {
  return config->split_strategy;
}

void configuration_set_port(configuration_t *config, uint16_t port) {
  config->port = port;
}

uint16_t configuration_get_port(const configuration_t *config) {
  return config->port;
}

void configuration_set_configuration_port(configuration_t *config,
                                          uint16_t configuration_port) {
  config->configuration_port = configuration_port;
}

uint16_t configuration_get_configuration_port(const configuration_t *config) {
  return config->configuration_port;
}

void configuration_set_loglevel(configuration_t *config, int loglevel) {
  config->loglevel = loglevel;
  log_conf.log_level = loglevel;
}

int configuration_get_loglevel(const configuration_t *config) {
  return config->loglevel;
}

void configuration_set_logfile(configuration_t *config, const char *logfile) {
  config->logfile = logfile;
  log_conf.log_file = fopen(logfile, "w");
  config->logfile_fd = fileno(log_conf.log_file);
}

const char *configuration_get_logfile(const configuration_t *config) {
  return config->logfile;
}

int configuration_get_logfile_fd(const configuration_t *config) {
  return config->logfile_fd;
}

void configuration_set_daemon(configuration_t *config, bool daemon) {
  config->daemon = daemon;
}

bool configuration_get_daemon(const configuration_t *config) {
  return config->daemon;
}

void configuration_set_strategy(configuration_t *config, const char *prefix,
                                strategy_type_t strategy_type) {
  int res;
  khiter_t k = kh_put_strategy_map(config->strategy_map, strdup(prefix), &res);
  kh_value(config->strategy_map, k) = strategy_type;
}

strategy_type_t configuration_get_strategy(const configuration_t *config,
                                           const char *prefix) {
  khiter_t k = kh_get_strategy_map(config->strategy_map, prefix);
  if (k == kh_end(config->strategy_map)) return STRATEGY_TYPE_UNDEFINED;
  return kh_val(config->strategy_map, k);
}

void configuration_flush_log() {
  if (log_conf.log_file) fclose(log_conf.log_file);
}
