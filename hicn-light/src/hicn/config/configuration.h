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
 * @file configuration.h
 * @brief hicn-light configuration, such as in-band commands or CLI
 *
 * Manages all user configuration of the system, such as from the CLI or web
 * interface It remembers the user commands and will be able to write out a
 * config file.
 *
 */

#ifndef HICNLIGHT_CONFIGURATION_H
#define HICNLIGHT_CONFIGURATION_H

#include <hicn/util/khash.h>
#include "../core/msgbuf.h"
#include "../core/strategy.h"
#include <hicn/ctrl/api.h>
#include <hicn/ctrl/hicn-light-ng.h>

KHASH_MAP_INIT_STR(strategy_map, unsigned);

typedef struct configuration_s configuration_t;

/**
 * <#One Line Description#>
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * @retval <#value#> <#explanation#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
configuration_t *configuration_create();

/**
 * <#One Line Description#>
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * @retval <#value#> <#explanation#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
void configuration_free(configuration_t *config);

/**
 * Returns the configured size of the content store
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * @retval <#value#> <#explanation#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
size_t configuration_get_cs_size(const configuration_t *config);

/**
 * Sets the size of the content store (in objects, not bytes)
 *
 * Must be set before starting the forwarder
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
void configuration_set_cs_size(configuration_t *config, size_t size);

const char *configuration_get_fn_config(const configuration_t *config);

void configuration_set_fn_config(configuration_t *config,
                                 const char *fn_config);

void configuration_set_port(configuration_t *config, uint16_t port);

uint16_t configuration_get_port(const configuration_t *config);

void configuration_set_configuration_port(configuration_t *config,
                                          uint16_t configuration_port);

uint16_t configuration_get_configuration_port(const configuration_t *config);

void configuration_set_loglevel(configuration_t *config, int loglevel);

int configuration_get_loglevel(const configuration_t *config);

void configuration_set_logfile(configuration_t *config, const char *logfile);

const char *configuration_get_logfile(const configuration_t *config);

int configuration_get_logfile_fd(const configuration_t *config);

void configuration_set_daemon(configuration_t *config, bool daemon);

bool configuration_get_daemon(const configuration_t *config);

void configuration_set_strategy(configuration_t *config, const char *prefix,
                                strategy_type_t strategy_type);

strategy_type_t configuration_get_strategy(const configuration_t *config,
                                           const char *prefix);

void configuration_flush_log();

#endif  // HICNLIGHT_CONFIGURATION_H
