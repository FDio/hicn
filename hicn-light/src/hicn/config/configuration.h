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

/**
 * @file configuration.h
 * @brief hicn-light configuration, such as in-band commands or CLI
 *
 * Manages all user configuration of the system, such as from the CLI or web
 * interface It remembers the user commands and will be able to write out a
 * config file.
 *
 */

#ifndef configuration_h
#define configuration_h

#include <hicn/utils/commands.h>

typedef struct configuration_s configuration_t;

struct forwarder_s;

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
configuration_t * configuration_create(struct forwarder_s * forwarder);

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
void configuration_free(configuration_t * config);

void configuration_setup_all_listeners(configuration_t *config, uint16_t port,
                                     const char *localPath);

void configuration_receive_command(configuration_t *config, command_type_t command,
        uint8_t * packet, unsigned ingress_id);

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
size_t configuration_content_store_get_size(configuration_t *config);

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
void configuration_content_store_set_size(configuration_t *config, size_t size);

strategy_type_t configuration_get_strategy(configuration_t *config, const char *prefix);

/**
 * Returns the Forwarder that owns the Configuration
 *
 * Returns the hicn-light Forwarder.  Used primarily by associated classes in
 * the configuration group.
 *
 * @param [in] config An allocated Configuration
 *
 * @return non-null The owning Forwarder
 * @return null An error
 *
 * Example:
 * @code
 * {
 *     <#example#>
 * }
 * @endcode
 */
struct forwarder_s * configuration_get_forwarder(const configuration_t *config);

uint8_t *
configuration_dispatch_command(configuration_t * config, command_type_t command_type,
        uint8_t * packet, unsigned ingress_id);

#endif  // configuration_h
