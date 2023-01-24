/*
 * Copyright (c) 2021-2023 Cisco and/or its affiliates.
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
 * \file command_strategy.h
 * \brief Implementation of strategy command.
 */
#include <hicn/ctrl/command.h>

/* Parameters */
#define prefix                                                          \
  {                                                                     \
    .name = "prefix",                                                   \
    .help = "The hicn name as IPv4 or IPv6 address (e.g 1234::0/64).",  \
    .type = TYPE_IP_PREFIX, .offset = offsetof(hc_strategy_t, address), \
    .offset2 = offsetof(hc_strategy_t, len),                            \
    .offset3 = offsetof(hc_strategy_t, family),                         \
  }

#define strategy                                                               \
  {                                                                            \
    .name = "strategy",                                                        \
    .help =                                                                    \
        "Strategy type (e.g. 'random', 'loadbalancer', 'low_latency', "        \
        "'replication', 'bestpath', local_remote).",                           \
    .type = TYPE_ENUM(strategy_type), .offset = offsetof(hc_strategy_t, type), \
  }

#define local_prefix                                                          \
  {                                                                           \
    .name = "local_prefix",                                                   \
    .help = "The hicn name as IPv4 or IPv6 address (e.g 1234::0/64).",        \
    .type = TYPE_IP_PREFIX, .offset = offsetof(hc_strategy_t, local_address), \
    .offset2 = offsetof(hc_strategy_t, local_len),                            \
    .offset3 = offsetof(hc_strategy_t, local_family),                         \
  }

/* Commands */

static const command_parser_t command_strategy_list = {
    .action = ACTION_SET,
    .object_type = OBJECT_TYPE_STRATEGY,
    .nparams = 2,
    .parameters = {prefix, strategy},
};
COMMAND_REGISTER(command_strategy_list);

static const command_parser_t local_prefix_add = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_LOCAL_PREFIX,
    .nparams = 3,
    .parameters = {prefix, strategy, local_prefix},
};
COMMAND_REGISTER(local_prefix_add);
