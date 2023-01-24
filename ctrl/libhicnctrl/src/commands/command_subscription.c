/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
 * \file command_subscription.h
 * \brief Implementation of subscription command.
 */
#include <limits.h>

#include <hicn/ctrl/command.h>

/* Parameters */

#define topics                                                                 \
  {                                                                            \
    .name = "topics",                                                          \
    .help =                                                                    \
        "Topics to subscribe to, e.g. 6 (110 in binary) means topic 2 (10 in " \
        "binary, TOPIC_CONNECTION) and topic 4 (100 in binary, "               \
        "TOPIC_LISTENER).",                                                    \
    .type = TYPE_INT(1, INT_MAX),                                              \
    .offset = offsetof(hc_subscription_t, topics),                             \
  }

/* Commands */

static const command_parser_t command_subscription_create = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_SUBSCRIPTION,
    .nparams = 1,
    .parameters = {topics},
};
COMMAND_REGISTER(command_subscription_create);
