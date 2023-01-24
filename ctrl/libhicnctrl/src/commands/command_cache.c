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
 * \file command_cache.h
 * \brief Implementation of cache command.
 */

#include <math.h>
#include <hicn/ctrl/command.h>

/* Parameters */

#define serve                                                            \
  {                                                                      \
    .name = "serve",                                                     \
    .help =                                                              \
        "Enables/disables replies from local content store. Either the " \
        "string 'on' or 'off'",                                          \
    .type = TYPE_ON_OFF, .offset = offsetof(hc_cache_t, serve),          \
  }

#define store                                                                 \
  {                                                                           \
    .name = "store",                                                          \
    .help =                                                                   \
        "enables/disables the storage of incoming data packets in the local " \
        "content store. Either the string 'on' or 'off'",                     \
    .type = TYPE_ON_OFF, .offset = offsetof(hc_cache_t, store),               \
  }

/* Commands */

static const command_parser_t command_cache_set_serve = {
    .action = ACTION_SERVE,
    .object_type = OBJECT_TYPE_CACHE,
    .nparams = 1,
    .parameters = {serve},
};
COMMAND_REGISTER(command_cache_set_serve);

static const command_parser_t command_cache_set_store = {
    .action = ACTION_STORE,
    .object_type = OBJECT_TYPE_CACHE,
    .nparams = 1,
    .parameters = {store},
};
COMMAND_REGISTER(command_cache_set_store);

static const command_parser_t command_cache_clear = {
    .action = ACTION_CLEAR,
    .object_type = OBJECT_TYPE_CACHE,
    .nparams = 0,
};
COMMAND_REGISTER(command_cache_clear);

static const command_parser_t command_cache_list = {
    .action = ACTION_LIST,
    .object_type = OBJECT_TYPE_CACHE,
    .nparams = 0,
};
COMMAND_REGISTER(command_cache_list);
