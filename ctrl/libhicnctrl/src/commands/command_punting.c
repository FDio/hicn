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
 * \file command_punting.h
 * \brief Implementation of punting command.
 */

#if 0
#include <hicn/ctrl/command.h>

/* Parameters */

#define symbolic_or_id                                                      \
  {                                                                         \
    .name = "symbolic_or_id",                                               \
    .help =                                                                 \
        "The symbolic name for an egress, or the egress punting id (see "   \
        "'help list puntings')",                                            \
    .type = TYPE_SYMBOLIC_OR_ID, .offset = offsetof(hc_punting_t, face_id), \
  }

#define prefix                                                        \
  {                                                                   \
    .name = "prefix",                                                 \
    .help = "Prefix to add as a punting rule. (example 1234::0/64)",  \
    .type = TYPE_IP_PREFIX, .offset = offsetof(hc_punting_t, prefix), \
    .offset2 = offsetof(hc_punting_t, prefix_len),                    \
    .offset3 = offsetof(hc_punting_t, family),                        \
  }

/* Commands */

static const command_parser_t command_punting_create = {
    .action = ACTION_CREATE,
    .object = OBJECT_PUNTING,
    .nparams = 2,
    .parameters = {symbolic_or_id, prefix},
};
COMMAND_REGISTER(command_punting_create);

static const command_parser_t command_punting_list = {
    .action = ACTION_LIST,
    .object = OBJECT_PUNTING,
    .nparams = 0,
};
COMMAND_REGISTER(command_punting_list);
#endif
