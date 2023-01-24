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
 * \file command_mapme.h
 * \brief Implementation of mapme command.
 */
#include <math.h>
#include <hicn/ctrl/command.h>

/* Parameters */

#define target                                                                \
  {                                                                           \
    .name = "target",                                                         \
    .help =                                                                   \
        "Target for the set action, e.g. enable, discovery, timescale, retx", \
    .type = TYPE_ENUM(mapme_target), .offset = offsetof(hc_mapme_t, target),  \
  }

#define value                                                              \
  {                                                                        \
    .name = "value",                                                       \
    .help = "Value to set for the target, e.g. 'on', 'off', milliseconds", \
    .type = TYPE_STRN(4), .offset = offsetof(hc_mapme_t, unparsed_arg),    \
  }

#define prefix                                                         \
  {                                                                    \
    .name = "prefix",                                                  \
    .help = "The hicn name as IPv4 or IPv6 address (e.g 1234::0/64).", \
    .type = TYPE_IP_PREFIX, .offset = offsetof(hc_mapme_t, address),   \
    .offset2 = offsetof(hc_mapme_t, len),                              \
    .offset3 = offsetof(hc_mapme_t, family),                           \
  }

/* Commands */

// Parse the raw string argument into 'timescale' or 'enabled',
// necessary since the command dispatch is based on the number
// of arguments and not their type
int parse_args(hc_mapme_t* mapme) {
  mapme->timescale = atoi(mapme->unparsed_arg);

  if (strcasecmp(mapme->unparsed_arg, "off") == 0) mapme->enabled = 0;
  if (strcasecmp(mapme->unparsed_arg, "on") == 0) mapme->enabled = 1;

  return 0;
}

static const command_parser_t command_mapme_set = {
    .action = ACTION_SET,
    .object_type = OBJECT_TYPE_MAPME,
    .nparams = 2,
    .parameters = {target, value},
    .post_hook = (parser_hook_t)parse_args,
};
COMMAND_REGISTER(command_mapme_set);

static const command_parser_t command_mapme_update = {
    .action = ACTION_UPDATE,
    .object_type = OBJECT_TYPE_MAPME,
    .nparams = 1,
    .parameters = {prefix},
};
COMMAND_REGISTER(command_mapme_update);
