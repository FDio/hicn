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
 * \file command_policy.h
 * \brief Implementation of policy command.
 */

#if 0
#include <hicn/policy.h>

#include <hicn/ctrl/command.h>

/* Parameters */

#define prefix                                                            \
  {                                                                       \
    .name = "prefix",                                                     \
    .help = "The hicn name as IPv4 or IPv6 address (e.g 1234::0/64).",    \
    .type = TYPE_IP_PREFIX, .offset = offsetof(hc_policy_t, remote_addr), \
    .offset2 = offsetof(hc_policy_t, len),                                \
    .offset3 = offsetof(hc_policy_t, family),                             \
  }

#define app_name                                                        \
  {                                                                     \
    .name = "app_name",                                                 \
    .help = "The application name associated to this policy",           \
    .type = TYPE_STR, .offset = offsetof(hc_policy_t, policy.app_name), \
  }

/* Commands */

static const command_parser_t command_policy_create = {
    .action = ACTION_CREATE,
    .object = OBJECT_POLICY,
    .nparams = 2 + POLICY_TAG_N,
    .parameters = {prefix, app_name,
#define _(x, y)                                                            \
  {                                                                        \
      .name = "flag:" #x,                                                  \
      .help =                                                              \
          "A value among [neutral|require|prefer|avoid|prohibit] with an " \
          "optional '!' character prefix for disabling changes",           \
      .type = TYPE_POLICY_STATE(POLICY_TAG_##x),                           \
      .offset = offsetof(hc_policy_t, policy.tags),                        \
  },
                   foreach_policy_tag
#undef _
    },
};
COMMAND_REGISTER(command_policy_create);

static const command_parser_t command_policy_list = {
    .action = ACTION_LIST,
    .object = OBJECT_POLICY,
    .nparams = 0,
};
COMMAND_REGISTER(command_policy_list);
#endif
