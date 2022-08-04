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
 * \file action.h
 * \brief Actions.
 */

#ifndef HICNCTRL_ACTION_H
#define HICNCTRL_ACTION_H

#define foreach_action \
  _(UNDEFINED)         \
  _(CREATE)            \
  _(UPDATE)            \
  _(DELETE)            \
  _(LIST)              \
  _(GET)               \
  _(SET)               \
  _(SERVE)             \
  _(STORE)             \
  _(CLEAR)             \
  _(SUBSCRIBE)         \
  _(N)

typedef enum {
#define _(x) ACTION_##x,
  foreach_action
#undef _
} hc_action_t;

extern const char *action_str[];

#define action_str(x) action_str[x]

hc_action_t action_from_str(const char *action_str);

#endif /* HICNCTRL_ACTION_H */
