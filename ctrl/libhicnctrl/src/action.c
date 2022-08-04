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
 * \file action.c
 * \brief Implementation of actions.
 */

#include <strings.h>

#include <hicn/ctrl/action.h>

const char *action_str[] = {
#define _(x) [ACTION_##x] = #x,
    foreach_action
#undef _
};

hc_action_t action_from_str(const char *action_str) {
#define _(x)                           \
  if (strcasecmp(action_str, #x) == 0) \
    return ACTION_##x;                 \
  else
  foreach_action
#undef _
      if (strcasecmp(action_str, "add") == 0) return ACTION_CREATE;
  else if (strcasecmp(action_str, "remove") == 0) return ACTION_DELETE;
  else return ACTION_UNDEFINED;
}
