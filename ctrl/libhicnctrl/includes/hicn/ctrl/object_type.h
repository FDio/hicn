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
 * \file object_type.h
 * \brief Object type.
 */

#ifndef HICNCTRL_OBJECT_TYPE_H
#define HICNCTRL_OBJECT_TYPE_H

#define foreach_object_type \
  _(UNDEFINED)              \
  _(CONNECTION)             \
  _(LISTENER)               \
  _(ROUTE)                  \
  _(FACE)                   \
  _(STRATEGY)               \
  _(PUNTING)                \
  _(POLICY)                 \
  _(CACHE)                  \
  _(MAPME)                  \
  _(WLDR)                   \
  _(LOCAL_PREFIX)           \
  _(PROBE)                  \
  _(SUBSCRIPTION)           \
  _(ACTIVE_INTERFACE)       \
  _(STATS)                  \
  _(N)

typedef enum {
#define _(x) OBJECT_TYPE_##x,
  foreach_object_type
#undef _
} hc_object_type_t;

extern const char *object_type_str[];

#define object_type_str(x) object_type_str[x]

hc_object_type_t object_type_from_str(const char *object_str);

#define IS_VALID_OBJECT_TYPE(x) IS_VALID_ENUM_TYPE(OBJECT_TYPE, x)

#endif /* HICNCTRL_OBJECT_TYPE_H */
