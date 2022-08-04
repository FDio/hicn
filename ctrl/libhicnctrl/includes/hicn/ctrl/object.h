/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 * \file object.h
 * \brief API object representation.
 */

#ifndef HICNCTRL_OBJECT_H
#define HICNCTRL_OBJECT_H

#include <hicn/ctrl/object_type.h>

#include <hicn/ctrl/objects/listener.h>
#include <hicn/ctrl/objects/connection.h>
#include <hicn/ctrl/objects/route.h>
#include <hicn/ctrl/objects/punting.h>
#include <hicn/ctrl/objects/strategy.h>
#include <hicn/ctrl/objects/policy.h>
#include <hicn/ctrl/objects/subscription.h>
#include <hicn/ctrl/objects/cache.h>
#include <hicn/ctrl/objects/mapme.h>
#include <hicn/ctrl/objects/active_interface.h>

typedef union {
  hc_connection_t connection;
  hc_listener_t listener;
  hc_route_t route;
  hc_face_t face;
  // hc_data_t *data;
  hc_punting_t punting;
  hc_strategy_t strategy;
  hc_policy_t policy;
  hc_subscription_t subscription;
  hc_cache_t cache;
  hc_mapme_t mapme;
  hc_active_interface_t active_interface;
  uint8_t as_uint8;
} hc_object_t;

#define MAXSZ_OBJECT_T MAX

#define IS_VALID_ACTION(x) IS_VALID_ENUM_TYPE(ACTION, x)

bool hc_object_is_empty(const hc_object_t *object);

size_t hc_object_size(hc_object_type_t object_type);

int hc_object_validate(hc_object_type_t object_type, hc_object_t *object,
                       bool allow_partial);
int hc_object_cmp(hc_object_type_t object_type, hc_object_t *object1,
                  hc_object_t *object2);
int hc_object_snprintf(char *s, size_t size, hc_object_type_t object_type,
                       hc_object_t *object);

#define foreach_object(VAR, data) foreach_type(hc_object_t, VAR, data)

#define foreach_type(TYPE, VAR, DATA)                         \
  for (TYPE *VAR = (TYPE *)hc_data_get_buffer(DATA);          \
       VAR < (TYPE *)(hc_data_get_buffer(DATA) +              \
                      hc_data_get_size(DATA) * sizeof(TYPE)); \
       VAR++)

#endif /* HICNCTRL_OBJECT_H */
