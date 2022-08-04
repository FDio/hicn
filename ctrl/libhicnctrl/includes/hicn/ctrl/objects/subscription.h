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
 * \file objects/subscription.h
 * \brief Subscription.
 */

#ifndef HICNCTRL_OBJECTS_SUBSCRIPTION_H
#define HICNCTRL_OBJECTS_SUBSCRIPTION_H

#include <limits.h>
#include <stddef.h>
#include <hicn/ctrl/object_type.h>

#undef PUNTING  // TODO(eloparco): Undefined to avoid collisions
                // Fix the collision

// Used only to create 'hc_topic_t'
typedef struct {
#define _(x) char x;
  foreach_object_type
#undef _
} object_offset_t;

// Flags for topic subscriptions
typedef enum {
#define _(x) TOPIC_##x = (1 << offsetof(object_offset_t, x)),
  foreach_object_type
#undef _
      TOPIC_ALL = INT_MAX,
} hc_topic_t;

static inline hc_object_type_t object_from_topic(hc_topic_t topic) {
#define _(x) \
  if (topic == TOPIC_##x) return OBJECT_TYPE_##x;
  foreach_object_type
#undef _
      return OBJECT_TYPE_UNDEFINED;
}

static inline hc_topic_t topic_from_object_type(hc_object_type_t object_type) {
  if (object_type == OBJECT_TYPE_UNDEFINED) return TOPIC_ALL;
#define _(x) \
  if (object_type == OBJECT_TYPE_##x) return TOPIC_##x;
  foreach_object_type
#undef _
      return TOPIC_UNDEFINED;
}

#define NUM_TOPICS OBJECT_TYPE_N  // Because a topic is created for each object
#define ALL_TOPICS ~0

// Subscriptions
typedef uint32_t hc_topics_t;
typedef struct {
  hc_topics_t topics;
} hc_subscription_t;

#if 0
typedef struct {
  netdevice_type_t interface_type;
} hc_event_interface_update_t;

typedef struct {
  ip_prefix_t prefix;
  netdevice_type_t interface_type;
} hc_event_active_interface_update_t;
#endif

#endif /* HICNCTRL_OBJECTS_SUBSCRIPTION_H */
