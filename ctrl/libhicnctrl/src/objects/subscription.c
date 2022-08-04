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
 * \file subscription.c
 * \brief Implementation of subscription.
 */

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/objects/subscription.h>
#include <hicn/util/log.h>

#include "../object_vft.h"
#include "../object_private.h"

/* SUBSCRIPTION VALIDATE */

int hc_subscription_validate(const hc_subscription_t *subscription,
                             bool allow_partial) {
  /* Any topic is considered valid */
  return 0;
}

int _hc_subscription_validate(const hc_object_t *object, bool allow_partial) {
  return hc_subscription_validate(&object->subscription, allow_partial);
}

/* LISTENER CMP */

int hc_subscription_cmp(const hc_subscription_t *l1,
                        const hc_subscription_t *l2) {
  return -1;
}

int _hc_subscription_cmp(const hc_object_t *object1,
                         const hc_object_t *object2) {
  return hc_subscription_cmp(&object1->subscription, &object2->subscription);
}

/* SUBSCRIPTION SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_subscription_snprintf(char *s, size_t size,
                             const hc_subscription_t *subscription) {
  return -1;
}

int _hc_subscription_snprintf(char *s, size_t size, const hc_object_t *object) {
  return hc_subscription_snprintf(s, size, &object->subscription);
}

/* OPERATIONS */

int hc_subscription_create(hc_sock_t *s, hc_subscription_t *subscription) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.subscription = *subscription;
  return hc_execute(s, ACTION_CREATE, OBJECT_TYPE_SUBSCRIPTION, &object, NULL);
}

int hc_subscription_get(hc_sock_t *s, hc_subscription_t *subscription,
                        hc_data_t **pdata) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.subscription = *subscription;
  return hc_execute(s, ACTION_GET, OBJECT_TYPE_SUBSCRIPTION, &object, pdata);
}

int hc_subscription_delete(hc_sock_t *s, hc_subscription_t *subscription) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.subscription = *subscription;
  return hc_execute(s, ACTION_DELETE, OBJECT_TYPE_SUBSCRIPTION, &object, NULL);
}

int hc_subscription_list(hc_sock_t *s, hc_data_t **pdata) {
  return hc_execute(s, ACTION_LIST, OBJECT_TYPE_SUBSCRIPTION, NULL, pdata);
}

GENERATE_FIND(subscription);
DECLARE_OBJECT_OPS(OBJECT_TYPE_SUBSCRIPTION, subscription);
