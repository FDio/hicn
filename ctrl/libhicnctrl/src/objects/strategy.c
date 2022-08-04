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
 * \file strategy.c
 * \brief Implementation of strategy.
 */

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/objects/strategy.h>
#include <hicn/util/log.h>

#include "../object_vft.h"
#include "../object_private.h"

/* STREATEGY VALIDATE */

int hc_strategy_validate(const hc_strategy_t *strategy, bool allow_partial) {
  // TODO verify name
  return 0;
}

int _hc_strategy_validate(const hc_object_t *object, bool allow_partial) {
  return hc_strategy_validate(&object->strategy, allow_partial);
}

/* STRATEGY CMP */

int hc_strategy_cmp(const hc_strategy_t *s1, const hc_strategy_t *s2) {
  return strcmp(s1->name, s2->name);
}

int _hc_strategy_cmp(const hc_object_t *object1, const hc_object_t *object2) {
  return hc_strategy_cmp(&object1->strategy, &object2->strategy);
}

/* STRATEGY SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_strategy_snprintf(char *s, size_t size, const hc_strategy_t *strategy) {
  return snprintf(s, size, "%s", strategy->name);
}

int _hc_strategy_snprintf(char *s, size_t size, const hc_object_t *object) {
  return hc_strategy_snprintf(s, size, &object->strategy);
}

/* OPERATIONS */

int hc_strategy_create(hc_sock_t *s, hc_strategy_t *strategy) { return -1; }

int hc_strategy_get(hc_sock_t *s, hc_strategy_t *strategy, hc_data_t **pdata) {
  return -1;
}

int hc_strategy_delete(hc_sock_t *s, hc_strategy_t *strategy) { return -1; }

int hc_strategy_list(hc_sock_t *s, hc_data_t **pdata) {
  return hc_execute(s, ACTION_LIST, OBJECT_TYPE_STRATEGY, NULL, pdata);
}

/* new api */

int hc_strategy_set(hc_sock_t *s, hc_strategy_t *strategy) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.strategy = *strategy;
  return hc_execute(s, ACTION_SET, OBJECT_TYPE_STRATEGY, &object, NULL);
}

#if 0
int hc_strategy_add_local_prefix(hc_sock_t *s, hc_strategy_t *strategy) {
  return s->hc_strategy_add_local_prefix(s, strategy);
}
#endif

GENERATE_FIND(strategy);

DECLARE_OBJECT_OPS(OBJECT_TYPE_STRATEGY, strategy);
