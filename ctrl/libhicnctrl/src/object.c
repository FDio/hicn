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
 * \file object.c
 * \brief Implementation of API object representation.
 */

#include <hicn/ctrl/action.h>
#include <hicn/ctrl/object.h>

#include "objects/base.h"  // iszero
#include "object_vft.h"

bool hc_object_is_empty(const hc_object_t *object) {
  return iszero(object, sizeof(hc_object_t));
}

int hc_object_validate(hc_object_type_t object_type, hc_object_t *object,
                       bool allow_partial) {
  const hc_object_ops_t *vft = object_vft[object_type];
  if (!vft) return -1;
  return vft->validate(object, allow_partial);
}

int hc_object_cmp(hc_object_type_t object_type, hc_object_t *object1,
                  hc_object_t *object2) {
  const hc_object_ops_t *vft = object_vft[object_type];
  if (!vft) return -1;
  return vft->cmp(object1, object2);
}

int hc_object_snprintf(char *s, size_t size, hc_object_type_t object_type,
                       hc_object_t *object) {
  const hc_object_ops_t *vft = object_vft[object_type];
  if (!vft) return -1;
  return vft->obj_snprintf(s, size, object);
}

size_t hc_object_size(hc_object_type_t object_type) {
  const hc_object_ops_t *vft = object_vft[object_type];
  if (!vft) return -1;
  return vft->size;
}
