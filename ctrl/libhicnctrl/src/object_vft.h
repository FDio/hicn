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
 * \file object_vft.h
 * \brief Object VFT.
 */

#ifndef HICNCTRL_OBJECT_VFT
#define HICNCTRL_OBJECT_VFT

#include <stddef.h>  // size_t
#include <hicn/ctrl/object_type.h>
#include <hicn/ctrl/object.h>

typedef struct {
  hc_object_type_t object_type;
  const char *object_name;
  size_t size;
  int (*validate)(const hc_object_t *object, bool allow_partial);
  int (*cmp)(const hc_object_t *object1, const hc_object_t *object2);
  /* cannot be named snprintf as it collides with a macro in clang/iOS */
  int (*obj_snprintf)(char *s, size_t size, const hc_object_t *object);
} hc_object_ops_t;

#define DECLARE_OBJECT_OPS_H(TYPE, NAME) \
  extern const hc_object_ops_t hc_##NAME##_ops;

#define DECLARE_OBJECT_OPS(TYPE, NAME)       \
  const hc_object_ops_t hc_##NAME##_ops = {  \
      .object_type = TYPE,                   \
      .object_name = #NAME,                  \
      .size = sizeof(hc_##NAME##_t),         \
      .validate = _hc_##NAME##_validate,     \
      .cmp = _hc_##NAME##_cmp,               \
      .obj_snprintf = _hc_##NAME##_snprintf, \
  };

extern const hc_object_ops_t *object_vft[];

#endif /* HICNCTRL_OBJECT_VFT */
