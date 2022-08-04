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
 * \file object_type.c
 * \brief Implementation of object type.
 */

#include <strings.h>

#include <hicn/ctrl/object_type.h>

const char *object_type_str[] = {
#define _(x) [OBJECT_TYPE_##x] = #x,
    foreach_object_type
#undef _
};

hc_object_type_t object_type_from_str(const char *object_str) {
#define _(x)                           \
  if (strcasecmp(object_str, #x) == 0) \
    return OBJECT_TYPE_##x;            \
  else
  foreach_object_type
#undef _
      return OBJECT_TYPE_UNDEFINED;
}
