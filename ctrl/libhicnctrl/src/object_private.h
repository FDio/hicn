/*
 * Copyright (c) 2021-2023 Cisco and/or its affiliates.
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
 * \file object_private.h
 * \brief Helper functions for object management.
 */

#ifndef HICNCTRL_OBJECT_PRIVATE_H
#define HICNCTRL_OBJECT_PRIVATE_H

#include <hicn/face.h>

#define INT_CMP(x, y) ((x > y) ? 1 : (x < y) ? -1 : 0)

// XXX Those are always true
#define IS_VALID_ADDRESS(x) (1)
#define IS_VALID_CONNECTION_ID(x) (x != INVALID_FACE_ID)
#define IS_VALID_ROUTE_COST(x) (1)
#define IS_VALID_PREFIX_LEN(x) (1)
#define IS_VALID_POLICY(x) (1)
#define IS_VALID_ID(x) (1)
#define IS_VALID_INTERFACE_NAME(x) (1)
#define IS_VALID_NAME(x) (1)
#define IS_VALID_TYPE(x) IS_VALID_ENUM_TYPE(FACE_TYPE, x)
#define IS_VALID_FACE_STATE(x) (1)

#define IS_VALID_ADDR_TYPE(x) ((x >= ADDR_INET) && (x <= ADDR_UNIX))

#define IS_VALID_CONNECTION_TYPE(x) IS_VALID_ENUM_TYPE(CONNECTION_TYPE, x)

#define GENERATE_FIND(TYPE)                                           \
  int hc_##TYPE##_find(hc_data_t *data, const hc_##TYPE##_t *element, \
                       hc_##TYPE##_t **found) {                       \
    foreach_type(hc_##TYPE##_t, x, data) {                            \
      if (hc_##TYPE##_cmp(x, element) == 0) {                         \
        *found = x;                                                   \
        return 0;                                                     \
      }                                                               \
    };                                                                \
    *found = NULL; /* this is optional */                             \
    return 0;                                                         \
  }

#endif /* HICNCTRL_OBJECT_PRIVATE_H */
