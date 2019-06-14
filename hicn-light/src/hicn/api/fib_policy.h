/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
 * \file fib_policy.h
 * \brief FIB policy description to be stored in FIB entries.
 */
#ifndef HICN_FIB_POLICY_H
#define HICN_FIB_POLICY_H

#include <hicn/api/face.h>

typedef struct {
  face_tags_t allow;
  face_tags_t prohibit;
  face_tags_t prefer;
  face_tags_t avoid;
} fib_policy_t;

static const fib_policy_t FIB_POLICY_NONE = {
    .allow = FACE_TAGS_EMPTY,
    .prohibit = FACE_TAGS_EMPTY,
    .prefer = FACE_TAGS_EMPTY,
    .avoid = FACE_TAGS_EMPTY,
};

#endif /* HICN_FIB_POLICY_H */
