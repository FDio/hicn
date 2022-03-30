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
 * \file state.h
 * \brief Face cache
 *
 * The face cache is an index array of faces that mirror the current state of
 * the forwarder in order to filter out redundant events, and perform set
 * reconciliation.
 */
#ifndef FACEMGR_CACHE_H
#define FACEMGR_CACHE_H

#include <stdlib.h>

#include "face.h"

/**
 * \brief Face cache
 */
typedef struct {
  face_t** faces;      /**< array of _pointers_ to faces */
  size_t max_size_log; /**< log2 of allocated size */
  size_t size;         /**< effective array size */
} face_cache_t;

face_cache_t* face_cache_create();
void face_cache_free(face_cache_t* face_cache);

/* a la VPP vector, we never create a face outside of the vector */
/* problem is that face ptr can get invalid if we manipulate the vector */
face_t* face_cache_get(face_cache_t* cache_cache);

face_t* face_cache_add(face_cache_t* face_cache, face_t* face);
face_t* face_cache_remove(face_cache_t* face_cache, face_t* face);
face_t* face_cache_get_by_id(face_cache_t* face_cache, int id);

void face_cache_dump(face_cache_t* face_cache);

#endif /* FACEMGR_CACHE_H */
