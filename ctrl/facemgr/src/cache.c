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
 * \file cache.c
 * \brief Implementation of face cache.
 *
 * The cache is currently implemented as a list so as not to worry about
 * platform-specific implementations (eg missing functions in BSD libC for
 * search.h).
 */

#include <math.h>    // log2
#include <string.h>  // memmove

#include "cache.h"

#define FACE_CACHE_MAX_SIZE_LOG_INIT 0

face_cache_t* face_cache_create() {
  face_cache_t* face_cache = malloc(sizeof(face_cache_t));
  if (!face_cache) goto ERR_MALLOC;

  face_cache->max_size_log = FACE_CACHE_MAX_SIZE_LOG_INIT;
#if (FACE_CACHE_MAX_SIZE_LOG_INIT == 0)
  face_cache->faces = NULL;
#else
  face_cache->faces = malloc((1 << face_cache->max_size_log) * sizeof(face_t*));
  if (!face_cache->faces)
    goto ERR_ARRAY :
#endif
  face_cache->size = 0;

  return face_cache;

#if (FACE_CACHE_MAX_SIZE_LOG_INIT != 0)
ERR_ARRAY:
  free(face_cache);
#endif
ERR_MALLOC:
  return NULL;
}

void face_cache_free(face_cache_t* face_cache) {
  free(face_cache->faces);

  free(face_cache);
}

face_t* face_cache_add(face_cache_t* face_cache, face_t* face) {
  /* Ensure sufficient space for next addition */
  size_t new_size_log = (face_cache->size > 0) ? log2(face_cache->size) + 1 : 0;
  if (new_size_log > face_cache->max_size_log) {
    face_cache->max_size_log = new_size_log;
    face_cache->faces =
        realloc(face_cache->faces, (1 << new_size_log) * sizeof(face_t*));
  }

  if (!face_cache->faces) goto ERR_REALLOC;

  face_cache->faces[face_cache->size++] = face;

  return face;

ERR_REALLOC:
  return NULL;
}

int face_cache_search(face_cache_t* face_cache, face_t* face,
                      face_cmp_t face_cmp) {
  for (int i = 0; i < face_cache->size; i++)
    if (face_cmp(face, face_cache->faces[i])) return i;
  return -1;
}

/* Remove a single occurrence */
face_t* face_cache_remove(face_cache_t* face_cache, face_t* face) {
  int pos = face_cache_search(face_cache, face, face_cmp);
  if (pos < 0) return NULL;

  /* No need to move memory if last item is removed */
  if (pos < face_cache->size)
    memmove(face_cache->faces + pos, face_cache->faces + pos + 1,
            face_cache->size - pos);

  face_cache->size--;

  return face;
}

/* TODO : remove by ... */

face_t* face_cache_get_by_id(face_cache_t* face_cache, int id) { return NULL; }

void face_cache_dump(face_cache_t* face_cache) {}
