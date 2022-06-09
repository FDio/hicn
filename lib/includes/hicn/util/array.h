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
 * \file array.h
 * \brief Generic array template
 */

#ifndef UTIL_ARRAY_H
#define UTIL_ARRAY_H

#include <assert.h>
#include <hicn/util/log.h>
#include <math.h>   // log2
#include <string.h> // memmove

#define BUFSIZE 1024

#define TYPEDEF_ARRAY_H(NAME, T)                                              \
                                                                              \
  typedef struct                                                              \
  {                                                                           \
    size_t size;                                                              \
    size_t max_size_log;                                                      \
    T *elements;                                                              \
  } NAME##_t;                                                                 \
                                                                              \
  int NAME##_initialize (NAME##_t *array);                                    \
                                                                              \
  int NAME##_finalize (NAME##_t *array);                                      \
                                                                              \
  NAME##_t *NAME##_create ();                                                 \
                                                                              \
  void NAME##_free (NAME##_t *array);                                         \
                                                                              \
  int NAME##_add (NAME##_t *array, T element);                                \
                                                                              \
  int NAME##_remove_index (NAME##_t *array, int index, T *element);           \
                                                                              \
  int NAME##_remove (NAME##_t *array, const T search, T *element);            \
                                                                              \
  int NAME##_get (const NAME##_t *array, const T search, T *element);         \
                                                                              \
  int NAME##_get_index (const NAME##_t *array, int index, T *element);        \
                                                                              \
  int NAME##_get_elements (const NAME##_t *array, T **elements);              \
                                                                              \
  size_t NAME##_len (const NAME##_t *array);

#define ARRAY_MAX_SIZE_LOG_INIT 0

#define TYPEDEF_ARRAY(NAME, T, CMP, SNPRINTF)                                 \
  int NAME##_initialize (NAME##_t *array)                                     \
  {                                                                           \
    array->max_size_log = ARRAY_MAX_SIZE_LOG_INIT;                            \
    array->size = 0;                                                          \
    if (array->max_size_log == 0)                                             \
      {                                                                       \
	array->elements = NULL;                                               \
	return 0;                                                             \
      }                                                                       \
    array->elements = malloc ((1 << array->max_size_log) * sizeof (T));       \
    if (!array->elements)                                                     \
      return -1;                                                              \
    return 0;                                                                 \
  }                                                                           \
                                                                              \
  int NAME##_finalize (NAME##_t *array)                                       \
  {                                                                           \
    for (unsigned i = 0; i < array->size; i++)                                \
      {                                                                       \
	NAME##_remove_index (array, i, NULL);                                 \
      }                                                                       \
    return 0;                                                                 \
  }                                                                           \
                                                                              \
  NAME##_t *NAME##_create ()                                                  \
  {                                                                           \
    NAME##_t *array = malloc (sizeof (NAME##_t));                             \
    if (!array)                                                               \
      goto ERR_MALLOC;                                                        \
                                                                              \
    if (NAME##_initialize (array) < 0)                                        \
      goto ERR_INITIALIZE;                                                    \
                                                                              \
    return array;                                                             \
                                                                              \
  ERR_INITIALIZE:                                                             \
    free (array);                                                             \
  ERR_MALLOC:                                                                 \
    return NULL;                                                              \
  }                                                                           \
                                                                              \
  void NAME##_free (NAME##_t *array)                                          \
  {                                                                           \
    NAME##_finalize (array);                                                  \
    free (array->elements);                                                   \
    free (array);                                                             \
  }                                                                           \
                                                                              \
  int NAME##_add (NAME##_t *array, T element)                                 \
  {                                                                           \
    /* Ensure sufficient space for next addition */                           \
    size_t new_size_log = (array->size > 0) ? log2 (array->size) + 1 : 1;     \
    if (new_size_log > array->max_size_log)                                   \
      {                                                                       \
	array->max_size_log = new_size_log;                                   \
	array->elements =                                                     \
	  realloc (array->elements, (1 << new_size_log) * sizeof (T));        \
      }                                                                       \
                                                                              \
    if (!array->elements)                                                     \
      goto ERR_REALLOC;                                                       \
                                                                              \
    array->elements[array->size++] = element;                                 \
    return 0;                                                                 \
                                                                              \
  ERR_REALLOC:                                                                \
    return -1;                                                                \
  }                                                                           \
                                                                              \
  int NAME##_remove_index (NAME##_t *array, int index, T *element)            \
  {                                                                           \
    if (index > NAME##_len (array))                                           \
      return -1;                                                              \
    if (element)                                                              \
      *element = array->elements[index];                                      \
    if (index < array->size)                                                  \
      memmove (array->elements + index, array->elements + index + 1,          \
	       array->size - index);                                          \
    array->size--;                                                            \
    return 0;                                                                 \
  }                                                                           \
                                                                              \
  int NAME##_remove (NAME##_t *array, const T search, T *element)             \
  {                                                                           \
    for (unsigned i = 0; i < array->size; i++)                                \
      {                                                                       \
	if (CMP (search, array->elements[i]) == 0)                            \
	  return NAME##_remove_index (array, i, element);                     \
      }                                                                       \
    /* Not found */                                                           \
    if (element)                                                              \
      *element = NULL;                                                        \
    return 0;                                                                 \
  }                                                                           \
                                                                              \
  int NAME##_get (const NAME##_t *array, const T search, T *element)          \
  {                                                                           \
    assert (element);                                                         \
    for (unsigned i = 0; i < array->size; i++)                                \
      if (CMP (search, array->elements[i]) == 0)                              \
	{                                                                     \
	  *element = array->elements[i];                                      \
	  return 0;                                                           \
	}                                                                     \
    /* Not found */                                                           \
    *element = NULL;                                                          \
    return 0;                                                                 \
  }                                                                           \
                                                                              \
  int NAME##_get_index (const NAME##_t *array, int index, T *element)         \
  {                                                                           \
    assert (element);                                                         \
    *element = array->elements[index];                                        \
    return 0;                                                                 \
  }                                                                           \
                                                                              \
  int NAME##_get_elements (const NAME##_t *array, T **elements)               \
  {                                                                           \
    *elements = array->elements;                                              \
    return 0;                                                                 \
  }                                                                           \
                                                                              \
  size_t NAME##_len (const NAME##_t *array) { return array->size; }

#endif /* UTIL_ARRAY_H */
