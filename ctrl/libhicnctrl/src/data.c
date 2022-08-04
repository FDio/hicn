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
 * \file data.c
 * \brief Implementation of request result data.
 */

#include <assert.h>
#include <stdlib.h>

#include <hicn/ctrl/data.h>
#include <hicn/ctrl/object.h>
#include <hicn/util/log.h>

#define MIN_ALLOC_SIZE 8
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

struct hc_data_s {
  hc_object_type_t object_type;
  bool complete;

  /**
   * >=0 success, indicates the number of records in array
   *  <0 error
   */
  ssize_t size;
  size_t alloc_size; /** Allocated size (a power of 2 when managed
                        automatically) */
  size_t max_size;   /** Maximum size defined at creation (0 = unlimited) */

  uint8_t *buffer;
};

void _hc_data_clear(hc_data_t *data) {
  data->complete = false;
  data->buffer = NULL;
  data->max_size = 0;
  data->alloc_size = 0;
  data->size = 0;
}

hc_data_t *hc_data_create(hc_object_type_t object_type) {
  hc_data_t *data = malloc(sizeof(hc_data_t));
  if (!data) return NULL;

  data->object_type = object_type;

  _hc_data_clear(data);

  return data;
  // data->buffer = malloc((1 << data->max_size_log) * data->out_element_size);
  // if (!data->buffer) goto ERR_BUFFER;
}

void hc_data_free(hc_data_t *data) {
  assert(data);

  if (data->buffer) free(data->buffer);
  free(data);
}

int hc_data_set_max_size(hc_data_t *data, size_t max_size) {
  if (data->size > max_size) return -1;
  data->max_size = max_size;
  return 0;
}

const uint8_t *hc_data_get_buffer(hc_data_t *data) { return data->buffer; }

const uint8_t *hc_data_get_free(hc_data_t *data) {
  if (!data) return NULL;
  if (data->max_size > 0 && data->size >= data->max_size) return NULL;
  hc_object_type_t object_type = hc_data_get_object_type(data);
  size_t object_size = hc_object_size(object_type);
  return data->buffer + data->size * object_size;
}

void hc_data_inc_size(hc_data_t *data) { data->size++; }

hc_object_type_t hc_data_get_object_type(const hc_data_t *data) {
  return data->object_type;
}

void hc_data_set_object_type(hc_data_t *data, hc_object_type_t object_type) {
  data->object_type = object_type;
}

ssize_t hc_data_get_size(const hc_data_t *data) { return data->size; }

int hc_data_clear(hc_data_t *data) {
  free(data->buffer);
  _hc_data_clear(data);
  return 0;
}

int _hc_data_allocate(hc_data_t *data, size_t size) {
  data->buffer =
      realloc(data->buffer, size * hc_object_size(data->object_type));
  if (!data->buffer) goto ERR;
  data->alloc_size = size;
  return 0;
ERR:
  data->alloc_size = 0;
  return -1;
}

int hc_data_allocate(hc_data_t *data, size_t size) {
  /* Do not allocate twice */
  if (data->buffer) return -1;
  if (data->max_size > 0 && size > data->max_size) return -1;
  return _hc_data_allocate(data, size);
}

int hc_data_ensure_available(hc_data_t *data, size_t count) {
  size_t new_size = data->size + count;
  if (new_size < data->alloc_size) return 0;
  if (data->max_size > 0 && new_size > data->max_size) return -1;

  size_t new_alloc_size = MAX(MIN_ALLOC_SIZE, next_pow2(new_size));
  if (data->max_size > 0 && new_alloc_size > data->max_size)
    new_alloc_size = data->max_size;

  return _hc_data_allocate(data, new_alloc_size);
}

int hc_data_push_many(hc_data_t *data, const void *elements, size_t count) {
  if (!data) return -1;
  if (!elements) return -1;
  if (count < 1) return -1;

  if (hc_data_ensure_available(data, count) < 0) return -1;

  hc_object_type_t object_type = hc_data_get_object_type(data);
  size_t object_size = hc_object_size(object_type);

  uint8_t *dst = data->buffer + data->size * object_size;
  memcpy(dst, elements, count * object_size);
  data->size += count;

  return 0;
}

int hc_data_push(hc_data_t *data, const void *element) {
  return hc_data_push_many(data, element, 1);
}
#if 0
/**
 *
 * NOTE: This function make sure there is enough room available in the data
 * structure.
 */
u8 *hc_data_get_next(hc_data_t *data) {
  if (hc_data_ensure_available(data, 1) < 0) return NULL;

  return data->buffer + data->size * data->out_element_size;
}

int hc_data_set_callback(hc_data_t *data, data_callback_t cb, void *cb_data) {
  data->complete_cb = cb;
  data->complete_cb_data = cb_data;
  return 0;
}
#endif

void hc_data_set_complete(hc_data_t *data) { data->complete = true; }

bool hc_data_is_complete(const hc_data_t *data) { return data->complete; }

void hc_data_set_error(hc_data_t *data) {
  data->size = -1;
  data->complete = true;
}

bool hc_data_get_result(hc_data_t *data) { return (data->size >= 0); }

hc_object_t *hc_data_find(hc_data_t *data, hc_object_t *object) {
  hc_object_type_t object_type = hc_data_get_object_type(data);
  hc_data_foreach(data, found, {
    if (hc_object_cmp(object_type, object, found) == 0) return found;
  });
  return NULL;
}

const hc_object_t *hc_data_get_object(const hc_data_t *data, off_t pos) {
  size_t size = hc_data_get_size(data);
  if (pos >= size) return NULL;

  hc_object_type_t object_type = hc_data_get_object_type(data);
  size_t object_size = hc_object_size(object_type);

  return (const hc_object_t *)(data->buffer + pos * object_size);
}

#if 0
int hc_data_reset(hc_data_t *data) {
  data->size = 0;
  return 0;
}
#endif
