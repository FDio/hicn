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
 * \file data.h
 * \brief Request result data.
 */

#ifndef HICNCTRL_DATA_H
#define HICNCTRL_DATA_H

#include <stdbool.h>
#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t
#include <sys/types.h>
#include <unistd.h>

#include <hicn/ctrl/object_type.h>
#include <hicn/ctrl/object.h>

/**
 * \brief Holds the results of an hICN control request
 */
typedef struct hc_data_s hc_data_t;

/**
 * Create a structure holding the results of an hICN control request.
 * \result The newly create data structure.
 */
hc_data_t *hc_data_create(hc_object_type_t object_type);

/**
 * Free a structure holding the results of an hICN control request.
 * \param [in] data - The data structure to free.
 */
void hc_data_free(hc_data_t *data);

/*
 * This function can fail if the current data size is bigger than the requested
 * maximum size
 */
int hc_data_set_max_size(hc_data_t *data, size_t max_size);

const uint8_t *hc_data_get_buffer(hc_data_t *data);
const uint8_t *hc_data_get_free(hc_data_t *data);
void hc_data_inc_size(hc_data_t *data);

hc_object_type_t hc_data_get_object_type(const hc_data_t *data);

void hc_data_set_object_type(hc_data_t *data, hc_object_type_t object_type);

ssize_t hc_data_get_size(const hc_data_t *data);

/*
 * This is used to perform manual allocation once after initialization is the
 * size of the data to store is known in advance. This does not prevent future
 * reallocations (in the limit though of the value in max_size, if applicable).
 */
int hc_data_allocate(hc_data_t *data, size_t size);

int hc_data_clear(hc_data_t *data);

#if 0
int hc_data_ensure_available(hc_data_t *data, size_t count);
#endif

/**
 * \brief Adds many new results at the end of the data structure, eventually
 * allocating buffer space for it.
 * \param [in] data - The data structure to which to add elements.
 * \param [in] elements - The array of elements to add.
 * \param [in] count - The number of elements to add.
 * \return Error code
 *
 * NOTE: The size of the element should match the one declared at structure
 * initialization.
 */
int hc_data_push_many(hc_data_t *data, const void *elements, size_t count);

/**
 * \brief Adds a new result at the end of the data structure, eventually
 * allocating buffer space for it.
 * \param [in] data - The data structure to which to add an element.
 * \param [in] element - The element to add
 * \return Error code
 *
 * NOTE: The size of the element should match the one declared at structure
 * initialization.
 */
int hc_data_push(hc_data_t *data, const void *element);

#if 0
uint8_t *hc_data_get_next(hc_data_t *data);

/**
 * \brief Configure a callback (along with private data) to be called upon
 * completion of a request
 * \param [in] data - hICN control data
 * \param [in] cb - Callback function
 * \param [in] cb_data - Callback private data
 */
int hc_data_set_callback(hc_data_t *data, data_callback_t cb, void *cb_data);

void hc_data_set_size(hc_data_t *data, int size);
#endif

void hc_data_set_complete(hc_data_t *data);
bool hc_data_is_complete(const hc_data_t *data);

void hc_data_set_error(hc_data_t *data);

bool hc_data_get_result(hc_data_t *data);

#if 0
/**
 * \brief Reset the data structure holding control data
 * \param [in] data - hICN control data
 * \return Error code
 */
int hc_data_reset(hc_data_t *data);
#endif

#define VAR(x) __##x
#define hc_data_foreach(DATA, OBJECT, BODY)                                    \
  do {                                                                         \
    hc_object_t *OBJECT;                                                       \
    size_t VAR(size) = hc_object_size(hc_data_get_object_type(DATA));          \
    for (unsigned VAR(i) = 0; VAR(i) < hc_data_get_size(DATA); VAR(i)++) {     \
      OBJECT = (hc_object_t *)(hc_data_get_buffer(DATA) + VAR(i) * VAR(size)); \
      BODY                                                                     \
    }                                                                          \
  } while (0)

hc_object_t *hc_data_find(hc_data_t *data, hc_object_t *object);

const hc_object_t *hc_data_get_object(const hc_data_t *data, off_t pos);

#endif /* HICNCTRL_DATA_H */
