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
 * @file fib_entry_list.h
 * @brief A typesafe list of fib_entry_t
 *
 * <#Detailed Description#>
 *
 */

#ifndef fib_entry_list_h
#define fib_entry_list_h

#include <hicn/processor/fib_entry.h>

struct fib_entry_list;
typedef struct fib_entry_list fib_entry_list_t;

/**
 * Creates an emtpy FIB entry list
 *
 * Must be destroyed with fib_entry_list_Destroy.
 *
 * @retval non-null An allocated fib_entry_list_t
 * @retval null An error
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
fib_entry_list_t *fib_entry_list_Create(void);

/**
 * @function fib_entry_list_t_Detroy
 * @abstract Destroys the list and all entries.
 * @discussion
 *   <#Discussion#>
 *
 * @param <#param1#>
 */
void fib_entry_list_Destroy(fib_entry_list_t **listPtr);

/**
 * @function fib_entry_list_Append
 * @abstract Will store a reference counted copy of the entry.
 * @discussion
 *   Will create and store a reference counted copy.  You keep ownership
 *   of the parameter <code>fib_entry</code>.
 *
 * @param <#param1#>
 * @return <#return#>
 */
void fib_entry_list_Append(fib_entry_list_t *list, fib_entry_t *fib_entry);

/**
 * Returns the number of entries in the list
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] list An allocated fib_entry_list_t
 *
 * @retval number The number of entries in the list
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
size_t fib_entry_list_Length(const fib_entry_list_t *list);

/**
 * @function fib_entry_list_Get
 * @abstract Gets an element.  This is the internal reference, do not destroy.
 * @discussion
 *   Returns an internal reference from the list.  You must not destroy it.
 *   Will assert if you go off the end of the list.
 *
 * @param <#param1#>
 * @return <#return#>
 */
const fib_entry_t *fib_entry_list_Get(const fib_entry_list_t *list, size_t index);
#endif  // fib_entry_list_h
