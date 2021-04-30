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
 * @file fibEntryList.h
 * @brief A typesafe list of FibEntry
 *
 * <#Detailed Description#>
 *
 */

#ifndef fibEntryList_h
#define fibEntryList_h

#include <hicn/processor/fibEntry.h>

struct fib_entry_list;
typedef struct fib_entry_list FibEntryList;

/**
 * Creates an emtpy FIB entry list
 *
 * Must be destroyed with fibEntryList_Destroy.
 *
 * @retval non-null An allocated FibEntryList
 * @retval null An error
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
FibEntryList *fibEntryList_Create(void);

/**
 * @function FibEntryList_Detroy
 * @abstract Destroys the list and all entries.
 * @discussion
 *   <#Discussion#>
 *
 * @param <#param1#>
 */
void fibEntryList_Destroy(FibEntryList **listPtr);

/**
 * @function fibEntryList_Append
 * @abstract Will store a reference counted copy of the entry.
 * @discussion
 *   Will create and store a reference counted copy.  You keep ownership
 *   of the parameter <code>fibEntry</code>.
 *
 * @param <#param1#>
 * @return <#return#>
 */
void fibEntryList_Append(FibEntryList *list, FibEntry *fibEntry);

/**
 * Returns the number of entries in the list
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] list An allocated FibEntryList
 *
 * @retval number The number of entries in the list
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
size_t fibEntryList_Length(const FibEntryList *list);

/**
 * @function fibEntryList_Get
 * @abstract Gets an element.  This is the internal reference, do not destroy.
 * @discussion
 *   Returns an internal reference from the list.  You must not destroy it.
 *   Will assert if you go off the end of the list.
 *
 * @param <#param1#>
 * @return <#return#>
 */
const FibEntry *fibEntryList_Get(const FibEntryList *list, size_t index);
#endif  // fibEntryList_h
