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
 * @file connectionList.h
 * @brief A typesafe list of Connection objects
 *
 * <#Detailed Description#>
 *
 */

#ifndef connectionList_h
#define connectionList_h

struct connection_list;
typedef struct connection_list ConnectionList;

#include <hicn/core/connection.h>

/**
 * Creates a lis of Connection
 *
 * @return non-null An allocated list
 * @return null An error
 */
ConnectionList *connectionList_Create(void);

/**
 * Destroys the list and all objects inside it
 */
void connectionList_Destroy(ConnectionList **listPtr);

/**
 * @function connectionList_Append
 * @abstract Adds a connection entry to the list.
 * @discussion
 *   Acquires a reference to the passed entry and stores it in the list.
 */
void connectionList_Append(ConnectionList *list, Connection *entry);

/**
 * Returns the number of items on the list
 * @param [in] list The allocated list to check
 * @return number The number of items on the list
 */
size_t connectionList_Length(const ConnectionList *list);

/**
 * @function connectionList_Get
 * @abstract Returns the connection entry.
 * @discussion
 *   Caller must not destroy the returned value.  If you will store the
 *   entry in your own data structure, you should acquire your own reference.
 *   Will assert if you go beyond the end of the list.
 *
 */
Connection *connectionList_Get(ConnectionList *list, size_t index);
#endif  // connectionList_h
