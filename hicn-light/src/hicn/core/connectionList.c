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

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_Memory.h>

#include <parc/assert/parc_Assert.h>
#include <hicn/core/connectionList.h>

struct connection_list {
  PARCArrayList *listOfConnections;
};

static void connectionList_ArrayDestroyer(void **voidPtr) {
  Connection **entryPtr = (Connection **)voidPtr;
  connection_Release(entryPtr);
}

ConnectionList *connectionList_Create() {
  ConnectionList *list = parcMemory_AllocateAndClear(sizeof(ConnectionList));
  parcAssertNotNull(list, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ConnectionList));
  list->listOfConnections = parcArrayList_Create(connectionList_ArrayDestroyer);
  return list;
}

void connectionList_Destroy(ConnectionList **listPtr) {
  parcAssertNotNull(listPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*listPtr, "Parameter must dereference to non-null pointer");
  ConnectionList *list = *listPtr;
  parcArrayList_Destroy(&list->listOfConnections);
  parcMemory_Deallocate((void **)&list);
  *listPtr = NULL;
}

void connectionList_Append(ConnectionList *list, Connection *entry) {
  parcAssertNotNull(list, "Parameter list must be non-null");
  parcAssertNotNull(entry, "Parameter entry must be non-null");

  parcArrayList_Add(list->listOfConnections, connection_Acquire(entry));
}

size_t connectionList_Length(const ConnectionList *list) {
  parcAssertNotNull(list, "Parameter list must be non-null");
  return parcArrayList_Size(list->listOfConnections);
}

Connection *connectionList_Get(ConnectionList *list, size_t index) {
  parcAssertNotNull(list, "Parameter list must be non-null");
  Connection *original =
      (Connection *)parcArrayList_Get(list->listOfConnections, index);
  return original;
}
