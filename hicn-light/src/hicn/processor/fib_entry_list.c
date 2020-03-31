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
#include <stdlib.h>

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/processor/fib_entry_list.h>

struct fib_entry_list {
  PARCArrayList *listOfFibEntries;
};

static void fib_entry_list_ListDestroyer(void **voidPtr) {
  fib_entry_t **entryPtr = (fib_entry_t **)voidPtr;
  fib_entry_Release(entryPtr);
}

fib_entry_list_t *fib_entry_list_Create() {
  fib_entry_list_t *fib_entry_list =
      parcMemory_AllocateAndClear(sizeof(fib_entry_list_t));
  parcAssertNotNull(fib_entry_list,
                    "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(fib_entry_list_t));
  fib_entry_list->listOfFibEntries =
      parcArrayList_Create(fib_entry_list_ListDestroyer);
  return fib_entry_list;
}

void fib_entry_list_Destroy(fib_entry_list_t **listPtr) {
  parcAssertNotNull(listPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*listPtr, "Parameter must dereference to non-null pointer");

  fib_entry_list_t *list = *listPtr;
  parcArrayList_Destroy(&list->listOfFibEntries);
  parcMemory_Deallocate((void **)&list);
  listPtr = NULL;
}

void fib_entry_list_Append(fib_entry_list_t *list, fib_entry_t *fib_entry) {
  parcAssertNotNull(list, "Parameter list must be non-null pointer");
  parcAssertNotNull(fib_entry, "Parameter fib_entry must be non-null pointer");

  fib_entry_t *copy = fib_entry_Acquire(fib_entry);
  parcArrayList_Add(list->listOfFibEntries, copy);
}

size_t fib_entry_list_Length(const fib_entry_list_t *list) {
  parcAssertNotNull(list, "Parameter list must be non-null pointer");
  return parcArrayList_Size(list->listOfFibEntries);
}

const fib_entry_t *fib_entry_list_Get(const fib_entry_list_t *list, size_t index) {
  parcAssertNotNull(list, "Parameter list must be non-null pointer");
  fib_entry_t *entry = parcArrayList_Get(list->listOfFibEntries, index);
  return entry;
}
