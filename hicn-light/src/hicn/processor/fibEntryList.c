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
#include <hicn/processor/fibEntryList.h>

struct fib_entry_list {
  PARCArrayList *listOfFibEntries;
};

static void fibEntryList_ListDestroyer(void **voidPtr) {
  FibEntry **entryPtr = (FibEntry **)voidPtr;
  fibEntry_Release(entryPtr);
}

FibEntryList *fibEntryList_Create() {
  FibEntryList *fibEntryList =
      parcMemory_AllocateAndClear(sizeof(FibEntryList));
  parcAssertNotNull(fibEntryList,
                    "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(FibEntryList));
  fibEntryList->listOfFibEntries =
      parcArrayList_Create(fibEntryList_ListDestroyer);
  return fibEntryList;
}

void fibEntryList_Destroy(FibEntryList **listPtr) {
  parcAssertNotNull(listPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*listPtr, "Parameter must dereference to non-null pointer");

  FibEntryList *list = *listPtr;
  parcArrayList_Destroy(&list->listOfFibEntries);
  parcMemory_Deallocate((void **)&list);
  listPtr = NULL;
}

void fibEntryList_Append(FibEntryList *list, FibEntry *fibEntry) {
  parcAssertNotNull(list, "Parameter list must be non-null pointer");
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null pointer");

  FibEntry *copy = fibEntry_Acquire(fibEntry);
  parcArrayList_Add(list->listOfFibEntries, copy);
}

size_t fibEntryList_Length(const FibEntryList *list) {
  parcAssertNotNull(list, "Parameter list must be non-null pointer");
  return parcArrayList_Size(list->listOfFibEntries);
}

const FibEntry *fibEntryList_Get(const FibEntryList *list, size_t index) {
  parcAssertNotNull(list, "Parameter list must be non-null pointer");
  FibEntry *entry = parcArrayList_Get(list->listOfFibEntries, index);
  return entry;
}
