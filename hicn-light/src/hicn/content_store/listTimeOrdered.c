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

#include <parc/assert/parc_Assert.h>
#include <hicn/hicn-light/config.h>
#include <hicn/content_store/listTimeOrdered.h>

#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_TreeRedBlack.h>

/**
 * A list of ContentStoreEntrys, kept in sorted order by time. The ordering is
 * calculated by a key compare function (e.g. {@link TimeOrderList_KeyCompare}),
 * passed in.
 *
 * This container does not hold references to the objects that it contains. In
 * other words, it does not Acquire() the Messages that are placed in it. That
 * reference count is managed by the owning ContentStore. This is purely an
 * index, and provides an easy to way index Messages based on a specified time
 * value. Typically, that would be the Expiration Time.
 *
 * It maintains a tree, sorted by the time values passed in to the Add()
 * function. It does not manage capacity, and can grow uncontrollably if the
 * owning ContentStore does not manage it. Items are indexed first by time, then
 * address of the Message (just as a distringuishing attribute). This allows us
 * to store multiple items with the same expiration time.
 */

struct list_timeordered {
  PARCTreeRedBlack *timeOrderedTree;
};

static void _finalRelease(ListTimeOrdered **listP) {
  ListTimeOrdered *list = *listP;
  parcTreeRedBlack_Destroy(&list->timeOrderedTree);
}

parcObject_ExtendPARCObject(ListTimeOrdered, _finalRelease, NULL, NULL, NULL,
                            NULL, NULL, NULL);

parcObject_ImplementAcquire(listTimeOrdered, ListTimeOrdered);

parcObject_ImplementRelease(listTimeOrdered, ListTimeOrdered);

ListTimeOrdered *listTimeOrdered_Create(
    TimeOrderList_KeyCompare *keyCompareFunction) {
  ListTimeOrdered *result = parcObject_CreateInstance(ListTimeOrdered);
  if (NULL != result) {
    result->timeOrderedTree =
        parcTreeRedBlack_Create(keyCompareFunction,  // keyCompare
                                NULL,                // keyFree
                                NULL,                // keyCopy
                                NULL,                // valueEquals
                                NULL,                // valueFree
                                NULL);               // valueCopy
  }
  return result;
}

void listTimeOrdered_Add(ListTimeOrdered *list, ContentStoreEntry *entry) {
  parcTreeRedBlack_Insert(list->timeOrderedTree, entry, entry);
}

ContentStoreEntry *listTimeOrdered_GetOldest(ListTimeOrdered *list) {
  return parcTreeRedBlack_FirstKey(list->timeOrderedTree);
}

bool listTimeOrdered_Remove(ListTimeOrdered *list,
                            ContentStoreEntry *storeEntry) {
  bool result = false;

  ContentStoreEntry *entry = (ContentStoreEntry *)parcTreeRedBlack_Remove(
      list->timeOrderedTree, storeEntry);
  if (entry != NULL) {
    result = true;
  }
  return result;
}

size_t listTimeOrdered_Length(ListTimeOrdered *list) {
  return (size_t)parcTreeRedBlack_Size(list->timeOrderedTree);
}
