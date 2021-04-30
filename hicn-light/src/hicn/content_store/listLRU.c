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

#ifndef _WIN32
#include <sys/queue.h>
#endif
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>

#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/content_store/listLRU.h>

struct list_lru_entry {
  void *userData;

  // always set to the list
  ListLru *parentList;

  // indicates if the Entry is currently in the list
  bool inList;

  TAILQ_ENTRY(list_lru_entry) list;
};

// this defines the TAILQ structure so we can access the tail pointer
TAILQ_HEAD(lru_s, list_lru_entry);

struct list_lru {
  struct lru_s head;
  size_t itemsInList;
};

void listLRU_EntryDestroy(ListLruEntry **entryPtr) {
  parcAssertNotNull(entryPtr,
                    "Parameter entryPtr must be non-null double pointer");

  ListLruEntry *entry = *entryPtr;
  if (entry->inList) {
    TAILQ_REMOVE(&entry->parentList->head, entry, list);
    parcAssertTrue(
        entry->parentList->itemsInList > 0,
        "Invalid state, removed entry from list, but itemsInList is 0");
    entry->parentList->itemsInList--;
  }

  parcMemory_Deallocate((void **)&entry);
  *entryPtr = NULL;
}

void listLRU_EntryMoveToHead(ListLruEntry *entry) {
  parcAssertNotNull(entry, "Parameter entry must be non-null");

  TAILQ_REMOVE(&entry->parentList->head, entry, list);
  TAILQ_INSERT_HEAD(&entry->parentList->head, entry, list);
}

void *listLRU_EntryGetData(ListLruEntry *entry) { return entry->userData; }

ListLru *listLRU_Create() {
  ListLru *list = parcMemory_AllocateAndClear(sizeof(ListLru));
  parcAssertNotNull(list, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ListLru));
  list->itemsInList = 0;
  TAILQ_INIT(&list->head);
  return list;
}

void listLRU_Destroy(ListLru **lruPtr) {
  parcAssertNotNull(lruPtr, "Parameter lruPtr must be non-null double pointer");

  ListLru *lru = *lruPtr;

  ListLruEntry *entry = TAILQ_FIRST(&lru->head);
  while (entry != NULL) {
    ListLruEntry *next = TAILQ_NEXT(entry, list);
    listLRU_EntryDestroy(&entry);
    entry = next;
  }

  parcMemory_Deallocate((void **)&lru);
  *lruPtr = NULL;
}

ListLruEntry *listLRU_NewHeadEntry(ListLru *lru, void *data) {
  parcAssertNotNull(lru, "Parameter lru must be non-null");
  parcAssertNotNull(data, "Parameter data must be non-null");

  ListLruEntry *entry = parcMemory_AllocateAndClear(sizeof(ListLruEntry));
  parcAssertNotNull(entry, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ListLruEntry));
  entry->userData = data;
  entry->parentList = lru;
  entry->inList = true;

  TAILQ_INSERT_HEAD(&lru->head, entry, list);
  lru->itemsInList++;

  return entry;
}

ListLruEntry *listLRU_PopTail(ListLru *lru) {
  parcAssertNotNull(lru, "Parameter lru must be non-null");

  ListLruEntry *entry = TAILQ_LAST(&lru->head, lru_s);

  if (entry) {
    parcAssertTrue(
        lru->itemsInList > 0,
        "Invalid state, removed entry from list, but itemsInList is 0");
    lru->itemsInList--;
    TAILQ_REMOVE(&lru->head, entry, list);
    entry->inList = false;
  }

  return entry;
}

size_t listLRU_Length(const ListLru *lru) {
  parcAssertNotNull(lru, "Parameter lru must be non-null");
  return lru->itemsInList;
}
