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

#include <parc/algol/parc_Memory.h>
#include <hicn/content_store/contentStoreEntry.h>

#include <parc/assert/parc_Assert.h>

const uint64_t contentStoreEntry_MaxExpiryTime = UINT64_MAX;

struct contentstore_entry {
  Message *message;
  ListLruEntry *lruEntry;
  unsigned refcount;
  bool hasExpiryTimeTicks;
  uint64_t expiryTimeTicks;
};

ContentStoreEntry *contentStoreEntry_Create(Message *contentMessage,
                                            ListLru *listLRU) {
  parcAssertNotNull(contentMessage, "Parameter objectMessage must be non-null");

  ContentStoreEntry *entry =
      parcMemory_AllocateAndClear(sizeof(ContentStoreEntry));
  parcAssertNotNull(entry, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ContentStoreEntry));
  entry->message = message_Acquire(contentMessage);
  entry->refcount = 1;

  if (listLRU != NULL) {
    entry->lruEntry = listLRU_NewHeadEntry(listLRU, entry);
  }

  entry->hasExpiryTimeTicks = message_HasContentExpiryTime(contentMessage);

  if (entry->hasExpiryTimeTicks) {
    entry->expiryTimeTicks = message_GetContentExpiryTimeTicks(contentMessage);
  }

  return entry;
}

ContentStoreEntry *contentStoreEntry_Acquire(
    const ContentStoreEntry *original) {
  parcAssertNotNull(original, "Parameter must be non-null");
  ((ContentStoreEntry *)original)->refcount++;
  return (ContentStoreEntry *)original;
}

void contentStoreEntry_Release(ContentStoreEntry **entryPtr) {
  parcAssertNotNull(entryPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*entryPtr,
                    "Parameter must dereference to non-null pointer");

  ContentStoreEntry *entry = *entryPtr;
  parcAssertTrue(entry->refcount > 0, "Illegal state: has refcount of 0");

  entry->refcount--;
  if (entry->refcount == 0) {
    if (entry->lruEntry) {
      listLRU_EntryDestroy(&entry->lruEntry);
    }
    message_Release(&entry->message);
    parcMemory_Deallocate((void **)&entry);
  }
  *entryPtr = NULL;
}

Message *contentStoreEntry_GetMessage(const ContentStoreEntry *storeEntry) {
  parcAssertNotNull(storeEntry, "Parameter must be non-null");
  return storeEntry->message;
}

bool contentStoreEntry_HasExpiryTimeTicks(const ContentStoreEntry *storeEntry) {
  parcAssertNotNull(storeEntry, "Parameter must be non-null");
  return storeEntry->hasExpiryTimeTicks;
}

uint64_t contentStoreEntry_GetExpiryTimeTicks(
    const ContentStoreEntry *storeEntry) {
  parcAssertNotNull(storeEntry, "Parameter must be non-null");
  parcAssertTrue(storeEntry->hasExpiryTimeTicks,
                 "storeEntry has no ExpiryTimeTicks. Did you call "
                 "contentStoreEntry_HasExpiryTimeTicks() first?");
  return storeEntry->expiryTimeTicks;
}

int contentStoreEntry_CompareExpiryTime(const ContentStoreEntry *value1,
                                        const ContentStoreEntry *value2) {
  // A signum comparison. negative if key 1 is smaller, 0 if key1 == key2,
  // greater than 0 if key1 is bigger.

  ContentStoreEntry *v1 = (ContentStoreEntry *)value1;
  ContentStoreEntry *v2 = (ContentStoreEntry *)value2;

  if (v1->expiryTimeTicks < v2->expiryTimeTicks) {
    return -1;
  } else if (v1->expiryTimeTicks > v2->expiryTimeTicks) {
    return +1;
  } else {
    // At this point, the times are the same. Use the address of the message as
    // the decider. This allows us to store multiple messages with the same
    // expiry/cache time.
    if (v1->message < v2->message) {
      return -1;
    } else if (v1->message > v2->message) {
      return +1;
    }
  }

  return 0;  // The same message has been encountered.
}

void contentStoreEntry_MoveToHead(ContentStoreEntry *storeEntry) {
  parcAssertNotNull(storeEntry, "Parameter must be non-null");
  parcAssertNotNull(storeEntry->lruEntry,
                    "ContentStoreEntry is not attached to an ListLru");
  if (storeEntry->lruEntry) {
    listLRU_EntryMoveToHead(storeEntry->lruEntry);
  }
}
