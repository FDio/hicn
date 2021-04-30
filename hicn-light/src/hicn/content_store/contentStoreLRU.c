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
#include <stdio.h>

#include <parc/algol/parc_DisplayIndented.h>
#include <parc/algol/parc_HashCodeTable.h>
#include <parc/algol/parc_Object.h>

#include <hicn/core/logger.h>

#include <hicn/content_store/contentStoreLRU.h>

#include <hicn/content_store/contentStoreEntry.h>
#include <hicn/content_store/contentStoreInterface.h>
#include <hicn/content_store/listLRU.h>
#include <hicn/content_store/listTimeOrdered.h>

#include <parc/assert/parc_Assert.h>
#include <hicn/processor/hashTableFunction.h>

typedef struct contentstore_stats {
  uint64_t countExpiryEvictions;
  uint64_t countRCTEvictions;
  uint64_t countLruEvictions;
  uint64_t countAdds;
  uint64_t countHits;
  uint64_t countMisses;
} _ContentStoreLRUStats;

typedef struct contentstore_lru_data {
  size_t objectCapacity;
  size_t objectCount;

  Logger *logger;

  // This LRU is just for keeping track of insertion and access order.
  ListLru *lru;

  ListTimeOrdered *indexByExpirationTime;

  PARCHashCodeTable *storageByName;

  _ContentStoreLRUStats stats;
} _ContentStoreLRU;

static void _destroyIndexes(_ContentStoreLRU *store) {
  if (store->indexByExpirationTime != NULL) {
    listTimeOrdered_Release(&(store->indexByExpirationTime));
  }

  if (store->storageByName != NULL) {
    parcHashCodeTable_Destroy(&(store->storageByName));
  }

  if (store->lru != NULL) {
    listLRU_Destroy(&(store->lru));
  }
}

static void _contentStoreInterface_Destroy(
    ContentStoreInterface **storeImplPtr) {
  _ContentStoreLRU *store = contentStoreInterface_GetPrivateData(*storeImplPtr);

  parcObject_Release((PARCObject **)&store);
}

static bool _contentStoreLRU_Destructor(_ContentStoreLRU **storePtr) {
  _ContentStoreLRU *store = *storePtr;

  _destroyIndexes(store);
  logger_Release(&store->logger);

  return true;
}

parcObject_Override(_ContentStoreLRU, PARCObject,
                    .destructor = (PARCObjectDestructor *)
                        _contentStoreLRU_Destructor);

parcObject_ExtendPARCObject(ContentStoreInterface,
                            _contentStoreInterface_Destroy, NULL, NULL, NULL,
                            NULL, NULL, NULL);

static parcObject_ImplementAcquire(_contentStoreLRU, ContentStoreInterface);
static parcObject_ImplementRelease(_contentStoreLRU, ContentStoreInterface);

static void _hashTableFunction_ContentStoreEntryDestroyer(void **dataPtr) {
  contentStoreEntry_Release((ContentStoreEntry **)dataPtr);
}

static bool _contentStoreLRU_Init(_ContentStoreLRU *store,
                                  ContentStoreConfig *config, Logger *logger) {
  bool result = false;

  store->logger = logger_Acquire(logger);

  size_t initialSize = config->objectCapacity * 2;
  memset(&store->stats, 0, sizeof(_ContentStoreLRUStats));

  store->objectCapacity = config->objectCapacity;
  store->objectCount = 0;

  // initial size must be at least 1 or else the data structures break.
  initialSize = (initialSize == 0) ? 1 : initialSize;

  store->indexByExpirationTime = listTimeOrdered_Create(
      (TimeOrderList_KeyCompare *)contentStoreEntry_CompareExpiryTime);

  store->storageByName = parcHashCodeTable_Create_Size(
      hashTableFunction_MessageNameEquals,
      hashTableFunction_MessageNameHashCode, NULL,
      _hashTableFunction_ContentStoreEntryDestroyer, initialSize);

  store->lru = listLRU_Create();

  // If any of the index tables couldn't be allocated, we can't continue.
  if ((store->indexByExpirationTime == NULL) ||
      (store->storageByName == NULL) || (store->lru == NULL)) {
    if (logger_IsLoggable(store->logger, LoggerFacility_Processor,
                          PARCLogLevel_Error)) {
      logger_Log(store->logger, LoggerFacility_Processor, PARCLogLevel_Error,
                 __func__,
                 "ContentStoreLRU could not be created. Could not allocate all "
                 "index tables.",
                 (void *)store, store->objectCapacity);
    }

    _destroyIndexes(store);
    result = false;
  } else {
    result = true;
  }
  return result;
}

/**
 * Remove a ContentStoreEntry from all tables and indices.
 */
static void _contentStoreLRU_PurgeStoreEntry(_ContentStoreLRU *store,
                                             ContentStoreEntry *entryToPurge) {
  if (contentStoreEntry_HasExpiryTimeTicks(entryToPurge)) {
    listTimeOrdered_Remove(store->indexByExpirationTime, entryToPurge);
  }

  Message *content = contentStoreEntry_GetMessage(entryToPurge);

  // This _Del call will call the Release/Destroy on the ContentStoreEntry,
  // which will remove it from the LRU as well.
  parcHashCodeTable_Del(store->storageByName, content);

  store->objectCount--;
}

static bool _contentStoreLRU_RemoveLeastUsed(_ContentStoreLRU *store) {
  bool result = false;

  if (store->objectCount > 0) {
    ListLruEntry *lruEntry = listLRU_PopTail(store->lru);
    ContentStoreEntry *storeEntry =
        (ContentStoreEntry *)listLRU_EntryGetData(lruEntry);

    if (logger_IsLoggable(store->logger, LoggerFacility_Processor,
                          PARCLogLevel_Debug)) {
      logger_Log(
          store->logger, LoggerFacility_Processor, PARCLogLevel_Debug, __func__,
          "ContentStore %p evict message %p by LRU (LRU evictions %" PRIu64 ")",
          (void *)store, (void *)contentStoreEntry_GetMessage(storeEntry),
          store->stats.countLruEvictions);
    }

    _contentStoreLRU_PurgeStoreEntry(store, storeEntry);

    result = true;
  }
  return result;
}

static void _evictByStorePolicy(_ContentStoreLRU *store,
                                uint64_t currentTimeInTicks) {
  // We need to make room. Here's the plan:
  //  1) Check to see if anything has expired. If so, remove it and we're done.
  //  If not, 2) Remove the least recently used item.

  ContentStoreEntry *entry =
      listTimeOrdered_GetOldest(store->indexByExpirationTime);
  if (entry && contentStoreEntry_HasExpiryTimeTicks(entry) &&
      (currentTimeInTicks > contentStoreEntry_GetExpiryTimeTicks(entry))) {
    // Found an expired entry. Remove it, and we're done.

    store->stats.countExpiryEvictions++;
    if (logger_IsLoggable(store->logger, LoggerFacility_Processor,
                          PARCLogLevel_Debug)) {
      logger_Log(store->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
                 __func__,
                 "ContentStore %p evict message %p by ExpiryTime (ExpiryTime "
                 "evictions %" PRIu64 ")",
                 (void *)store, (void *)contentStoreEntry_GetMessage(entry),
                 store->stats.countExpiryEvictions);
    }

    _contentStoreLRU_PurgeStoreEntry(store, entry);
  } else {
    store->stats.countLruEvictions++;
    _contentStoreLRU_RemoveLeastUsed(store);
  }
}

static bool _contentStoreLRU_PutContent(ContentStoreInterface *storeImpl,
                                        Message *content,
                                        uint64_t currentTimeTicks)

{
  bool result = false;
  _ContentStoreLRU *store =
      (_ContentStoreLRU *)contentStoreInterface_GetPrivateData(storeImpl);
  parcAssertNotNull(store, "Parameter store must be non-null");
  parcAssertNotNull(content, "Parameter objectMessage must be non-null");

  parcAssertTrue(message_GetType(content) == MessagePacketType_ContentObject,
                 "Parameter objectMessage must be a Content Object");

  if (store->objectCapacity == 0) {
    return false;
  }

  ContentStoreEntry *storeEntry = parcHashCodeTable_Get(store->storageByName, content);
  if(storeEntry){
    _contentStoreLRU_PurgeStoreEntry(store, storeEntry);
  }

  uint64_t expiryTimeTicks = contentStoreEntry_MaxExpiryTime;

  if (message_HasContentExpiryTime(content)) {
    expiryTimeTicks = message_GetContentExpiryTimeTicks(content);
  }
  // Don't add anything that's already expired or has exceeded RCT.
  if (currentTimeTicks >= expiryTimeTicks) {
    return false;
  }

  if (store->objectCount >= store->objectCapacity) {
    // Store is full. Need to make room.
    _evictByStorePolicy(store, currentTimeTicks);
  }

  // And now add a new entry to the head of the LRU.

  ContentStoreEntry *entry = contentStoreEntry_Create(content, store->lru);

  if (entry != NULL) {
    if (parcHashCodeTable_Add(store->storageByName, content, entry)) {
      if (contentStoreEntry_HasExpiryTimeTicks(entry)) {
        listTimeOrdered_Add(store->indexByExpirationTime, entry);
      }

      store->objectCount++;
      store->stats.countAdds++;

      if (logger_IsLoggable(store->logger, LoggerFacility_Processor,
                            PARCLogLevel_Debug)) {
        logger_Log(store->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
                   __func__,
                   "ContentStoreLRU %p saved message %p (object count %" PRIu64
                   ")",
                   (void *)store, (void *)content, store->objectCount);
      }

      result = true;
    } else {
      // Free what we just created, but did not add. 'entry' has ownership of
      // 'copy', and so will call _Release() on it
      contentStoreEntry_Release(&entry);

      if (logger_IsLoggable(store->logger, LoggerFacility_Processor,
                            PARCLogLevel_Warning)) {
        logger_Log(store->logger, LoggerFacility_Processor,
                   PARCLogLevel_Warning, __func__,
                   "ContentStoreLRU %p failed to add message %p to hash table",
                   (void *)store, (void *)content);
      }
    }
  }

  return result;
}

static Message *_contentStoreLRU_MatchInterest(ContentStoreInterface *storeImpl,
                                               Message *interest,
                                               uint64_t currentTimeTicks) {
  Message *result = NULL;

  _ContentStoreLRU *store =
      (_ContentStoreLRU *)contentStoreInterface_GetPrivateData(storeImpl);

  parcAssertNotNull(store, "Parameter store must be non-null");
  parcAssertNotNull(interest, "Parameter interestMessage must be non-null");
  parcAssertTrue(message_GetType(interest) == MessagePacketType_Interest,
                 "Parameter interestMessage must be an Interest");

  PARCHashCodeTable *table;
  table = store->storageByName;

  ContentStoreEntry *storeEntry = parcHashCodeTable_Get(table, interest);

  bool foundEntry = false;

  if (storeEntry) {
    if (contentStoreEntry_HasExpiryTimeTicks(storeEntry) &&
        contentStoreEntry_GetExpiryTimeTicks(storeEntry) < currentTimeTicks) {
      // the entry is expired, we can remove it
      _contentStoreLRU_PurgeStoreEntry(store, storeEntry);
    } else {
      foundEntry = true;
    }
  }

  if (foundEntry) {
    contentStoreEntry_MoveToHead(storeEntry);
    result = contentStoreEntry_GetMessage(storeEntry);

    store->stats.countHits++;

    if (logger_IsLoggable(store->logger, LoggerFacility_Processor,
                          PARCLogLevel_Debug)) {
      logger_Log(store->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
                 __func__,
                 "ContentStoreLRU %p matched interest %p (hits %" PRIu64
                 ", misses %" PRIu64 ")",
                 (void *)store, (void *)interest, store->stats.countHits,
                 store->stats.countMisses);
    }
  } else {
    store->stats.countMisses++;

    if (logger_IsLoggable(store->logger, LoggerFacility_Processor,
                          PARCLogLevel_Debug)) {
      logger_Log(store->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
                 __func__,
                 "ContentStoreLRU %p missed interest %p (hits %" PRIu64
                 ", misses %" PRIu64 ")",
                 (void *)store, (void *)interest, store->stats.countHits,
                 store->stats.countMisses);
    }
  }

  return result;
}

static bool _contentStoreLRU_RemoveContent(ContentStoreInterface *storeImpl,
                                           Message *content) {
  bool result = false;
  _ContentStoreLRU *store =
      (_ContentStoreLRU *)contentStoreInterface_GetPrivateData(storeImpl);

  ContentStoreEntry *storeEntry =
      parcHashCodeTable_Get(store->storageByName, content);

  if (storeEntry != NULL) {
    _contentStoreLRU_PurgeStoreEntry(store, storeEntry);
    result = true;
  }

  return result;
}

static void _contentStoreLRU_Log(ContentStoreInterface *storeImpl) {
  _ContentStoreLRU *store =
      (_ContentStoreLRU *)contentStoreInterface_GetPrivateData(storeImpl);

  logger_Log(store->logger, LoggerFacility_Processor, PARCLogLevel_All,
             __func__,
             "ContentStoreLRU @%p {count = %zu, capacity = %zu {"
             "stats = @%p {adds = %" PRIu64 ", hits = %" PRIu64
             ", misses = %" PRIu64 ", LRUEvictons = %" PRIu64
             ", ExpiryEvictions = %" PRIu64 ", RCTEvictions = %" PRIu64 "} }",
             store, store->objectCount, store->objectCapacity, &store->stats,
             store->stats.countAdds, store->stats.countHits,
             store->stats.countMisses, store->stats.countLruEvictions,
             store->stats.countExpiryEvictions, store->stats.countRCTEvictions);
}

static size_t _contentStoreLRU_GetObjectCapacity(
    ContentStoreInterface *storeImpl) {
  _ContentStoreLRU *store =
      (_ContentStoreLRU *)contentStoreInterface_GetPrivateData(storeImpl);
  return store->objectCapacity;
}

static size_t _contentStoreLRU_GetObjectCount(
    ContentStoreInterface *storeImpl) {
  _ContentStoreLRU *store =
      (_ContentStoreLRU *)contentStoreInterface_GetPrivateData(storeImpl);
  return store->objectCount;
}

static size_t _contentStoreLRU_SetObjectCapacity(
    ContentStoreInterface *storeImpl, size_t newCapacity) {
  _ContentStoreLRU *store =
      (_ContentStoreLRU *)contentStoreInterface_GetPrivateData(storeImpl);
  return store->objectCapacity = newCapacity;
}

ContentStoreInterface *contentStoreLRU_Create(ContentStoreConfig *config,
                                              Logger *logger) {
  ContentStoreInterface *storeImpl = NULL;

  parcAssertNotNull(logger, "ContentStoreLRU requires a non-NULL logger");

  storeImpl = parcObject_CreateAndClearInstance(ContentStoreInterface);

  if (storeImpl != NULL) {
    storeImpl->_privateData =
        parcObject_CreateAndClearInstance(_ContentStoreLRU);

    if (_contentStoreLRU_Init(storeImpl->_privateData, config, logger)) {
      storeImpl->putContent = &_contentStoreLRU_PutContent;
      storeImpl->removeContent = &_contentStoreLRU_RemoveContent;

      storeImpl->matchInterest = &_contentStoreLRU_MatchInterest;

      storeImpl->getObjectCount = &_contentStoreLRU_GetObjectCount;
      storeImpl->getObjectCapacity = &_contentStoreLRU_GetObjectCapacity;

      storeImpl->log = &_contentStoreLRU_Log;

      storeImpl->acquire = &_contentStoreLRU_Acquire;
      storeImpl->release = &_contentStoreLRU_Release;

      // Initialize from the config passed to us.
      _contentStoreLRU_SetObjectCapacity(storeImpl, config->objectCapacity);

      if (logger_IsLoggable(logger, LoggerFacility_Processor,
                            PARCLogLevel_Info)) {
        logger_Log(logger, LoggerFacility_Processor, PARCLogLevel_Info,
                   __func__, "ContentStoreLRU %p created with capacity %zu",
                   (void *)storeImpl,
                   contentStoreInterface_GetObjectCapacity(storeImpl));
      }
    }
  } else {
    parcObject_Release((void **)&storeImpl);
  }

  return storeImpl;
}
