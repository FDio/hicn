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

#ifndef contentStoreInterface_h
#define contentStoreInterface_h

#include <stdio.h>

#include <hicn/core/message.h>

typedef struct contentstore_config {
  size_t objectCapacity;
} ContentStoreConfig;

typedef struct contentstore_interface ContentStoreInterface;

struct contentstore_interface {
  /**
   * Place a Message representing a ContentObject into the ContentStore. If
   * necessary to make room, remove expired content or content that has exceeded
   * the Recommended Cache Time.
   *
   * @param storeImpl - a pointer to this ContentStoreInterface instance.
   * @param content - a pointer to a `Message` to place in the store.
   * @param currentTimeTicks - the current time, in hicn-light ticks, since the
   * UTC epoch.
   */
  bool (*putContent)(ContentStoreInterface *storeImpl, Message *content,
                     uint64_t currentTimeTicks);

  /**
   * The function to call to remove content from the ContentStore.
   * It will Release any references that were created when the content was
   * placed into the ContentStore.
   *
   * @param storeImpl - a pointer to this ContentStoreInterface instance.
   * @param content - a pointer to a `Message` to remove from the store.
   */
  bool (*removeContent)(ContentStoreInterface *storeImpl, Message *content);

  /**
   * Given a Message that represents and Interest, try to find a matching
   * ContentObject.
   *
   * @param storeImpl - a pointer to this ContentStoreInterface instance.
   * @param interest - a pointer to a `Message` representing the Interest to
   * match.
   *
   * @return a pointer to a Message containing the matching ContentObject
   * @return NULL if no matching ContentObject was found
   */
  Message *(*matchInterest)(ContentStoreInterface *storeImpl, Message *interest,
                            uint64_t currentTimeTicks);

  /**
   * Return the maximum number of ContentObjects that can be stored in this
   * ContentStore. This is a raw count, not based on memory size.
   *
   * @param storeImpl - a pointer to this ContentStoreInterface instance.
   *
   * @return the maximum number of ContentObjects that can be stored
   */
  size_t (*getObjectCapacity)(ContentStoreInterface *storeImpl);

  /**
   * Return the number of ContentObjects currently stored in the ContentStore.
   *
   * @param storeImpl - a pointer to this ContentStoreInterface instance.
   *
   * @return the current number of ContentObjects in the ContentStore
   */
  size_t (*getObjectCount)(ContentStoreInterface *storeImpl);

  /**
   * Log a ContentStore implementation specific version of store-related
   * information.
   *
   * @param storeImpl - a pointer to this ContentStoreInterface instance.
   */
  void (*log)(ContentStoreInterface *storeImpl);

  /**
   * Acquire a new reference to the specified ContentStore instance. This
   * reference will eventually need to be released by calling {@link
   * contentStoreInterface_Release}.
   *
   * @param storeImpl - a pointer to this ContentStoreInterface instance.
   */
  ContentStoreInterface *(*acquire)(const ContentStoreInterface *storeImpl);

  /**
   * Release the ContentStore, which will also Release any references held by
   * it.
   *
   * @param storeImpl - a pointer to this ContentStoreInterface instance.
   */
  void (*release)(ContentStoreInterface **storeImpl);

  /**
   * A pointer to opaque private data used by the ContentStore instance
   * represented by this instance of ContentStoreInterface.
   */
  void *_privateData;
};

/**
 * Place a Message representing a ContentObject into the ContentStore. If
 * necessary to make room, remove expired content or content that has exceeded
 * the Recommended Cache Time.
 *
 * @param storeImpl - a pointer to this ContentStoreInterface instance.
 * @param content - a pointer to a `Message` to place in the store.
 *
 * @param currentTimeTicks - the current time, in hicn-light ticks, since the
 * UTC epoch.
 */
bool contentStoreInterface_PutContent(ContentStoreInterface *storeImpl,
                                      Message *content,
                                      uint64_t currentTimeTicks);

/**
 * The function to call to remove content from the ContentStore.
 * It will Release any references that were created when the content was placed
 * into the ContentStore.
 *
 * @param storeImpl - a pointer to this ContentStoreInterface instance.
 * @param content - a pointer to a `Message` to remove from the store.
 */
bool contentStoreInterface_RemoveContent(ContentStoreInterface *storeImpl,
                                         Message *content);

/**
 * Given a Message that represents and Interest, try to find a matching
 * ContentObject.
 *
 * @param storeImpl - a pointer to this ContentStoreInterface instance.
 * @param interest - a pointer to a `Message` representing the Interest to
 * match.
 *
 * @return a pointer to a Message containing the matching ContentObject
 * @return NULL if no matching ContentObject was found
 */
Message *contentStoreInterface_MatchInterest(ContentStoreInterface *storeImpl,
                                             Message *interest,
                                             uint64_t currentTimeTicks);

/**
 * Return the maximum number of ContentObjects that can be stored in this
 * ContentStore. This is a raw count, not based on memory size.
 *
 * @param storeImpl - a pointer to this ContentStoreInterface instance.
 *
 * @return the maximum number of ContentObjects that can be stored
 */
size_t contentStoreInterface_GetObjectCapacity(
    ContentStoreInterface *storeImpl);

/**
 * Return the number of ContentObjects currently stored in the ContentStore.
 *
 * @param storeImpl - a pointer to this ContentStoreInterface instance.
 *
 * @return the current number of ContentObjects in the ContentStore
 */
size_t contentStoreInterface_GetObjectCount(ContentStoreInterface *storeImpl);

/**
 * Loga ContentStore implementation specific version of store-related
 * information.
 *
 * @param storeImpl - a pointer to this ContentStoreInterface instance.
 */
void contentStoreInterface_Log(ContentStoreInterface *storeImpl);

/**
 * Acquire a new reference to the specified ContentStore instance. This
 * reference will eventually need to be released by calling {@link
 * contentStoreInterface_Release}.
 *
 * @param storeImpl - a pointer to this ContentStoreInterface instance.
 */
ContentStoreInterface *contentStoreInterface_Aquire(
    const ContentStoreInterface *storeImpl);

/**
 * Release the ContentStore, which will also Release any references held by it.
 *
 * @param storeImpl - a pointer to this ContentStoreInterface instance.
 */
void contentStoreInterface_Release(ContentStoreInterface **storeImplPtr);

/**
 * Return a pointer to the data private to this implementation of the
 * ContentStore interface.
 *
 * @param storeImpl - a pointer to this ContentStoreInterface instance.
 */
void *contentStoreInterface_GetPrivateData(ContentStoreInterface *storeImpl);
#endif  // contentStoreInterface_h
