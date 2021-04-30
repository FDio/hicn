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

#ifndef contentStoreEntry_h
#define contentStoreEntry_h

#include <hicn/content_store/listLRU.h>
#include <hicn/core/message.h>

struct contentstore_entry;
typedef struct contentstore_entry ContentStoreEntry;

/**
 * The max time allowed for an ExpiryTime. Will never be exceeded.
 */
extern const uint64_t contentStoreEntry_MaxExpiryTime;

/**
 * Creates a new `ContentStoreEntry` instance, acquiring a reference to the
 * supplied `Message`.
 *
 * @param message the message to store
 * @param listLRU the LRU list that this entry will be stored in.
 * @return A newly created `ContentStoreEntry` instance that must eventually be
 * released by calling
 *         {@link contentStoreEntry_Release}.
 *
 * @see contentStoreEntry_Release
 */
ContentStoreEntry *contentStoreEntry_Create(Message *objectMessage,
                                            ListLru *listLRU);

/**
 * Returns a reference counted copy of the supplied `ContentStoreEntry`.
 *
 * @param original the ContentStoreEntry to return a reference to.
 * @return Reference counted copy, must call
 * <code>contentStoreEntry_Destroy()</code> on it.
 */
ContentStoreEntry *contentStoreEntry_Acquire(const ContentStoreEntry *original);

/**
 * Releases one reference count and destroys object when reaches zero
 *
 * @param [in,out] entryPtr A pointer to an allocated ContentStoreEntry
 *
 */
void contentStoreEntry_Release(ContentStoreEntry **entryPtr);

/**
 * Returns a pointer to the contained {@link Message}.
 * The caller must called {@link message_Acquire()} if they want to keep a
 * reference to the returned message.
 *
 * @param storeEntry the ContentStoreEntry from which to retrieve the `Message`
 * pointer.
 * @return the address of the `Message` contained in the storeEntry.
 * @see message_Acquire
 */
Message *contentStoreEntry_GetMessage(const ContentStoreEntry *storeEntry);

/**
 * Return true if the message stored in this `ContentStoreEntry` has an
 * ExpiryTime.
 *
 * @param storeEntry the ContentStoreEntry containing the message.
 * @return true if the referenced message has an ExpiryTime. False, otherwise.
 */
bool contentStoreEntry_HasExpiryTimeTicks(const ContentStoreEntry *storeEntry);

/**
 * Return the ExpiryTime stored in this `ContentStoreEntry`.
 *
 * @param storeEntry the ContentStoreEntry from which to retrieve the `Message`
 * pointer.
 * @return the address of the `Message` contained in the storeEntry.
 */
uint64_t contentStoreEntry_GetExpiryTimeTicks(
    const ContentStoreEntry *storeEntry);

/**
 * A signum function comparing two `ContentStoreEntry` instances, using their
 * ExpiryTime and, if necessary, the addresses of the referenced Message. In
 * other words, if two ContentStoreEntries have the same ExpiryTime, the
 * comparison will then be made on the memory addresses of the Messages
 * referenced by the ContentStoreEntrys. So, the only way two ContentStoreEntrys
 * will compare equally (0) is if they both have the same ExpiryTime and
 * reference the same Message.
 *
 * Used to determine the ordering relationship of two `ContentStoreEntry`
 * instances. This is used by the {@link ListTimeOrdered} to keep a list of
 * ContentStoreEntrys, sorted by ExpiryTime.
 *
 * @param [in] storeEntry1 A pointer to a `ContentStoreEntry` instance.
 * @param [in] storeEntry2 A pointer to a `ContentStoreEntry` instance to be
 * compared to `storeEntry1`.
 *
 * @return 0 if `storeEntry1` and `storeEntry2` are equivalent
 * @return < 0 if `storeEntry1` < `storeEntry2`
 * @return > 0 if `storeEntry1` > `storeEntry2`
 *
 * Example:
 * @code
 * {
 *     ContentStoreEntry *entry1 = contentStoreEntry_Create(...);
 *     ContentStoreEntry *entry2 = contentStoreEntry_Create(...);
 *
 *     int val = contentStoreEntry_CompareExpiryTime(entry1, entry2);
 *     if (val < 0) {
 *         // entry1 has a lower ExpiryTime, or the same ExpiryTime as entry2
 * and a different message. } else if (val > 0) {
 *         // entry2 has a lower ExpiryTime, or the same ExpiryTime as entry1
 * and a different message. } else {
 *         // entry1 and entry2 have the same ExpiryTime AND the same message.
 *     }
 *
 *     contentStoreEntry_Release(&entry1);
 *     contentStoreEntry_Release(&entry2);
 *
 * }
 * @endcode
 */
int contentStoreEntry_CompareExpiryTime(const ContentStoreEntry *storeEntry1,
                                        const ContentStoreEntry *storeEntry2);

/**
 * Move this entry to the head of the LRU list
 *
 * Moves the entry to the head of the LRU list it was created with
 *
 * @param [in] storeEntry An allocated ContenstoreEntry
 */
void contentStoreEntry_MoveToHead(ContentStoreEntry *storeEntry);
#endif  // contentStoreEntry_h
