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
 * @file listLRU.h
 * @brief Maintains an LRU for the content store
 *
 * An LRU list is make up of LRU entries.  The entries are bound to the list.
 * The user of the list is reponsible for knowing when there's too many things
 * and wants to remove one.  The LRU list will grow without bound otherwise.
 *
 * The LRU list is meant to be used as an auxiliary data structure, not the
 * primary storage of data elements.
 *
 */

#ifndef listLRU_h
#define listLRU_h

struct list_lru_entry;
typedef struct list_lru_entry ListLruEntry;

struct list_lru;
typedef struct list_lru ListLru;

/**
 * @function lruEntry_Destroy
 * @abstract Destroys and element.  This will also remove it from the list.
 */
void listLRU_EntryDestroy(ListLruEntry **entryPtr);

/**
 * @function listLRU_EntryMoveToHead
 * @abstract move an element to head
 */
void listLRU_EntryMoveToHead(ListLruEntry *entry);

/**
 * @function lruEntry_GetData
 * @abstract Returns the user-supplied opaque data when the entry was created
 */
void *listLRU_EntryGetData(ListLruEntry *entry);

/**
 * @function listLRU_Create
 * @abstract Creates a new Least-Recently-Used list
 */
ListLru *listLRU_Create();

/**
 * @function listLRU_Destroy
 * @abstract Destroys a list and frees all the elements in it
 */
void listLRU_Destroy(ListLru **listPtr);

/**
 * Returns the number of items in the list
 *
 * @param [in] lru An allocated ListLru
 * @retval number The number of items in the LRU list
 */
size_t listLRU_Length(const ListLru *lru);

/**
 * @function listLRU_NewHeadEntry
 * @abstract Creates a new entry for the list.  It is inserted at the head of
 * the list.
 */
ListLruEntry *listLRU_NewHeadEntry(ListLru *lru, void *data);

/**
 * @function listLRU_PopTail
 * @abstract Removes the tail element from the list and returns it to the user
 * @discussion
 *   Pops the tail element.  The user should examine its data to destroy their
 *   tail object, then call <code>LruEntry_Destroy()</code> to free the
 *   LRU entry.
 *
 * @return The tail element, or NULL for an empty list
 */
ListLruEntry *listLRU_PopTail(ListLru *list);
#endif  // listLRU_h
