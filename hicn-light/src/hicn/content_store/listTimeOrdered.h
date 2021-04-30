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

#ifndef listTimeOrdered_h
#define listTimeOrdered_h

#include <parc/algol/parc_TreeRedBlack.h>
#include <hicn/content_store/contentStoreEntry.h>
#include <hicn/core/message.h>
#include <stdio.h>

struct list_timeordered;
typedef struct list_timeordered ListTimeOrdered;

/**
 * A signum function that takes two instances of ContentStoreEntrys and
 * returns a value based on their relative values.
 */
typedef PARCTreeRedBlack_KeyCompare TimeOrderList_KeyCompare;

/**
 * Create a new instance of `ListTimeOrdered` that will maintain the order of
 * its list items using the supplied `keyCompareFunction`.
 *
 * The newly created `ListTimeOrdered` must eventually be released by calling
 * {@link listTimeOrdered_Release}.
 *
 * @param keyCompareFunction the signum comparison function to use to sort
 * stored items.
 * @return a new instance of `TimeOrderList`.
 * @return NULL if the new instance couldn't be created.
 *
 */
ListTimeOrdered *listTimeOrdered_Create(
    TimeOrderList_KeyCompare *keyCompareFunction);

/**
 * Release a previously acquired reference to the specified instance,
 * decrementing the reference count for the instance.
 *
 * The pointer to the instance is set to NULL as a side-effect of this function.
 *
 * If the invocation causes the last reference to the instance to be released,
 * the instance is deallocated and the instance's implementation will perform
 * additional cleanup and release other privately held references.
 *
 */
void listTimeOrdered_Release(ListTimeOrdered **listP);

/**
 * Add a {@link ContentStoreEntry} instance to the specified list. Note that a
 * new refernece to the specified `storeEntry` is not acquired.
 *
 * @param list the list instance into which to add the specified storeEntry.
 * @param storeEntry the storeEntry instance to add.
 *
 */
void listTimeOrdered_Add(ListTimeOrdered *list, ContentStoreEntry *storeEntry);

/**
 * Remove a {@link ContentStoreEntry} instance from the specified list.
 *
 * @param list the list instance from which to remove the specified storeEntry.
 * @param storeEntry the storeEntry instance to remove.
 * @return true if the removal was succesful.
 * @return false if the removal was not succesful.
 *
 */
bool listTimeOrdered_Remove(ListTimeOrdered *list,
                            ContentStoreEntry *storeEntry);

/**
 * Return the oldest {@link ContentStoreEntry} instance in this list. That is,
 * the one with the smallest time value.
 *
 * @param list the list instance from which to retrieve the oldest storeEntry.
 * @param the oldest `ContentStoreEntry` in the list
 * @param NULL if no `ContentStoreEntry` was available.
 *
 */
ContentStoreEntry *listTimeOrdered_GetOldest(ListTimeOrdered *list);

/**
 * Return the number of items currently stored in the list.
 *
 * @param list the `ListTimeOrdered` instance from which to retrieve the count.
 * @return the number of items in the list.
 *
 */
size_t listTimeOrdered_Length(ListTimeOrdered *list);
#endif /* defined(listTimeOrdered_h) */
