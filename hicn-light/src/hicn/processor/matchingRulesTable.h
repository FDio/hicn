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
 * @header matchingRulesTable
 * @abstract A generic table (void *) that matches a Message
 * @discussion
 *     Matching is done based on Name
 *
 *     When used in the PIT, one calls
 * <code>matchingRulesTable_AddToBestTable()</code> to add an interest to the
 * "best" (i.e. most restrictive match) table, then calls
 *     <code>matchingRulesTable_GetUnion()</code> on a content object to match
 * against all of them.
 *
 *     When used in a ContentStore, one calls
 * <code>matchingRulesTable_AddToAllTables()</code> to index a Content Object in
 * all the tables.  one then calls <code>matchingRulesTable_Get()</code> with an
 * Interest to do the "best" matching (i.e by hash first, then keyid, then just
 * by name).
 *
 */

#ifndef matchingRulesTable_h
#define matchingRulesTable_h

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_HashCodeTable.h>
#include <hicn/core/message.h>

struct matching_rules_table;
typedef struct matching_rules_table MatchingRulesTable;

/**
 * Creates a MatchigRulesTable and specifies the function to call to de-allocate
 * an entry
 *
 * The datadestroyer will be called when an entry is removed from a table. It
 * may be NULL.
 */
MatchingRulesTable *matchingRulesTable_Create(
    PARCHashCodeTable_Destroyer dataDestroyer);

/**
 * Destroys the table and removes all stored elements.
 *
 */
void matchingRulesTable_Destroy(MatchingRulesTable **tablePtr);

/**
 * @function matchingRulesTable_Get
 * @abstract Returns the data item that best matches the message.
 * @discussion
 *   Indexed by NameAndContentObjectHash, NameAndKeyId, and Name, in that order.
 *
 * @return NULL if nothing matches, otherwise the stored value
 */
void *matchingRulesTable_Get(const MatchingRulesTable *table,
                             const Message *message);

/**
 * @function matchingRulesTable_GetUnion
 * @abstract Returns matching data items from all index tables.
 * @discussion
 *   The PARCArrayList does not have an item destructor, so destroying it will
 * not affect the underlying data.
 *
 * @return Will not be NULL, but may be empty
 */
PARCArrayList *matchingRulesTable_GetUnion(const MatchingRulesTable *table,
                                           const Message *message);

/**
 * @function matchingRulesTable_Add
 * @abstract Adds the data to the best table
 * @discussion
 *   The key must be derived from the data and destroyed when the data is
 * destroyed.  Only the data destroyer is called.
 *
 *   No duplicates are allowed, will return false if not added.
 *
 * @return true if unique key and added, false if duplicate and no action taken.
 */
bool matchingRulesTable_AddToBestTable(MatchingRulesTable *rulesTable,
                                       Message *key, void *data);

/**
 * @function matchingRulesTable_Remove
 * @abstract Removes the matching entry from the best match table, calling the
 * destroyer on the data.
 */
void matchingRulesTable_RemoveFromBest(MatchingRulesTable *rulesTable,
                                       const Message *message);

/**
 * @function matchingRulesTable_RemoveFromAll
 * @abstract Removes the message from all tables
 */
void matchingRulesTable_RemoveFromAll(MatchingRulesTable *rulesTable,
                                      const Message *message);
#endif  // matchingRulesTable_h
