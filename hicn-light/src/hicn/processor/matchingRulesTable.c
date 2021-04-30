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

#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_Memory.h>

#include <parc/assert/parc_Assert.h>
#include <hicn/processor/hashTableFunction.h>
#include <hicn/processor/matchingRulesTable.h>

struct matching_rules_table {
  // using this wrapper we can manatain multiple hash tables indexed in
  // different ways
  // for now we use only a table indexed by name

  PARCHashCodeTable *tableByName;
  PARCHashCodeTable_Destroyer dataDestroyer;
};

static PARCHashCodeTable *matchingRulesTable_GetTableForMessage(
    const MatchingRulesTable *pit, const Message *interestMessage);

// ======================================================================

MatchingRulesTable *matchingRulesTable_Create(
    PARCHashCodeTable_Destroyer dataDestroyer) {
  size_t initialSize = 65535;

  MatchingRulesTable *table =
      parcMemory_AllocateAndClear(sizeof(MatchingRulesTable));
  parcAssertNotNull(table, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(MatchingRulesTable));
  table->dataDestroyer = dataDestroyer;

  table->tableByName = parcHashCodeTable_Create_Size(
      hashTableFunction_MessageNameEquals,
      hashTableFunction_MessageNameHashCode, NULL, dataDestroyer, initialSize);

  return table;
}

void matchingRulesTable_Destroy(MatchingRulesTable **tablePtr) {
  parcAssertNotNull(tablePtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*tablePtr,
                    "Parameter must dereference to non-null pointer");

  MatchingRulesTable *table = *tablePtr;

  parcHashCodeTable_Destroy(&table->tableByName);

  parcMemory_Deallocate((void **)&table);
  *tablePtr = NULL;
}

void *matchingRulesTable_Get(const MatchingRulesTable *rulesTable,
                             const Message *message) {
  parcAssertNotNull(rulesTable, "Parameter rulesTable must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");

  PARCHashCodeTable *hashTable =
      matchingRulesTable_GetTableForMessage(rulesTable, message);
  return parcHashCodeTable_Get(hashTable, message);
}

PARCArrayList *matchingRulesTable_GetUnion(const MatchingRulesTable *table,
                                           const Message *message) {
  PARCArrayList *list = parcArrayList_Create_Capacity(NULL, NULL, 3);

  void *dataByName = parcHashCodeTable_Get(table->tableByName, message);
  if (dataByName) {
    parcArrayList_Add(list, dataByName);
  }

  return list;
}

void matchingRulesTable_RemoveFromBest(MatchingRulesTable *rulesTable,
                                       const Message *message) {
  parcAssertNotNull(rulesTable, "Parameter rulesTable must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");

  PARCHashCodeTable *hashTable =
      matchingRulesTable_GetTableForMessage(rulesTable, message);
  parcHashCodeTable_Del(hashTable, message);
}

void matchingRulesTable_RemoveFromAll(MatchingRulesTable *rulesTable,
                                      const Message *message) {
  parcAssertNotNull(rulesTable, "Parameter rulesTable must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");

  parcHashCodeTable_Del(rulesTable->tableByName, message);
}

bool matchingRulesTable_AddToBestTable(MatchingRulesTable *rulesTable,
                                       Message *key, void *data) {
  parcAssertNotNull(rulesTable, "Parameter rulesTable must be non-null");
  parcAssertNotNull(key, "Parameter key must be non-null");
  parcAssertNotNull(data, "Parameter data must be non-null");

  PARCHashCodeTable *hashTable =
      matchingRulesTable_GetTableForMessage(rulesTable, key);

  bool success = parcHashCodeTable_Add(hashTable, key, data);

  return success;
}

// ========================================================================================

static PARCHashCodeTable *matchingRulesTable_GetTableForMessage(
    const MatchingRulesTable *pit, const Message *interestMessage) {
  PARCHashCodeTable *table;
  table = pit->tableByName;

  return table;
}
