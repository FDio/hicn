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

#include <ctype.h>
#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_HashCodeTable.h>
#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/config/symbolicNameTable.h>

struct symblic_name_table {
  PARCHashCodeTable *symbolicNameTable;
  PARCHashCodeTable *indexToNameTable;
};

// ========================================================================================
// symbolic name table functions

static bool _symbolicNameEquals(const void *keyA, const void *keyB) {
  return (strcasecmp((const char *)keyA, (const char *)keyB) == 0);
}

static HashCodeType _symbolicNameHash(const void *keyA) {
  const char *str = (const char *)keyA;
  size_t length = strlen(str);
  return parcHash32_Data(str, length);
}

static bool _connectionIdEquals(const void *keyA, const void *keyB) {
  unsigned idA = *((unsigned *)keyA);
  unsigned idB = *((unsigned *)keyB);
  return (idA == idB);
}

static HashCodeType _connectionIdHash(const void *keyA) {
  unsigned idA = *((unsigned *)keyA);
  return parcHash32_Int32(idA);
}

// ========================================================================================

SymbolicNameTable *symbolicNameTable_Create(void) {
  SymbolicNameTable *table = parcMemory_Allocate(sizeof(SymbolicNameTable));

  if (table) {
    // key = char *
    // value = uint32_t *
    table->symbolicNameTable = parcHashCodeTable_Create(
        _symbolicNameEquals, _symbolicNameHash, parcMemory_DeallocateImpl,
        parcMemory_DeallocateImpl);
    table->indexToNameTable = parcHashCodeTable_Create(
        _connectionIdEquals, _connectionIdHash, parcMemory_DeallocateImpl,
        parcMemory_DeallocateImpl);
  }

  return table;
}

void symbolicNameTable_Destroy(SymbolicNameTable **tablePtr) {
  SymbolicNameTable *table = *tablePtr;
  parcHashCodeTable_Destroy(&table->symbolicNameTable);
  parcHashCodeTable_Destroy(&table->indexToNameTable);
  parcMemory_Deallocate((void **)&table);
  *tablePtr = NULL;
}

static char *_createKey(const char *symbolicName) {
  char *key = parcMemory_StringDuplicate(symbolicName, strlen(symbolicName));

  // convert key to upper case
  char *p = key;

  // keeps looping until the first null
  while ((*p = toupper(*p))) {
    p++;
  }
  return key;
}

bool symbolicNameTable_Exists(SymbolicNameTable *table,
                              const char *symbolicName) {
  parcAssertNotNull(table, "Parameter table must be non-null");
  parcAssertNotNull(symbolicName, "Parameter symbolicName must be non-null");

  char *key = _createKey(symbolicName);
  bool found = (parcHashCodeTable_Get(table->symbolicNameTable, key) != NULL);
  parcMemory_Deallocate((void **)&key);
  return found;
}

void symbolicNameTable_Remove(SymbolicNameTable *table,
                              const char *symbolicName) {
  parcAssertNotNull(table, "Parameter table must be non-null");
  parcAssertNotNull(symbolicName, "Parameter symbolicName must be non-null");

  char *key = _createKey(symbolicName);

  unsigned id = symbolicNameTable_Get(table, symbolicName);
  uint32_t *value = parcMemory_Allocate(sizeof(uint32_t));
  *value = id;

  parcHashCodeTable_Del(table->symbolicNameTable, key);
  parcHashCodeTable_Del(table->indexToNameTable, value);
  parcMemory_Deallocate((void **)&key);
  parcMemory_Deallocate((void **)&value);
}

bool symbolicNameTable_Add(SymbolicNameTable *table, const char *symbolicName,
                           unsigned connid) {
  parcAssertNotNull(table, "Parameter table must be non-null");
  parcAssertNotNull(symbolicName, "Parameter symbolicName must be non-null");
  parcAssertTrue(connid < UINT32_MAX, "Parameter connid must be less than %u",
                 UINT32_MAX);

  char *key1 = _createKey(symbolicName);

  uint32_t *value1 = parcMemory_Allocate(sizeof(uint32_t));
  *value1 = connid;

  bool success = parcHashCodeTable_Add(table->symbolicNameTable, key1, value1);
  if (!success)
      goto ERR_NAME;

  char *key2 = _createKey(symbolicName);

  uint32_t *value2 = parcMemory_Allocate(sizeof(uint32_t));
  *value2 = connid;

  success = parcHashCodeTable_Add(table->indexToNameTable, value2, key2);
  if (!success)
      goto ERR_INDEX;

  goto END;

ERR_INDEX:
    parcMemory_Deallocate((void **)&key2);
    parcMemory_Deallocate((void **)&value2);
    parcHashCodeTable_Del(table->symbolicNameTable, key1);
ERR_NAME:
    parcMemory_Deallocate((void **)&key1);
    parcMemory_Deallocate((void **)&value1);
END:
  return success;

}

unsigned symbolicNameTable_Get(SymbolicNameTable *table,
                               const char *symbolicName) {
  parcAssertNotNull(table, "Parameter table must be non-null");
  parcAssertNotNull(symbolicName, "Parameter symbolicName must be non-null");

  unsigned connid = UINT32_MAX;

  char *key = _createKey(symbolicName);

  uint32_t *value = parcHashCodeTable_Get(table->symbolicNameTable, key);
  if (value)
    connid = *value;

  parcMemory_Deallocate((void **)&key);
  return connid;
}

const char *symbolicNameTable_GetNameByIndex(SymbolicNameTable *table,
                                             unsigned id) {
  parcAssertNotNull(table, "Parameter table must be non-null");

  uint32_t *value = parcMemory_Allocate(sizeof(uint32_t));
  *value = id;

  const char *name = parcHashCodeTable_Get(table->indexToNameTable, value);
  if (name == NULL) name = "";

  parcMemory_Deallocate((void **)&value);
  return name;
}
