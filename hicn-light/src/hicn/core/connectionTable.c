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
 * @header ConnectionTable
 * @abstract Records all the current connections and references to them
 * @discussion
 *
 */

#ifndef _WIN32
#include <unistd.h>
#endif
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_HashCodeTable.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_TreeRedBlack.h>
#include <hicn/core/connectionTable.h>
#include <hicn/io/addressPair.h>

struct connection_table {
  // The main storage table that has a Destroy method.
  // The key is an unsigned int pointer.  We use an unsigned int pointer
  // because we want to be able to lookup by the id alone, and not have to
  // have the IoOperations everywhere.
  PARCHashCodeTable *storageTableById;

  // The key is a AddressPair
  // It does not have a destroy method for the data or key,
  // as they are derived from the storage table.
  PARCHashCodeTable *indexByAddressPair;

  // An iterable stucture organized by connection id.  The keys and
  // values are the same pointers as in storageTableById, so there
  // are no destructors in the tree.
  // The only reason to keep this tree is so we have an iterable list
  // of connections, which the hash table does not give us.
  PARCTreeRedBlack *listById;
};

static bool connectionTable_ConnectionIdEquals(const void *keyA,
                                               const void *keyB) {
  unsigned idA = *((unsigned *)keyA);
  unsigned idB = *((unsigned *)keyB);
  return (idA == idB);
}

static int connectionTable_ConnectionIdCompare(const void *keyA,
                                               const void *keyB) {
  unsigned idA = *((unsigned *)keyA);
  unsigned idB = *((unsigned *)keyB);
  if (idA < idB) {
    return -1;
  }
  if (idA > idB) {
    return +1;
  }
  return 0;
}

static bool connectionTable_AddressPairEquals(const void *keyA,
                                              const void *keyB) {
  const AddressPair *pairA = (const AddressPair *)keyA;
  const AddressPair *pairB = (const AddressPair *)keyB;

  return addressPair_Equals(pairA, pairB);
}

static HashCodeType connectionTable_ConnectionIdHashCode(const void *keyA) {
  unsigned idA = *((unsigned *)keyA);
  return parcHash32_Int32(idA);
}

static HashCodeType connectionTable_AddressPairHashCode(const void *keyA) {
  const AddressPair *pairA = (const AddressPair *)keyA;
  return addressPair_HashCode(pairA);
}

static void connectionTable_ConnectionIdDestroyer(void **dataPtr) {
  unsigned *idA = (unsigned *)*dataPtr;
  parcMemory_Deallocate((void **)&idA);
  *dataPtr = NULL;
}

static void connectionTable_ConnectionDestroyer(void **dataPtr) {
  connection_Release((Connection **)dataPtr);
}

ConnectionTable *connectionTable_Create() {
  size_t initialSize = 16384;

  ConnectionTable *conntable =
      parcMemory_AllocateAndClear(sizeof(ConnectionTable));
  parcAssertNotNull(conntable, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ConnectionTable));

  conntable->storageTableById = parcHashCodeTable_Create_Size(
      connectionTable_ConnectionIdEquals, connectionTable_ConnectionIdHashCode,
      connectionTable_ConnectionIdDestroyer,
      connectionTable_ConnectionDestroyer, initialSize);

  // no key or data destroyer, this is an index into storageByid.
  conntable->indexByAddressPair = parcHashCodeTable_Create_Size(
      connectionTable_AddressPairEquals, connectionTable_AddressPairHashCode,
      NULL, NULL, initialSize);

  conntable->listById =
      parcTreeRedBlack_Create(connectionTable_ConnectionIdCompare,
                              NULL,   // key free
                              NULL,   // key copy
                              NULL,   // value equals
                              NULL,   // value free
                              NULL);  // value copy

  return conntable;
}

void connectionTable_Destroy(ConnectionTable **conntablePtr) {
  parcAssertNotNull(conntablePtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*conntablePtr,
                    "Parameter must dereference to non-null pointer");

  ConnectionTable *conntable = *conntablePtr;

  parcTreeRedBlack_Destroy(&conntable->listById);
  parcHashCodeTable_Destroy(&conntable->indexByAddressPair);
  parcHashCodeTable_Destroy(&conntable->storageTableById);
  parcMemory_Deallocate((void **)&conntable);
  *conntablePtr = NULL;
}

/**
 * @function connectionTable_Add
 * @abstract Add a connection, takes ownership of memory
 */
void connectionTable_Add(ConnectionTable *table, Connection *connection) {
  parcAssertNotNull(table, "Parameter table must be non-null");
  parcAssertNotNull(connection, "Parameter connection must be non-null");

  unsigned *connectionIdKey = parcMemory_Allocate(sizeof(unsigned));
  parcAssertNotNull(connectionIdKey, "parcMemory_Allocate(%zu) returned NULL",
                    sizeof(unsigned));
  *connectionIdKey = connection_GetConnectionId(connection);

  if (parcHashCodeTable_Add(table->storageTableById, connectionIdKey,
                            connection)) {
    parcHashCodeTable_Add(table->indexByAddressPair,
                          (void *)connection_GetAddressPair(connection),
                          connection);
    parcTreeRedBlack_Insert(table->listById, connectionIdKey, connection);
  } else {
    parcTrapUnexpectedState(
        "Could not add connection id %u -- is it a duplicate?",
        *connectionIdKey);
  }
}

/**
 * @function connectionTable_Remove
 * @abstract Removes the connection, calling Destroy on our copy
 */
void connectionTable_Remove(ConnectionTable *table,
                            const Connection *connection) {
  parcAssertNotNull(table, "Parameter table must be non-null");
  parcAssertNotNull(connection, "Parameter connection must be non-null");

  unsigned connid = connection_GetConnectionId(connection);

  parcTreeRedBlack_Remove(table->listById, &connid);
  parcHashCodeTable_Del(table->indexByAddressPair,
                        connection_GetAddressPair(connection));
  parcHashCodeTable_Del(table->storageTableById, &connid);
}

void connectionTable_RemoveById(ConnectionTable *table, unsigned id) {
  parcAssertNotNull(table, "Parameter table must be non-null");
  const Connection *connection = connectionTable_FindById(table, id);
  if (connection) {
    connectionTable_Remove(table, connection);
  }
}

const Connection *connectionTable_FindByAddressPair(ConnectionTable *table,
                                                    const AddressPair *pair) {
  parcAssertNotNull(table, "Parameter table must be non-null");
  return (Connection *)parcHashCodeTable_Get(table->indexByAddressPair, pair);
}

const Connection *connectionTable_FindById(const ConnectionTable *table,
                                           unsigned id) {
  parcAssertNotNull(table, "Parameter table must be non-null");
  return (Connection *)parcHashCodeTable_Get(table->storageTableById, &id);
}

ConnectionList *connectionTable_GetEntries(const ConnectionTable *table) {
  parcAssertNotNull(table, "Parameter table must be non-null");
  ConnectionList *list = connectionList_Create();

  PARCArrayList *values = parcTreeRedBlack_Values(table->listById);
  for (size_t i = 0; i < parcArrayList_Size(values); i++) {
    Connection *original = parcArrayList_Get(values, i);
    connectionList_Append(list, original);
  }
  parcArrayList_Destroy(&values);
  return list;
}
