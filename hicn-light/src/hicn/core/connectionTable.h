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
 */

#ifndef connectionTable_h
#define connectionTable_h

#include <hicn/core/connection.h>
#include <hicn/core/connectionList.h>
#include <hicn/io/addressPair.h>
#include <hicn/io/ioOperations.h>

struct connection_table;
typedef struct connection_table ConnectionTable;

/**
 * Creates an empty connection table
 */
ConnectionTable *connectionTable_Create(void);

/**
 * Destroys the connection table
 * This will release the reference to all connections stored in the connection
 * table.
 * @param [in,out] conntablePtr Pointer to the allocated connection table, will
 * be NULL'd
 */
void connectionTable_Destroy(ConnectionTable **conntablePtr);

/**
 * @function connectionTable_Add
 * @abstract Add a connection, takes ownership of memory
 */
void connectionTable_Add(ConnectionTable *table, Connection *connection);

/**
 * @function connectionTable_Remove
 * @abstract Removes the connection, calling Destroy on our copy
 */
void connectionTable_Remove(ConnectionTable *table,
                            const Connection *connection);

/**
 * Removes a connection from the connection table
 *
 * Looks up a connection by its connection ID and removes it from the connection
 * table. Removing the connection will call connection_Release() on the
 * connection object.
 *
 * @param [in] table The allocated connection table
 * @param [in] id The connection ID
 */
void connectionTable_RemoveById(ConnectionTable *table, unsigned id);

/**
 * Lookup a connection by the (local, remote) addres pair
 *
 * @param [in] table The allocated connection table
 * @param [in] pair The address pair to match, based on the inner values of the
 * local and remote addresses
 *
 * @retval non-null The matched conneciton
 * @retval null No match found or error
 */
const Connection *connectionTable_FindByAddressPair(ConnectionTable *table,
                                                    const AddressPair *pair);

/**
 * @function connectionTable_FindById
 * @abstract Find a connection by its numeric id.
 * @return NULL if not found
 */
const Connection *connectionTable_FindById(const ConnectionTable *table, unsigned id);

/**
 * @function connectionTable_GetEntries
 * @abstract Returns a list of connections.  They are reference counted copies
 * from the table.
 * @discussion
 *   An allocated list of connections in the table.  Each list entry is a
 * reference counted copy of the connection in the table, thus they are "live"
 * objects.
 */
ConnectionList *connectionTable_GetEntries(const ConnectionTable *table);
#endif  // connectionTable_h
