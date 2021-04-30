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
 * @file symbolicNameTable.h
 * @brief The symbolic name table maps a string name to a connection id
 *
 * When configuring tunnels/connections, the user provides a string name
 * (symbolic name) that they will use to refer to that connection.  The symblic
 * name table translates that symbolic name to a connection id.
 *
 */

#ifndef symbolicNameTable_h
#define symbolicNameTable_h

struct symblic_name_table;
typedef struct symblic_name_table SymbolicNameTable;

#include <stdbool.h>

/**
 * Creates a symbolic name table
 *
 * Allocates a SymbolicNameTable, which will store the symbolic names
 * in a hash table.
 *
 * @retval non-null An allocated SymbolicNameTable
 * @retval null An error
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
SymbolicNameTable *symbolicNameTable_Create(void);

/**
 * Destroys a name table
 *
 * All keys and data are released.
 *
 * @param [in,out] tablePtr A pointer to a SymbolicNameTable, which will be
 * NULL'd
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
void symbolicNameTable_Destroy(SymbolicNameTable **tablePtr);

/**
 * Checks if the name (case insensitive) is in the table
 *
 * Does a case-insensitive match to see if the name is in the table
 *
 * @param [in] table An allocated SymbolicNameTable
 * @param [in] symbolicName The name to check for
 *
 * @retval true The name is in the table
 * @retval false The name is not in the talbe
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
bool symbolicNameTable_Exists(SymbolicNameTable *table,
                              const char *symbolicName);

/**
 * Adds a (name, connid) pair to the table.
 *
 * The name is stored case insensitive.  The value UINT_MAX is used to indicate
 * a non-existent key, so it should not be stored as a value in the table.
 *
 * @param [in] table An allocated SymbolicNameTable
 * @param [in] symbolicName The name to save (will make a copy)
 * @param [in] connid The connection id to associate with the name
 *
 * @retval true The pair was added
 * @retval false The pair was not added (likely duplicate key)
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
bool symbolicNameTable_Add(SymbolicNameTable *table, const char *symbolicName,
                           unsigned connid);

/**
 * Returns the connection id associated with the symbolic name
 *
 * This function will look for the given name (case insensitive) and return the
 * corresponding connid.  If the name is not in the table, the function will
 * return UINT_MAX.
 *
 * @param [in] table An allocated SymbolicNameTable
 * @param [in] symbolicName The name to retrieve
 *
 * @retval UINT_MAX symbolicName not found
 * @retval number the corresponding connid.
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
unsigned symbolicNameTable_Get(SymbolicNameTable *table,
                               const char *symbolicName);

void symbolicNameTable_Remove(SymbolicNameTable *table,
                              const char *symbolicName);
const char *symbolicNameTable_GetNameByIndex(SymbolicNameTable *table,
                                             unsigned id);

#endif /* defined(symbolicNameTable_h) */
