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
 * @brief <#Brief Description#>
 *
 * <#Detailed Description#>
 *
 */
#ifndef InterfaceSet_h
#define InterfaceSet_h

#include <hicn/utils/interface.h>

struct interfaceSet;
/**
 *
 * @see interfaceSetCreate
 */
typedef struct interfaceSet InterfaceSet;

/**
 * <#One Line Description#>
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * @return <#value#> <#explanation#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 *
 * @see <#references#>
 */
InterfaceSet *interfaceSetCreate(void);

/**
 * <#One Line Description#>
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * @return <#value#> <#explanation#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 *
 * @see <#references#>
 */
void interfaceSetDestroy(InterfaceSet **setPtr);

/**
 * Adds interface to set, does not allow duplicates
 *
 *   Takes ownership of the iface memory if added
 *
 *   Duplicates are two entries with the same interface index
 *
 * @param <#param1#>
 * @return true if added, false if not (likely a duplicate)
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
bool interfaceSetAdd(InterfaceSet *set, Interface *iface);

/**
 * The number of interfaces in the set
 *
 *   <#Discussion#>
 *
 * @param <#param1#>
 * @return <#return#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
size_t interfaceSetLength(const InterfaceSet *set);

/**
 * Uses the ordinal index of the interface in the Set
 *
 *   Ranges from 0 .. <code>interfaceSetLength()-1</code>.
 *
 * @param <#param1#>
 * @return NULL if not found
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
Interface *interfaceSetGetByOrdinalIndex(InterfaceSet *set,
                                         size_t ordinalIndex);

/**
 * Retreives by the assigned interface index
 *
 *   <#Discussion#>
 *
 * @param <#param1#>
 * @return NULL if not found
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
Interface *interfaceSetGetByInterfaceIndex(const InterfaceSet *set,
                                           unsigned interfaceIndex);

/**
 * Uses the system name (e.g. "en0")
 *
 *   <#Discussion#>
 *
 * @param <#param1#>
 * @return NULL if not found
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
Interface *interfaceSetGetByName(InterfaceSet *set, const char *name);

/**
 * Determine if two InterfaceSet instances are equal.
 *
 * Two InterfaceSet instances are equal if, and only if, the sets contain the
 * same elements
 * - order independent.
 * Each element is compared via <code>interfaceEquals()</code>
 *
 * The following equivalence relations on non-null `InterfaceSet` instances are
 * maintained:
 *
 *  * It is reflexive: for any non-null reference value x,
 * `InterfaceSet_Equals(x, x)` must return true.
 *
 *  * It is symmetric: for any non-null reference values x and y,
 *    `InterfaceSet_Equals(x, y)` must return true if and only if
 *        `interfaceSetEquals(y, x)` returns true.
 *
 *  * It is transitive: for any non-null reference values x, y, and z, if
 *        `interfaceSetEquals(x, y)` returns true and
 *        `interfaceSetEquals(y, z)` returns true,
 *        then  `interfaceSetEquals(x, z)` must return true.
 *
 *  * It is consistent: for any non-null reference values x and y, multiple
 *      invocations of `interfaceSetEquals(x, y)` consistently return true or
 *      consistently return false.
 *
 *  * For any non-null reference value x, `interfaceSetEquals(x, NULL)` must
 *      return false.
 *
 * @param a A pointer to a `InterfaceSet` instance.
 * @param b A pointer to a `InterfaceSet` instance.
 * @return true if the two `InterfaceSet` instances are equal.
 *
 * Example:
 * @code
 * {
 *    InterfaceSet *a = interfaceSetCreate();
 *    InterfaceSet *b = interfaceSetCreate();
 *
 *    if (interfaceSetEquals(a, b)) {
 *        // true
 *    } else {
 *        // false
 *    }
 * }
 * @endcode
 */
bool interfaceSetEquals(const InterfaceSet *a, const InterfaceSet *b);
#endif  // InterfaceSet_h
