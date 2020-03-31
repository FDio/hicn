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
#ifndef interface_h
#define interface_h

#include <hicn/base/address.h>

struct interface;
typedef struct interface Interface;

/**
 * Creates a representation of an interface
 *
 *   The name is copied.  Creates a representation of a system interface.
 *
 * @param <#param1#>
 * @return An allocated object, you must call <code>interfaceDestroy()</code>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
Interface *interfaceCreate(const char *name, unsigned interfaceIndex,
                           bool loopback, bool supportMulticast, unsigned mtu);

void interfaceDestroy(Interface **interfacePtr);

/**
 * Adds an address to an interface
 *
 *   Does not allow duplicates, if already exists is not added again
 *
 * @param <#param1#>
 * @return <#return#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
void interfaceAddAddress(Interface *iface, address_t *address);

/**
 * Retrieves a list of interface addresses
 *
 *   <#Discussion#>
 *
 * @param <#param1#>
 * @return Will not be NULL, but may be empty
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
const address_t ** interfaceGetAddresses(const Interface *iface);

/**
 * The interface index
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
unsigned interfaceGetInterfaceIndex(const Interface *iface);

/**
 * Returns the interface name, e.g. "eth0"
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] iface An allocated Interface
 *
 * @return non-null The interface Name as a C-string
 * @return null An error
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
const char *interfaceGetName(const Interface *iface);

/**
 * Returns the Maximum Transmission Unit (MTU) of the interface
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] iface An allocated Interface
 *
 * @return number The MTU as reported by the kernel
 *
 * Example:
 * @code
 * {
 *     <#example#>
 * }
 * @endcode
 */
unsigned interfaceGetMTU(const Interface *iface);

/**
 * Determine if two InterfaceName instances are equal.
 *
 *
 * The following equivalence relations on non-null `InterfaceName` instances are
 * maintained:
 *
 *  * It is reflexive: for any non-null reference value x,
 * `InterfaceName_Equals(x, x)` must return true.
 *
 *  * It is symmetric: for any non-null reference values x and y,
 *    `InterfaceName_Equals(x, y)` must return true if and only if
 *        `InterfaceName_Equals(y, x)` returns true.
 *
 *  * It is transitive: for any non-null reference values x, y, and z, if
 *        `InterfaceName_Equals(x, y)` returns true and
 *        `InterfaceName_Equals(y, z)` returns true,
 *        then  `InterfaceName_Equals(x, z)` must return true.
 *
 *  * It is consistent: for any non-null reference values x and y, multiple
 *      invocations of `InterfaceName_Equals(x, y)` consistently return true or
 *      consistently return false.
 *
 *  * For any non-null reference value x, `InterfaceName_Equals(x, NULL)` must
 *      return false.
 *
 * @param a A pointer to a `InterfaceName` instance.
 * @param b A pointer to a `InterfaceName` instance.
 * @return true if the two `InterfaceName` instances are equal.
 *
 * Example:
 * @code
 * {
 *    InterfaceName *a = InterfaceName_Create();
 *    InterfaceName *b = InterfaceName_Create();
 *
 *    if (InterfaceName_Equals(a, b)) {
 *        // true
 *    } else {
 *        // false
 *    }
 * }
 * @endcode
 */
bool interfaceNameEquals(const Interface *iface, const char *name);

/**
 * Two Interfaces are idential
 *
 *   All properties must be the same.  The order of addresses matters, and
 *   they must have been added to the address list in the same order.
 *
 *   The interface name match is case in-sensitive.
 *
 * @param <#param1#>
 * @return <#return#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
bool interfaceEquals(const Interface *a, const Interface *b);

/**
 * <#OneLineDescription#>
 *
 *   <#Discussion#>
 *
 * @param interface A Interface structure pointer.
 * @return An allocate string representation of the Interface that must be freed
 * via parcMemory_Deallocate().
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
char *interfaceToString(const Interface *interface);
#endif  // interface_h
