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
 * @brief A list of Address instances.
 *
 * An AddressList is a list of addresses.
 * It wraps a PARCLinkedList for type saftey with Address.
 *
 */
#ifndef address_list_h
#define address_list_h

#include <hicn/utils/address.h>

struct address_list;
/**
 * @typedef AddressList
 * @abstract A list of Address instance pointers.
 */
typedef struct address_list AddressList;

/**
 * Create an instance of {@link AddressList}
 *
 * @return NULL An error occurred
 * @return non-NULL A pointer to a valid AddressList instance.
 *
 * Example:
 * @code
 * {
 *     AddressList *list = addressListCreate();
 *
 * }
 * @endcode
 *
 * @see addressListDestroy
 */
AddressList *addressListCreate(void);

/**
 * Dellocate and destroy a AddressList instance.
 *
 * @param [in] addressListPtr A pointer to a pointer to a valid {@link
 * AddressList}.
 *
 *
 * Example:
 * @code
 * {
 *     AddressList *list = addressListCreate(void);
 *     addressListDestroy(&list);
 * }
 * @endcode
 *
 * @see addressListCreate
 */
void addressListDestroy(AddressList **addressListPtr);

/**
 * Appends the address, taking ownership of the memory
 *
 * @param list A pointer to a AddressList.
 * @param address must be non-null
 * @return The input list
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
AddressList *addressListAppend(AddressList *list, Address *address);

/**
 * Creates a reference counted copy
 *
 * @param list A pointer to a valid {@link AddressList}.
 *
 * @return An allocated list, you must destroy it.
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
AddressList *addressListCopy(const AddressList *list);

/**
 * Determine if two AddressList instances are equal.
 *
 * Two AddressList instances are equal if, and only if, they have the same
 * length, with the same elements in the same order.
 *
 *
 * The following equivalence relations on non-null `AddressList` instances are
 * maintained:
 *
 *  * It is reflexive: for any non-null reference value x,
 * `AddressList_Equals(x, x)` must return true.
 *
 *  * It is symmetric: for any non-null reference values x and y,
 *    `AddressList_Equals(x, y)` must return true if and only if
 *        `addressListEquals(y, x)` returns true.
 *
 *  * It is transitive: for any non-null reference values x, y, and z, if
 *        `addressListEquals(x, y)` returns true and
 *        `addressListEquals(y, z)` returns true,
 *        then  `addressListEquals(x, z)` must return true.
 *
 *  * It is consistent: for any non-null reference values x and y, multiple
 *      invocations of `addressListEquals(x, y)` consistently return true or
 *      consistently return false.
 *
 *  * For any non-null reference value x, `addressListEquals(x, NULL)` must
 *      return false.
 *
 * @param a A pointer to a `AddressList` instance.
 * @param b A pointer to a `AddressList` instance.
 * @return true if the two `AddressList` instances are equal.
 *
 * Example:
 * @code
 * {
 *    AddressList *a = addressListCreate();
 *    AddressList *b = addressListCreate();
 *
 *    if (addressListEquals(a, b)) {
 *        // true
 *    } else {
 *        // false
 *    }
 * }
 * @endcode
 */
bool addressListEquals(const AddressList *a, const AddressList *b);

/**
 * Get the number of items in the list
 *
 * @param list A pointer to a {@link AddressList}.
 * @return The number of items in the list.
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
size_t addressListLength(const AddressList *list);

/**
 * Returns a const reference to an item.
 * Use addressCopy if needed.
 *
 * Do not free or modify the returned value.
 * Use addressCopy if you   need a mutable instance.
 *
 * @param list A pointer to a AddressList.
 * @param item A value less than the number of items in the given {@link
 * AddressList}.
 * @return Asserts if item off end of list.
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
const Address *addressListGetItem(const AddressList *list, size_t item);

/**
 * Get a nul-terminated, C-string representation of the given {@link
 * AddressList}.
 *
 * @param list A pointer to a valid {@link AddressList} instance.
 *
 * @return An allocate string representation of the {@link AddressList} that
 * must be freed via `parcMemory_Deallocate()`.
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
char *addressListToString(const AddressList *list);
#endif  // address_list_h
