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
 * Used to identify a connection between a specific local address and
 * a specific remote address.
 */

#ifndef address_Pair_h
#define address_Pair_h

#include <hicn/utils/address.h>

struct address_pair;
typedef struct address_pair AddressPair;

/**
 * @function addressPair_Create
 * @abstract Creates and address pair.  There is no restriction on the address
 * types.
 * @discussion
 *   Creates an ordered pair of addresses, where the first is considered the
 * "local" address and the second is the "remote" address.  Those designations
 * are purely a convention used to name them, and does not imply any specifici
 * types of operations.
 *
 *   The two addresses may be of any address types (e.g. IPv4, IPv6, Local,
 * Ethernet). However, some functions that use an AddressPair may require that
 * the local and remote addresses be the same type.
 *
 */
AddressPair *addressPair_Create(const Address *local, const Address *remote);

/**
 * Returns a reference counted copy of the address pair
 *
 * Increments the reference count and returns the same address pair
 *
 * @param [in] addressPair An allocated address pair
 *
 * @retval non-null A reference counted copy
 * @retval null An error
 */
AddressPair *addressPair_Acquire(const AddressPair *addressPair);

/**
 * Releases a reference count to the object
 *
 * Decrements the reference count and destroys the object when it reaches 0.
 */
void addressPair_Release(AddressPair **pairPtr);

/**
 * Determine if two AddressPair instances are equal.
 *
 * Two AddressPair instances are equal if, and only if, the local and remote
 * addresses are identical. Equality is determined by addressEquals(a->local,
 * b->local) and Adress_Equals(a->remote, b->remote).
 *
 * The following equivalence relations on non-null `AddressPair` instances are
 * maintained:
 *
 *  * It is reflexive: for any non-null reference value x,
 * `AddressPair_Equals(x, x)` must return true.
 *
 *  * It is symmetric: for any non-null reference values x and y,
 *    `addressPair_Equals(x, y)` must return true if and only if
 *        `addressPair_Equals(y, x)` returns true.
 *
 *  * It is transitive: for any non-null reference values x, y, and z, if
 *        `addressPair_Equals(x, y)` returns true and
 *        `addressPair_Equals(y, z)` returns true,
 *        then  `addressPair_Equals(x, z)` must return true.
 *
 *  * It is consistent: for any non-null reference values x and y, multiple
 *      invocations of `addressPair_Equals(x, y)` consistently return true or
 *      consistently return false.
 *
 *  * For any non-null reference value x, `addressPair_Equals(x, NULL)` must
 *      return false.
 *
 * @param a A pointer to a `AddressPair` instance.
 * @param b A pointer to a `AddressPair` instance.
 * @return true if the two `AddressPair` instances are equal.
 */
bool addressPair_Equals(const AddressPair *a, const AddressPair *b);

/**
 * @function addressPair_EqualsAddresses
 * @abstract As AddressEquals, but "b" is broken out
 * @discussion
 *   Equality is determined by addressEquals(a->local, local) and
 *   Adress_Equals(a->remote, remote).
 */
bool addressPair_EqualsAddresses(const AddressPair *a, const Address *local,
                                 const Address *remote);

const Address *addressPair_GetLocal(const AddressPair *pair);

const Address *addressPair_GetRemote(const AddressPair *pair);

/**
 * @function addressPair_HashCode
 * @abstract Hash useful for tables.  Consistent with Equals.
 * @discussion
 *   Returns a non-cryptographic hash that is consistent with equals.  That is,
 *   if a == b, then hash(a) == hash(b).
 */
PARCHashCode addressPair_HashCode(const AddressPair *pair);

/**
 * @function addressPair_ToString
 * @abstract Human readable string representation.  Caller must use free(3).
 */
char *addressPair_ToString(const AddressPair *pair);
#endif  // address_Pair_h
