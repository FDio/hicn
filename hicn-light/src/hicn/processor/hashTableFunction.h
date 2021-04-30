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
 * @file hashTableFunction.h
 * @brief These functions are used in PARCHashCodeTables by the
 * MatchingRulesTable and ContentStore and PIT. They perform the equality
 * and has generation needed by the PARCHashCodeTable.
 *
 */
#ifndef hashTableFunction_h
#define hashTableFunction_h

#include <parc/algol/parc_HashCodeTable.h>

// ==========================================================
// These functions operate on a message as the key in the HashTable.
// The functions use void * rather than message instances in the function
// signature because it is using generic has code tables from PARC Library

/**
 * Determine if the Names of two `message` instances are equal.
 *
 * The following equivalence relations on non-null `message` instances are
 * maintained:
 *
 *  * It is reflexive: for any non-null reference value x,
 * `hashTableFunction_MessageNameEquals(x, x)` must return true.
 *
 *  * It is symmetric: for any non-null reference values x and y,
 *    `message_Equals(x, y)` must return true if and only if
 *        `hashTableFunction_MessageNameEquals(y, x)` returns true.
 *
 *  * It is transitive: for any non-null reference values x, y, and z, if
 *        `hashTableFunction_MessageNameEquals(x, y)` returns true and
 *        `hashTableFunction_MessageNameEquals(y, z)` returns true,
 *        then  `hashTableFunction_MessageNameEquals(x, z)` must return true.
 *
 *  * It is consistent: for any non-null reference values x and y, multiple
 *      invocations of `hashTableFunction_MessageNameEquals(x, y)` consistently
 * return true or consistently return false.
 *
 *  * For any non-null reference value x,
 * `hashTableFunction_MessageNameEquals(x, NULL)` must return false.
 *
 * @param a A pointer to a `message` instance.
 * @param b A pointer to a `message` instance.
 * @return true if the names of the two `message` instances are equal.
 */
bool hashTableFunction_MessageNameEquals(const void *messageA,
                                         const void *messageB);

/**
 * @function hashTableFunction_NameHashCode
 * @abstract Computes the hash of the entire name in a message
 *
 * @param messageA is a message
 * @return A non-cryptographic hash of Name
 */
HashCodeType hashTableFunction_MessageNameHashCode(const void *messageA);
#endif  // hashTableFunction_h