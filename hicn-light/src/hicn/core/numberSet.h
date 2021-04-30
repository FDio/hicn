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
 * @brief Stores a set of numbers.
 *
 * Useful for things like the reverse path of a PIT
 * or the forward paths of a FIB.  Does not allow duplicates.
 *
 */

#ifndef numberSet_h
#define numberSet_h

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct number_set;
typedef struct number_set NumberSet;

typedef uint32_t Number;

/**
 * @function numberList_Create
 * @abstract A new list of numbers
 */
NumberSet *numberSet_Create(void);

/**
 * Obtains a reference counted copy of the original
 * The reference count is increased by one.  It must be released with
 * NumberSet_Release().
 * @param [in] original An allocated NumberSet
 * @return non-null The reference counted copy
 */
NumberSet *numberSet_Acquire(const NumberSet *original);

/**
 * Releases one reference count and destroys the memory after last release
 * The pointer will be NULLed after release regardless if the memory was
 * destroyed.
 * @param [in,out] setPtr A pointer to a NumberSet.  Will be NULL'd after
 * release.
 */
void numberSet_Release(NumberSet **setPtr);

/**
 * @function numberList_Append
 * @abstract Add a number to the end of the list
 * @discussion
 *   No check for duplicates is done
 * @return true if added, false if a duplicate
 */
bool numberSet_Add(NumberSet *set, Number number);

/**
 * @function numberList_Length
 * @abstract The count of numbers in the list
 */
size_t numberSet_Length(const NumberSet *set);

/**
 * @function numberSet_GetItem
 * @abstract Retrieves an item based on the ordinal index
 * @discussion
 *   Will assert if the ordinalIndex is out of bounds.
 */
Number numberSet_GetItem(const NumberSet *set, size_t ordinalIndex);

/**
 * @function numberSet_Contains
 * @abstract Checks for set membership
 * @return true if the set contains the number, false otherwise
 */
bool numberSet_Contains(const NumberSet *set, Number number);

/**
 * @function numberSet_AddSet
 * @abstract Adds one set to another set
 * @discussion
 *   Adds <code>setToAdd</code> to <code>destinationSet</code>
 * @return true if the set contains the number, false otherwise
 */
void numberSet_AddSet(NumberSet *destinationSet, const NumberSet *setToAdd);

/**
 * @function numberSet_Subtract
 * @abstract Computes set difference <code>difference = minuend -
 * subtrahend</code>, returns a new number set.
 * @discussion
 *   <code>minuend</code> and <code>subtrahend</code> are not modified.  A new
 * difference set is created.
 *
 *   Returns the elements in <code>minuend</code> that are not in
 * <code>subtrahend</code>.
 *
 * @param minuend The set from which to subtract
 * @param subrahend The set begin removed from minuend
 * @return The set difference.  May be empty, but will not be NULL.
 */
NumberSet *numberSet_Subtract(const NumberSet *minuend,
                              const NumberSet *subtrahend);

/**
 * Determine if two NumberSet instances are equal.
 *
 * Two NumberSet instances are equal if, and only if,
 *   they are the same size and contain the same elements.  Empty sets are
 * equal. NULL equals NULL, but does not equal non-NULL.
 *
 * The following equivalence relations on non-null `NumberSet` instances are
 * maintained:
 *
 *  * It is reflexive: for any non-null reference value x, `NumberSet_Equals(x,
 * x)` must return true.
 *
 *  * It is symmetric: for any non-null reference values x and y,
 *    `numberSet_Equals(x, y)` must return true if and only if
 *        `numberSet_Equals(y, x)` returns true.
 *
 *  * It is transitive: for any non-null reference values x, y, and z, if
 *        `numberSet_Equals(x, y)` returns true and
 *        `numberSet_Equals(y, z)` returns true,
 *        then  `numberSet_Equals(x, z)` must return true.
 *
 *  * It is consistent: for any non-null reference values x and y, multiple
 *      invocations of `numberSet_Equals(x, y)` consistently return true or
 *      consistently return false.
 *
 *  * For any non-null reference value x, `numberSet_Equals(x, NULL)` must
 *      return false.
 *
 * @param a A pointer to a `NumberSet` instance.
 * @param b A pointer to a `NumberSet` instance.
 * @return true if the two `NumberSet` instances are equal.
 */
bool numberSet_Equals(const NumberSet *a, const NumberSet *b);

/**
 * @function numberSet_Remove
 * @abstract Removes the number from the set
 */
void numberSet_Remove(NumberSet *set, Number number);
#endif  // numberSet_h
