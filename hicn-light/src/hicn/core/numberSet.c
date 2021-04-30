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

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_Memory.h>
#include <hicn/hicn-light/config.h>
#include <hicn/core/numberSet.h>
#include <stdio.h>

#include <parc/assert/parc_Assert.h>

struct number_set {
  Number *arrayOfNumbers;
  size_t length;
  size_t limit;
  unsigned refcount;
};

static void numberSet_Expand(NumberSet *set);

NumberSet *numberSet_Create() {
  NumberSet *set = parcMemory_AllocateAndClear(sizeof(NumberSet));
  parcAssertNotNull(set, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(NumberSet));
  set->arrayOfNumbers = parcMemory_AllocateAndClear(sizeof(Number) * 16);
  parcAssertNotNull((set->arrayOfNumbers),
                    "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Number) * 16);
  set->length = 0;
  set->limit = 16;
  set->refcount = 1;
  return set;
}

NumberSet *numberSet_Acquire(const NumberSet *original) {
  parcAssertNotNull(original, "Parameter original must be non-null");
  NumberSet *copy = (NumberSet *)original;
  copy->refcount++;
  return copy;
}

void numberSet_Release(NumberSet **setPtr) {
  parcAssertNotNull(setPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*setPtr, "Parameter must dereference to non-null pointer");

  NumberSet *set = *setPtr;
  parcAssertTrue(
      set->refcount > 0,
      "Invalid state: calling destroy on an object with 0 reference count");
  set->refcount--;

  if (set->refcount == 0) {
    parcMemory_Deallocate((void **)&(set->arrayOfNumbers));
    parcMemory_Deallocate((void **)&set);
    *setPtr = NULL;
  }
}

/**
 * @function numberSet_AddNoChecks
 * @abstract Add a number we know is not already in the set
 * @discussion
 *   Used by other functions that already know the number is unique in the set,
 *   Does not do the expensive Contains check.
 */
static void numberSet_AddNoChecks(NumberSet *set, Number number) {
  if (set->length == set->limit) {
    numberSet_Expand(set);
  }

  set->arrayOfNumbers[set->length] = number;
  set->length++;
}

bool numberSet_Add(NumberSet *set, Number number) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  if (numberSet_Contains(set, number)) {
    return false;
  }

  numberSet_AddNoChecks(set, number);
  return true;
}

size_t numberSet_Length(const NumberSet *set) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  return set->length;
}

Number numberSet_GetItem(const NumberSet *set, size_t ordinalIndex) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  parcAssertTrue(ordinalIndex < set->length,
                 "Limit beyond end of set, length %zu got %zu", set->length,
                 ordinalIndex);

  return set->arrayOfNumbers[ordinalIndex];
}

bool numberSet_Contains(const NumberSet *set, Number number) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  for (size_t i = 0; i < set->length; i++) {
    if (set->arrayOfNumbers[i] == number) {
      return true;
    }
  }
  return false;
}

void numberSet_AddSet(NumberSet *destinationSet, const NumberSet *setToAdd) {
  parcAssertNotNull(destinationSet,
                    "Parameter destinationSet must be non-null");
  parcAssertNotNull(setToAdd, "Parameter setToAdd must be non-null");

  for (size_t i = 0; i < setToAdd->length; i++) {
    numberSet_Add(destinationSet, setToAdd->arrayOfNumbers[i]);
  }
}

NumberSet *numberSet_Subtract(const NumberSet *minuend,
                              const NumberSet *subtrahend) {
  // because the underlying ADT is not sorted, this is pretty ineffient, could
  // be O(n^2).

  NumberSet *difference = numberSet_Create();

  for (size_t i = 0; i < minuend->length; i++) {
    bool unique = true;
    for (size_t j = 0; j < subtrahend->length && unique; j++) {
      if (minuend->arrayOfNumbers[i] == subtrahend->arrayOfNumbers[j]) {
        unique = false;
      }
    }

    if (unique) {
      numberSet_AddNoChecks(difference, minuend->arrayOfNumbers[i]);
    }
  }
  return difference;
}

bool numberSet_Equals(const NumberSet *a, const NumberSet *b) {
  if (a == NULL && b == NULL) {
    return true;
  }

  if (a == NULL || b == NULL) {
    return false;
  }

  if (a->length == b->length) {
    for (size_t i = 0; i < a->length; i++) {
      bool found = false;
      for (size_t j = 0; j < b->length && !found; j++) {
        if (a->arrayOfNumbers[i] == b->arrayOfNumbers[j]) {
          found = true;
        }
      }
      if (!found) {
        return false;
      }
    }
    return true;
  }

  return false;
}

void numberSet_Remove(NumberSet *set, Number number) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  for (size_t i = 0; i < set->length; i++) {
    if (set->arrayOfNumbers[i] == number) {
      set->length--;
      if (set->length > 0) {
        // move the last element to the removed element to keep the array
        // packed.
        set->arrayOfNumbers[i] = set->arrayOfNumbers[set->length];
      }
      return;
    }
  }
}

// =====================================================

static void numberSet_Expand(NumberSet *set) {
  size_t newlimit = set->limit * 2;
  size_t newbytes = newlimit * sizeof(Number);

  set->arrayOfNumbers = parcMemory_Reallocate(set->arrayOfNumbers, newbytes);
  set->limit = newlimit;
}
