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
 * A type-safe wrapper for Missives around a {@link PARCDeque}.  We only
 * implement the subset of functions used.
 *
 */

#include <parc/algol/parc_Deque.h>
#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/messenger/missive.h>
#include <hicn/messenger/missiveDeque.h>

struct missive_deque {
  PARCDeque *queue;
};

MissiveDeque *missiveDeque_Create(void) {
  MissiveDeque *missiveDeque =
      parcMemory_AllocateAndClear(sizeof(MissiveDeque));
  parcAssertNotNull(missiveDeque,
                    "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(MissiveDeque));
  missiveDeque->queue = parcDeque_Create();
  return missiveDeque;
}

void missiveDeque_Release(MissiveDeque **dequePtr) {
  parcAssertNotNull(dequePtr, "Double pointer must be non-null");
  parcAssertNotNull(*dequePtr, "Double pointer must dereference to non-null");
  MissiveDeque *missiveDeque = *dequePtr;

  // flush the queue
  while (!parcDeque_IsEmpty(missiveDeque->queue)) {
    Missive *missive = missiveDeque_RemoveFirst(missiveDeque);
    missive_Release(&missive);
  }

  parcDeque_Release(&missiveDeque->queue);
  parcMemory_Deallocate((void **)&missiveDeque);
  *dequePtr = NULL;
}

MissiveDeque *missiveDeque_Append(MissiveDeque *deque, Missive *missive) {
  parcAssertNotNull(deque, "Parameter deque must be non-null");
  parcAssertNotNull(missive, "Parameter missive must be non-null");

  parcDeque_Append(deque->queue, missive);
  return deque;
}

Missive *missiveDeque_RemoveFirst(MissiveDeque *deque) {
  parcAssertNotNull(deque, "Parameter deque must be non-null");
  return (Missive *)parcDeque_RemoveFirst(deque->queue);
}

size_t missiveDeque_Size(const MissiveDeque *deque) {
  parcAssertNotNull(deque, "Parameter deque must be non-null");
  return parcDeque_Size(deque->queue);
}
