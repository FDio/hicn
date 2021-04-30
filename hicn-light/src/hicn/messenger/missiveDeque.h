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
 * @file missiveDeque
 * @brief Double ended queue of Missives
 *
 * Used to queue Missives.  This is a type-safe wrapper around {@link PARCDeque}
 *
 */

#ifndef missiveDeque_h
#define missiveDeque_h

struct missive_deque;

typedef struct missive_deque MissiveDeque;

/**
 * Create a `PARCDeque` instance with the default element equals function.
 *
 * The queue is created with no elements.
 *
 * The default element equals function is used by the `parcDeque_Equals`
 * function and simply compares the values using the `==` operator. Users that
 * need more sophisticated comparisons of the elements need to supply their own
 * function via the `parcDeque_CreateCustom` function.
 *
 * @return non-NULL A pointer to a PARCDeque instance.
 */
MissiveDeque *missiveDeque_Create(void);

void missiveDeque_Release(MissiveDeque **dequePtr);

/**
 * Appends the missive to the queue, taking ownership of the memory
 */
MissiveDeque *missiveDeque_Append(MissiveDeque *deque, Missive *missive);

Missive *missiveDeque_RemoveFirst(MissiveDeque *deque);

size_t missiveDeque_Size(const MissiveDeque *deque);
#endif  // missiveDeque_h
