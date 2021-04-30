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
#ifndef fib_h
#define fib_h

#include <hicn/core/message.h>
#include <hicn/core/name.h>
#include <hicn/processor/fibEntry.h>
#include <hicn/processor/fibEntryList.h>

struct fib;
typedef struct fib FIB;

FIB *fib_Create(Forwarder *forwarder);

void fib_Destroy(FIB **fibPtr);

void fib_Add(FIB *fib, FibEntry *node);

FibEntry *fib_Contains(const FIB *fib, const Name *prefix);

void fib_Remove(FIB *fib, const Name *prefix, unsigned connId);

void fib_RemoveConnectionId(FIB *fib, unsigned connectionId);

FibEntry *fib_MatchMessage(const FIB *fib, const Message *interestMessage);
FibEntry *fib_MatchName(const FIB *fib, const Name *name);
FibEntry *fib_MatchBitvector(const FIB *fib, const NameBitvector *name);

size_t fib_Length(const FIB *fib);

FibEntryList *fib_GetEntries(const FIB *fib);
#endif  // fib_h
