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

#include <src/core/message.h>
#include <src/core/name.h>
#include <src/processor/fibEntry.h>
#include <src/processor/fibEntryList.h>

struct fib;
typedef struct fib FIB;


FIB *fIB_Create();

void fIB_Destroy(FIB **fibPtr);

void fIB_Add(FIB *fib, FibEntry *node);

FibEntry * fIB_Contains(const FIB *fib, const Name *prefix);

void fIB_Remove(FIB *fib, const Name *prefix, unsigned connId);

void fIB_RemoveConnectionId(FIB *fib, unsigned connectionId);

FibEntry *fIB_Match(const FIB *fib, const Message *interestMessage);

size_t fIB_Length(const FIB *fib);

FibEntryList *fIB_GetEntries(const FIB *fib);
#endif // fib_h
