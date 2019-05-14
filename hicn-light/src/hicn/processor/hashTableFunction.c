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

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_Memory.h>

#include <hicn/core/message.h>
#include <hicn/processor/hashTableFunction.h>

#include <parc/assert/parc_Assert.h>

// ======================================================================
// Hash table key functions
// We use a Message as the key data type

bool hashTableFunction_MessageNameEquals(const void *messageA,
                                         const void *messageB) {
  const Message *a = (const Message *)messageA;
  const Message *b = (const Message *)messageB;

  return name_Equals(message_GetName(a), message_GetName(b));
}

HashCodeType hashTableFunction_MessageNameHashCode(const void *messageA) {
  const Message *message = (const Message *)messageA;
  Name *name = message_GetName(message);

  // we want the cumulative hash for the whole name
  uint32_t hash = name_HashCode(name);

  return hash;
}