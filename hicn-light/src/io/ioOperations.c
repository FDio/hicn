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

#include <parc/assert/parc_Assert.h>
#include <src/config.h>
#include <src/io/ioOperations.h>
#include <stdio.h>

void *ioOperations_GetClosure(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  return ops->closure;
}

bool ioOperations_Send(IoOperations *ops, const Address *nexthop,
                       Message *message) {
  return ops->send(ops, nexthop, message);
}

const Address *ioOperations_GetRemoteAddress(const IoOperations *ops) {
  return ops->getRemoteAddress(ops);
}

const AddressPair *ioOperations_GetAddressPair(const IoOperations *ops) {
  return ops->getAddressPair(ops);
}

bool ioOperations_IsUp(const IoOperations *ops) { return ops->isUp(ops); }

bool ioOperations_IsLocal(const IoOperations *ops) { return ops->isLocal(ops); }

unsigned ioOperations_GetConnectionId(const IoOperations *ops) {
  return ops->getConnectionId(ops);
}

void ioOperations_Release(IoOperations **opsPtr) {
  IoOperations *ops = *opsPtr;
  ops->destroy(opsPtr);
}

const void *ioOperations_Class(const IoOperations *ops) {
  return ops->class(ops);
}

list_connections_type ioOperations_GetConnectionType(const IoOperations *ops) {
  return ops->getConnectionType(ops);
}

Ticks ioOperations_SendProbe(IoOperations *ops, unsigned probeType,
                             uint8_t *message) {
  return ops->sendProbe(ops, probeType, message);
}
