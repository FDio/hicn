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
#include <hicn/hicn-light/config.h>
#include <hicn/io/ioOperations.h>
#include <hicn/base/msgbuf.h>
#include <stdio.h>

void *ioOperations_GetClosure(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  return ops->closure;
}

bool ioOperations_Send(IoOperations *ops, const address_t *nexthop,
                       msgbuf_t *message, bool queue) {
  return ops->send(ops, nexthop, message, queue);
}

bool ioOperations_SendIOVBuffer(IoOperations *ops, struct iovec *message,
    size_t size) {
  return ops->sendIOVBuffer(ops, message, size);
}

const address_t *ioOperations_GetRemoteAddress(const IoOperations *ops) {
  return ops->getRemoteAddress(ops);
}

const address_pair_t *ioOperations_GetAddressPair(const IoOperations *ops) {
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

void ioOperations_SendProbe(IoOperations *ops, uint8_t *message) {
  ops->sendProbe(ops, message);
}


connection_state_t ioOperations_GetState(const IoOperations *ops) {
  return ops->getState(ops);
}

void ioOperations_SetState(IoOperations *ops, connection_state_t state) {
  ops->setState(ops, state);
}

connection_state_t ioOperations_GetAdminState(const IoOperations *ops) {
  return ops->getAdminState(ops);
}

void ioOperations_SetAdminState(IoOperations *ops, connection_state_t admin_state) {
  ops->setAdminState(ops, admin_state);
}

#ifdef WITH_POLICY
uint32_t ioOperations_GetPriority(const IoOperations *ops) {
  return ops->getPriority(ops);
}

void ioOperations_SetPriority(IoOperations *ops, uint32_t priority) {
  ops->setPriority(ops, priority);
}
#endif /* WITH_POLICY */

const char * ioOperations_GetInterfaceName(const IoOperations *ops) {
    return ops->getInterfaceName(ops);
}
