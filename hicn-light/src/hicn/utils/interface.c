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
#include <stdlib.h>
#include <string.h>

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_BufferComposer.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>
#include <hicn/utils/addressList.h>
#include <hicn/utils/interface.h>

#include <parc/assert/parc_Assert.h>
#include <hicn/utils/commands.h>

#if 0

struct interface {
  char *name;
  unsigned interfaceIndex;
  bool loopback;
  bool supportMulticast;
  unsigned mtu;

  AddressList *addressList;
};

char *interfaceToString(const Interface *interface) {
  PARCBufferComposer *composer = parcBufferComposer_Create();

  parcBufferComposer_Format(
      composer, "%3u %10s %1s%1s %8u ", interface->interfaceIndex,
      interface->name, interface->loopback ? "l" : " ",
      interface->supportMulticast ? "m" : " ", interface->mtu);

  for (size_t i = 0; i < addressListLength(interface->addressList); i++) {
    addressBuildString(addressListGetItem(interface->addressList, i), composer);
    if (i < (addressListLength(interface->addressList) - 1)) {
      parcBufferComposer_PutStrings(composer, "\n", NULL);
    }
  }

  PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
  char *result = parcBuffer_ToString(tempBuffer);
  parcBuffer_Release(&tempBuffer);
  parcBufferComposer_Release(&composer);
  return result;
}

Interface *interfaceCreate(const char *name, unsigned interfaceIndex,
                           bool loopback, bool supportMulticast, unsigned mtu) {
  Interface *iface = parcMemory_AllocateAndClear(sizeof(Interface));

  parcAssertNotNull(iface, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Interface));
  iface->name = parcMemory_StringDuplicate(name, 64);
  iface->interfaceIndex = interfaceIndex;
  iface->loopback = loopback;
  iface->supportMulticast = supportMulticast;
  iface->mtu = mtu;
  iface->addressList = addressListCreate();

  return iface;
}

void interfaceDestroy(Interface **interfacePtr) {
  parcAssertNotNull(interfacePtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*interfacePtr,
                    "Parameter must dereference to non-null pointer");

  Interface *iface = *interfacePtr;
  parcMemory_Deallocate((void **)&iface->name);
  addressListDestroy(&iface->addressList);
  parcMemory_Deallocate((void **)&iface);
  interfacePtr = NULL;
}

void interfaceAddAddress(Interface *iface, Address *address) {
  parcAssertNotNull(iface, "Parameter iface must be non-null");

  size_t length = addressListLength(iface->addressList);
  for (size_t i = 0; i < length; i++) {
    const Address *a = addressListGetItem(iface->addressList, i);
    if (addressEquals(a, address)) {
      return;
    }
  }

  addressListAppend(iface->addressList, address);
}

const AddressList *interfaceGetAddresses(const Interface *iface) {
  parcAssertNotNull(iface, "Parameter iface must be non-null");
  return iface->addressList;
}

unsigned interfaceGetInterfaceIndex(const Interface *iface) {
  parcAssertNotNull(iface, "Parameter iface must be non-null");
  return iface->interfaceIndex;
}

bool interfaceNameEquals(const Interface *iface, const char *name) {
  parcAssertNotNull(iface, "Parameter iface must be non-null");

  if (strcasecmp(iface->name, name) == 0) {
    return true;
  }
  return false;
}

bool interfaceEquals(const Interface *a, const Interface *b) {
  if (a == NULL && b == NULL) {
    return true;
  }

  if (a == NULL || b == NULL) {
    return false;
  }

  if (a->interfaceIndex == b->interfaceIndex) {
    if (a->loopback == b->loopback) {
      if (a->supportMulticast == b->supportMulticast) {
        if (a->mtu == b->mtu) {
          if (strcasecmp(a->name, b->name) == 0) {
            if (addressListEquals(a->addressList, b->addressList)) {
              return true;
            }
          }
        }
      }
    }
  }
  return false;
}

// static const char light_Iface[] = "Interface";
// static const char light_IfName[] = "Name";
// static const char light_IFIDX[] = "Index";
// static const char light_IsLoopback[] = "Loopback";
// static const char light_Multicast[] = "Multicast";
// static const char light_MTU[] = "MTU";

// static const char light_True[] = "true";
// static const char light_False[] = "false";
// static const char light_Addrs[] = "Addrs";

const char *interfaceGetName(const Interface *iface) {
  parcAssertNotNull(iface, "Parameter iface must be non-null");
  return iface->name;
}

unsigned interfaceGetMTU(const Interface *iface) {
  parcAssertNotNull(iface, "Parameter iface must be non-null");
  return iface->mtu;
}

#endif
