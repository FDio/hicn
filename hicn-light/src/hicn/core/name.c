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

#include <limits.h>
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <parc/algol/parc_BufferComposer.h>
#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_Memory.h>

#include <hicn/core/messageHandler.h>
#include <hicn/core/name.h>

#include <parc/algol/parc_Hash.h>

#include <parc/assert/parc_Assert.h>

#define IPv6_TYPE 6
#define IPv4_TYPE 4

// assumption: the IPv6 address is the name, the TCP segment number is the ICN
// segment

struct name {
  NameBitvector *content_name;
  uint32_t segment;
  uint32_t name_hash;
  // the refcount is shared between all copies
  unsigned *refCountPtr;
};

// =====================================================

static unsigned _getRefCount(const Name *name) { return *name->refCountPtr; }

static void _incrementRefCount(Name *name) {
  parcAssertTrue(*name->refCountPtr > 0,
                 "Illegal State: Trying to increment a 0 refcount!");
  (*name->refCountPtr)++;
}

static void _decrementRefCount(Name *name) {
  parcAssertTrue(*name->refCountPtr > 0,
                 "Illegal State: Trying to decrement a 0 refcount!");
  (*name->refCountPtr)--;
}

static uint32_t _computeHash(Name *name) {
  parcAssertNotNull(name, "Parameter must be non-null pointer");

  uint32_t hash1 = nameBitvector_GetHash32(name->content_name);
  return parcHash32_Data_Cumulative((const uint8_t *)&name->segment, 4, hash1);
}

// ============================================================================

Name *name_CreateFromPacket(const uint8_t *packet, MessagePacketType type) {
  Name *name = parcMemory_AllocateAndClear(sizeof(Name));
  parcAssertNotNull(name, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Name));

  if (messageHandler_GetIPPacketType(packet) == IPv6_TYPE) {
    if (type == MessagePacketType_Interest) {
      name->content_name = nameBitvector_CreateFromIn6Addr(
          (struct in6_addr *)messageHandler_GetDestination(packet), 128);
    } else if (type == MessagePacketType_ContentObject) {
      name->content_name = nameBitvector_CreateFromIn6Addr(
          (struct in6_addr *)messageHandler_GetSource(packet), 128);
    } else {
      parcMemory_Deallocate((void **)&name);
      return NULL;
    }
  } else if (messageHandler_GetIPPacketType(packet) == IPv4_TYPE) {
    if (type == MessagePacketType_Interest) {
      name->content_name = nameBitvector_CreateFromInAddr(
          *((uint32_t *)messageHandler_GetDestination(packet)), 32);
    } else if (type == MessagePacketType_ContentObject) {
      name->content_name = nameBitvector_CreateFromInAddr(
          *((uint32_t *)messageHandler_GetSource(packet)), 32);
    } else {
      parcMemory_Deallocate((void **)&name);
      return NULL;
    }
  } else {
    printf("Error: unknown message type\n");
    parcMemory_Deallocate((void **)&name);
    return NULL;
  }

  name->segment = messageHandler_GetSegment(packet);
  name->name_hash = _computeHash(name);

  name->refCountPtr = parcMemory_Allocate(sizeof(unsigned));
  parcAssertNotNull(name->refCountPtr, "parcMemory_Allocate(%zu) returned NULL",
                    sizeof(unsigned));
  *name->refCountPtr = 1;
  return name;
}

Name *name_CreateFromAddress(int family, ip_address_t addr,
                             uint8_t len) {
  Name *name = parcMemory_AllocateAndClear(sizeof(Name));
  parcAssertNotNull(name, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Name));

  switch(family) {
    case AF_INET:
      name->content_name = nameBitvector_CreateFromInAddr(addr.v4.as_u32, len);
      break;
    case AF_INET6:
      name->content_name = nameBitvector_CreateFromIn6Addr(&addr.v6.as_in6addr, len);
      break;
    default:
      parcTrapNotImplemented("Unkown packet type");
      break;
  }

  name->segment = 0;
  name->name_hash = _computeHash(name);

  name->refCountPtr = parcMemory_Allocate(sizeof(unsigned));
  parcAssertNotNull(name->refCountPtr, "parcMemory_Allocate(%zu) returned NULL",
                    sizeof(unsigned));
  *name->refCountPtr = 1;

  return name;
}

void name_Release(Name **namePtr) {
  parcAssertNotNull(namePtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*namePtr, "Parameter must dereference to non-null pointer");

  Name *name = *namePtr;
  _decrementRefCount(name);
  if (_getRefCount(name) == 0) {
    parcMemory_Deallocate((void **)&(name->refCountPtr));
    nameBitvector_Destroy(&(name->content_name));
  }
  parcMemory_Deallocate((void **)&name);
  *namePtr = NULL;
}

Name *name_Acquire(const Name *original) {
  parcAssertNotNull(original, "Parameter must be non-null");
  Name *copy = parcMemory_AllocateAndClear(sizeof(Name));
  parcAssertNotNull(copy, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Name));

  memcpy(copy, original, sizeof(Name));
  _incrementRefCount(copy);

  return copy;
}

Name *name_Copy(const Name *original) {
  parcAssertNotNull(original, "Parameter must be non-null");
  Name *copy = parcMemory_AllocateAndClear(sizeof(Name));
  parcAssertNotNull(copy, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Name));

  copy->content_name = nameBitvector_Copy(original->content_name);
  copy->segment = original->segment;
  copy->name_hash = original->name_hash;

  copy->refCountPtr = parcMemory_Allocate(sizeof(unsigned));
  parcAssertNotNull(copy->refCountPtr, "parcMemory_Allocate(%zu) returned NULL",
                    sizeof(unsigned));
  *copy->refCountPtr = 1;

  return copy;
}

uint32_t name_HashCode(const Name *name) {
  parcAssertNotNull(name, "Parameter must be non-null");
  return name->name_hash;
}

NameBitvector *name_GetContentName(const Name *name) {
  parcAssertNotNull(name, "Parameter must be non-null");
  return name->content_name;
}

bool name_Equals(const Name *a, const Name *b) {
  parcAssertNotNull(a, "Parameter a must be non-null");
  parcAssertNotNull(b, "Parameter b must be non-null");

  /* BEGIN: Workaround for HICN-400 */
  if ((!a->content_name) || (!b->content_name))
      return false;
  /* END: Workaround for HICN-400 */

  if ((nameBitvector_Equals(a->content_name, b->content_name) &&
       a->segment == b->segment))
    return true;
  return false;
}

int name_Compare(const Name *a, const Name *b) {
  parcAssertNotNull(a, "Parameter a must be non-null");
  parcAssertNotNull(b, "Parameter b must be non-null");

  if (a == NULL && b == NULL) {
    return 0;
  }
  if (a == NULL) {
    return -1;
  }
  if (b == NULL) {
    return +1;
  }

  int res = nameBitvector_Compare(a->content_name, b->content_name);

  if (res != 0) {
    return res;
  } else {
    if (a->segment < b->segment) {
      return -1;
    } else if (a->segment > b->segment) {
      return +1;
    } else {
      return 0;
    }
  }
}

char *name_ToString(const Name *name) {
  char *output = malloc(128);

  address_t address;
  nameBitvector_ToAddress(name_GetContentName(name), &address);

// XXX TODO
#if 0
  sprintf(output, "name: %s seq: %u", addressToString(address),
          name->segment);
#else
  snprintf(output, 128, "%s", "Not implemented");
#endif

  return output;
}

void name_setLen(Name *name, uint8_t len) {
  nameBitvector_setLen(name->content_name, len);
  name->name_hash = _computeHash(name);
}

#ifdef WITH_POLICY
uint32_t name_GetSuffix(const Name * name) {
    return name->segment;
}

uint8_t name_GetLen(const Name * name) {
    return nameBitvector_GetLength(name->content_name);
}
#endif /* WITH_POLICY */
