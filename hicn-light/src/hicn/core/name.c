/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <assert.h>
#include <limits.h>
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <hicn/common.h>  // cumulative_hash32
#include <hicn/core/messageHandler.h>
#include <hicn/core/name.h>
#include <hicn/util/log.h>
#include <hicn/util/hash.h>

#define IPv6_TYPE 6
#define IPv4_TYPE 4

static uint32_t _computeHash(Name *name) {
  assert(name);

  uint32_t hash1 = nameBitvector_GetHash32(&(name->content_name));
  return hashlittle(&name->segment, sizeof(name->segment), hash1);
}

// ============================================================================

void name_create_from_interest(const uint8_t *packet, Name *name) {
  assert(packet);
  assert(name);

  if (messageHandler_GetIPPacketType(packet) == IPv6_TYPE) {
    nameBitvector_CreateFromIn6Addr(
        &(name->content_name),
        (struct in6_addr *)messageHandler_GetDestination(packet), 128);
  } else if (messageHandler_GetIPPacketType(packet) == IPv4_TYPE) {
    nameBitvector_CreateFromInAddr(
        &(name->content_name),
        *((uint32_t *)messageHandler_GetDestination(packet)), 32);
  } else {
    ERROR("Error: unknown message type\n");
    return;
  }

  name->segment = messageHandler_GetSegment(packet);
  name->name_hash = _computeHash(name);
}

void name_create_from_data(const uint8_t *packet, Name *name) {
  assert(packet);
  assert(name);

  if (messageHandler_GetIPPacketType(packet) == IPv6_TYPE) {
    nameBitvector_CreateFromIn6Addr(
        &(name->content_name),
        (struct in6_addr *)messageHandler_GetSource(packet), 128);
  } else if (messageHandler_GetIPPacketType(packet) == IPv4_TYPE) {
    nameBitvector_CreateFromInAddr(
        &(name->content_name), *((uint32_t *)messageHandler_GetSource(packet)),
        32);
  } else {
    printf("Error: unknown message type\n");
    return;
  }

  name->segment = messageHandler_GetSegment(packet);
  name->name_hash = _computeHash(name);
}

void name_CreateFromAddress(Name *name, int family, ip_address_t addr,
                            uint8_t len) {
  assert(name);

  switch (family) {
    case AF_INET:
      nameBitvector_CreateFromInAddr(&(name->content_name), addr.v4.as_u32,
                                     len);
      break;
    case AF_INET6:
      nameBitvector_CreateFromIn6Addr(&(name->content_name),
                                      &addr.v6.as_in6addr, len);
      break;
    default:
      return;
  }

  name->segment = 0;
  name->name_hash = _computeHash(name);
}

void name_Copy(const Name *original, Name *copy) {
  assert(original);
  assert(copy);

  nameBitvector_Copy(&(original->content_name), &(copy->content_name));
  copy->segment = original->segment;
  copy->name_hash = original->name_hash;
}

uint32_t name_HashCode(const Name *name) {
  assert(name);
  return name->name_hash;
}

NameBitvector *name_GetContentName(const Name *name) {
  assert(name);
  return (NameBitvector *)&(name->content_name);
}

uint32_t name_GetSegment(const Name *name) {
  assert(name);
  return name->segment;
}

void name_SetSegment(Name *name, uint32_t segment) { name->segment = segment; }

bool name_Equals(const Name *a, const Name *b) {
  assert(a);
  assert(b);

  if ((nameBitvector_Equals(&(a->content_name), &(b->content_name)) &&
       a->segment == b->segment))
    return true;
  return false;
}

int name_Compare(const Name *a, const Name *b) {
  assert(a);
  assert(b);

  if (a == NULL && b == NULL) {
    return 0;
  }
  if (a == NULL) {
    return -1;
  }
  if (b == NULL) {
    return +1;
  }

  int res = nameBitvector_Compare(&(a->content_name), &(b->content_name));

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
  char *output = malloc(NI_MAXHOST * 2);
  address_t address;
  nameBitvector_ToAddress(name_GetContentName(name), &address);

  char addr_str[NI_MAXHOST];
  int err = address_to_string(&address, addr_str, NULL);
  _ASSERT(!err);

  int chars_written =
      snprintf(output, NI_MAXHOST * 2, "name=%s|%u", addr_str, name->segment);
  _ASSERT(chars_written > 0);

  return output;
}

void name_setLen(Name *name, uint8_t len) {
  nameBitvector_setLen(&(name->content_name), len);
  name->name_hash = _computeHash(name);
}

#ifdef WITH_POLICY
uint32_t name_GetSuffix(const Name *name) { return name->segment; }

uint8_t name_GetLen(const Name *name) {
  return nameBitvector_GetLength(&(name->content_name));
}
#endif /* WITH_POLICY */
