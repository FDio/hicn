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

#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/utils/address.h>

#include <parc/algol/parc_Base64.h>
#include <parc/algol/parc_BufferComposer.h>
#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>
#include <parc/algol/parc_Object.h>

#include <parc/assert/parc_Assert.h>

struct address {
  address_type addressType;
  PARCBuffer *blob;
};

static struct address_type_str {
  address_type type;
  const char *str;
} addressTypeString[] = {
    {.type = ADDR_INET, .str = "INET"}, {.type = ADDR_INET6, .str = "INET6"},
    {.type = ADDR_LINK, .str = "LINK"}, {.type = ADDR_IFACE, .str = "IFACE"},
    {.type = ADDR_UNIX, .str = "UNIX"}, {.type = 0, .str = NULL}};

void addressDestroy(Address **addressPtr) {
  parcAssertNotNull(addressPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*addressPtr,
                    "Parameter must dereference to non-null pointer");

  Address *address = *addressPtr;
  parcBuffer_Release(&address->blob);
  parcMemory_Deallocate((void **)&address);
  *addressPtr = NULL;
}

void addressAssertValid(const Address *address) {
  parcAssertNotNull(address, "Parameter must be non-null Address *");
}

const char *addressTypeToString(address_type type) {
  for (int i = 0; addressTypeString[i].str != NULL; i++) {
    if (addressTypeString[i].type == type) {
      return addressTypeString[i].str;
    }
  }
  parcTrapIllegalValue(type, "Unknown value: %d", type);
  const char *result = NULL;
  return result;
}

address_type addressStringToType(const char *str) {
  for (int i = 0; addressTypeString[i].str != NULL; i++) {
    if (strcasecmp(addressTypeString[i].str, str) == 0) {
      return addressTypeString[i].type;
    }
  }
  parcTrapIllegalValue(str, "Unknown type '%s'", str);
  return 0;
}

static Address *_addressCreate(address_type addressType, PARCBuffer *buffer) {
  Address *result = parcMemory_AllocateAndClear(sizeof(Address));

  parcAssertNotNull(result, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Address));
  if (result != NULL) {
    result->addressType = addressType;
    result->blob = buffer;
  }
  return result;
}

Address *addressCreateFromInet(struct sockaddr_in *addr_in) {
  parcAssertNotNull(addr_in, "Parameter must be non-null");

  addr_in->sin_family = AF_INET;

  PARCBuffer *buffer = parcBuffer_Allocate(sizeof(struct sockaddr_in));
  parcBuffer_PutArray(buffer, sizeof(struct sockaddr_in), (uint8_t *)addr_in);
  parcBuffer_Flip(buffer);

  Address *result = _addressCreate(ADDR_INET, buffer);

  return result;
}

Address *addressCreateFromInet6(struct sockaddr_in6 *addr_in6) {
  parcAssertNotNull(addr_in6, "Parameter must be non-null");

  PARCBuffer *buffer = parcBuffer_Allocate(sizeof(struct sockaddr_in6));
  parcBuffer_PutArray(buffer, sizeof(struct sockaddr_in6), (uint8_t *)addr_in6);
  parcBuffer_Flip(buffer);

  Address *result = _addressCreate(ADDR_INET6, buffer);

  return result;
}

Address *addressFromInaddr4Port(in_addr_t *addr4, in_port_t *port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));

  // We assume address and port are already written in memory in network byte
  // order
  addr.sin_family = AF_INET;
  addr.sin_port = *port;
  addr.sin_addr.s_addr = *addr4;

  Address *result = addressCreateFromInet(&addr);
  return result;
}

Address *addressFromInaddr6Port(struct in6_addr *addr6, in_port_t *port) {
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;

  // We assume address and port are already written in memory in network byte
  // order
  addr.sin6_port = *port;
  addr.sin6_addr = *addr6;
  addr.sin6_scope_id = 0;
  // Other 2 fields: scope_id and flowinfo, do not know what to put inside.

  Address *result = addressCreateFromInet6(&addr);
  return result;
}

Address *addressCreateFromLink(const uint8_t *linkaddr, size_t length) {
  parcAssertNotNull(linkaddr, "Parameter must be non-null");

  PARCBuffer *buffer = parcBuffer_Allocate(sizeof(struct sockaddr_in6));
  parcBuffer_PutArray(buffer, length, linkaddr);
  parcBuffer_Flip(buffer);

  Address *result = _addressCreate(ADDR_LINK, buffer);
  return result;
}

Address *addressCreateFromInterface(unsigned interfaceIndex) {
  unsigned netbyteorder = htonl(interfaceIndex);

  PARCBuffer *buffer = parcBuffer_Allocate(sizeof(netbyteorder));
  parcBuffer_PutArray(buffer, sizeof(netbyteorder), (uint8_t *)&netbyteorder);
  parcBuffer_Flip(buffer);

  Address *result = _addressCreate(ADDR_IFACE, buffer);
  return result;
}

Address *addressCreateFromUnix(struct sockaddr_un *addr_un) {
  parcAssertNotNull(addr_un, "Parameter must be non-null");

  PARCBuffer *buffer = parcBuffer_Allocate(sizeof(struct sockaddr_un));
  parcBuffer_PutArray(buffer, sizeof(struct sockaddr_un), (uint8_t *)addr_un);
  parcBuffer_Flip(buffer);

  Address *result = _addressCreate(ADDR_UNIX, buffer);
  return result;
}

Address *addressCopy(const Address *original) {
  addressAssertValid(original);

  Address *result =
      _addressCreate(original->addressType, parcBuffer_Copy(original->blob));
  return result;
}

bool addressEquals(const Address *a, const Address *b) {
  if (a == b) {
    return true;
  }

  if (a == NULL || b == NULL) {
    return false;
  }

  if (a->addressType == b->addressType) {
    if (parcBuffer_Equals(a->blob, b->blob)) {
      return true;
    }
  }

  return false;
}

address_type addressGetType(const Address *address) {
  addressAssertValid(address);

  return address->addressType;
}

// The Get functions need better names, what they do (Get from what? Put to
// what?) is not clear from their names.  Case 1028
bool addressGetInet(const Address *address, struct sockaddr_in *addr_in) {
  addressAssertValid(address);
  parcAssertNotNull(addr_in, "Parameter addr_in must be non-null");

  if (address->addressType == ADDR_INET) {
    parcAssertTrue(
        parcBuffer_Remaining(address->blob) == sizeof(struct sockaddr_in),
        "Address corrupted. Expected length %zu, actual length %zu",
        sizeof(struct sockaddr_in), parcBuffer_Remaining(address->blob));

    memcpy(addr_in, parcBuffer_Overlay(address->blob, 0),
           sizeof(struct sockaddr_in));
    return true;
  }
  return false;
}

bool addressGetInet6(const Address *address, struct sockaddr_in6 *addr_in6) {
  addressAssertValid(address);
  parcAssertNotNull(addr_in6, "Parameter addr_in6 must be non-null");

  if (address->addressType == ADDR_INET6) {
    parcAssertTrue(
        parcBuffer_Remaining(address->blob) == sizeof(struct sockaddr_in6),
        "Address corrupted. Expected length %zu, actual length %zu",
        sizeof(struct sockaddr_in6), parcBuffer_Remaining(address->blob));

    memcpy(addr_in6, parcBuffer_Overlay(address->blob, 0),
           sizeof(struct sockaddr_in6));
    return true;
  }
  return false;
}

bool addressGetUnix(const Address *address, struct sockaddr_un *addr_un) {
  addressAssertValid(address);
  parcAssertNotNull(addr_un, "Parameter addr_in6 must be non-null");

  if (address->addressType == ADDR_UNIX) {
    parcAssertTrue(
        parcBuffer_Remaining(address->blob) == sizeof(struct sockaddr_un),
        "Address corrupted. Expected length %zu, actual length %zu",
        sizeof(struct sockaddr_un), parcBuffer_Remaining(address->blob));

    memcpy(addr_un, parcBuffer_Overlay(address->blob, 0),
           sizeof(struct sockaddr_un));
    return true;
  }
  return false;
}

bool addressGetInterfaceIndex(const Address *address, uint32_t *ifidx) {
  addressAssertValid(address);
  parcAssertNotNull(ifidx, "Parameter ifidx must be non-null");

  if (address->addressType == ADDR_IFACE) {
    parcAssertTrue(parcBuffer_Remaining(address->blob) == sizeof(uint32_t),
                   "Address corrupted. Expected length %zu, actual length %zu",
                   sizeof(uint32_t), parcBuffer_Remaining(address->blob));

    uint32_t netbyteorder;
    memcpy(&netbyteorder, parcBuffer_Overlay(address->blob, 0),
           sizeof(uint32_t));
    *ifidx = ntohl(netbyteorder);
    return true;
  }
  return false;
}

PARCBuffer *addressGetLinkAddress(const Address *address) {
  addressAssertValid(address);
  if (address->addressType == ADDR_LINK) {
    return address->blob;
  }
  return NULL;
}

static PARCBufferComposer *_Inet_BuildString(const Address *address,
                                             PARCBufferComposer *composer) {
  addressAssertValid(address);

  struct sockaddr_in *saddr =
      (struct sockaddr_in *)parcBuffer_Overlay(address->blob, 0);
  return parcNetwork_SockInet4Address_BuildString(saddr, composer);
}

static PARCBufferComposer *_Inet6_BuildString(const Address *address,
                                              PARCBufferComposer *composer) {
  addressAssertValid(address);

  struct sockaddr_in6 *saddr =
      (struct sockaddr_in6 *)parcBuffer_Overlay(address->blob, 0);
  return parcNetwork_SockInet6Address_BuildString(saddr, composer);
}

static PARCBufferComposer *_Link_BuildString(const Address *address,
                                             PARCBufferComposer *composer) {
  addressAssertValid(address);

  const unsigned char *addr = parcBuffer_Overlay(address->blob, 0);

  size_t length = parcBuffer_Remaining(address->blob);

  return parcNetwork_LinkAddress_BuildString(addr, length, composer);
}

static ssize_t _UnixToString(char *output, size_t remaining_size,
                             const PARCBuffer *addr) {
  parcAssertNotNull(output, "parameter output must be non-null");
  parcBuffer_AssertValid(addr);

  parcAssertTrue(parcBuffer_Remaining(addr) == sizeof(struct sockaddr_un),
                 "Address corrupted. Expected %zu actual %zu",
                 sizeof(struct sockaddr_un), parcBuffer_Remaining(addr));

  // sockaddr length for the path, 16 for the ascii stuff, 3 for the length
  // number
  struct sockaddr_un *saddr =
      (struct sockaddr_un *)parcBuffer_Overlay((PARCBuffer *)addr, 0);
  size_t min_remaining = strlen(saddr->sun_path) + 16 + 3;
  parcAssertTrue(remaining_size >= min_remaining,
                 "Remaining size too small, need at least %zu", min_remaining);

  ssize_t output_length = sprintf(output, "{ .path=%s, .len=%zu }",
                                  saddr->sun_path, strlen(saddr->sun_path));
  return output_length;
}

static ssize_t _IfaceToString(char *output, size_t remaining_size,
                              const PARCBuffer *addr) {
  parcAssertNotNull(output, "parameter output must be non-null");
  parcBuffer_AssertValid(addr);

  parcAssertTrue(parcBuffer_Remaining(addr) == sizeof(uint32_t),
                 "Address corrupted. Expected %zu actual %zu", sizeof(uint32_t),
                 parcBuffer_Remaining(addr));

  uint32_t *ifidx = (uint32_t *)parcBuffer_Overlay((PARCBuffer *)addr, 0);

  ssize_t output_length = sprintf(output, "{ .ifidx=%u }", ntohl(*ifidx));

  return output_length;
}

PARCBufferComposer *addressBuildString(const Address *address,
                                       PARCBufferComposer *composer) {
  if (address != NULL) {
    char *str = addressToString(address);
    parcBufferComposer_PutString(composer, str);
    parcMemory_Deallocate((void **)&str);
  }
  return composer;
}

char *addressToString(const Address *address) {
  addressAssertValid(address);

  char addrstr[256];

  switch (address->addressType) {
    case ADDR_INET: {
      PARCBufferComposer *composer = parcBufferComposer_Create();
      PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(
          _Inet_BuildString(address, composer));
      char *result = parcBuffer_ToString(tempBuffer);
      parcBuffer_Release(&tempBuffer);
      parcBufferComposer_Release(&composer);
      return result;
    } break;

    case ADDR_INET6: {
      PARCBufferComposer *composer = parcBufferComposer_Create();

      PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(
          _Inet6_BuildString(address, composer));
      char *result = parcBuffer_ToString(tempBuffer);
      parcBuffer_Release(&tempBuffer);

      parcBufferComposer_Release(&composer);
      return result;
    } break;

    case ADDR_LINK:
      _UnixToString(addrstr, 256, address->blob);
      break;

    case ADDR_IFACE: {
      PARCBufferComposer *composer = parcBufferComposer_Create();

      PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(
          _Link_BuildString(address, composer));
      char *result = parcBuffer_ToString(tempBuffer);
      parcBuffer_Release(&tempBuffer);

      parcBufferComposer_Release(&composer);
      return result;
    } break;

    case ADDR_UNIX:
      _IfaceToString(addrstr, 256, address->blob);
      break;

    default:
      sprintf(addrstr, "UNKNOWN type = %d", address->addressType);
      break;
  }

  ssize_t alloc_size = 1024;
  char *output = parcMemory_Allocate(alloc_size);
  parcAssertNotNull(output, "parcMemory_Allocate(%zu) returned NULL",
                    alloc_size);
  ssize_t output_length =
      snprintf(output, alloc_size, "{ .type=%s, .data=%s }",
               addressTypeToString(address->addressType), addrstr);

  parcAssertTrue(output_length < alloc_size,
                 "allocated size too small, needed %zd", output_length);
  parcAssertFalse(output_length < 0, "snprintf error: (%d) %s", errno,
                  strerror(errno));

  return output;
}

PARCHashCode addressHashCode(const Address *address) {
  addressAssertValid(address);

  PARCHashCode hash = parcBuffer_HashCode(address->blob);
  hash = parcHashCode_HashImpl((uint8_t *)&address->addressType,
                               sizeof(address->addressType), hash);

  return hash;
}
