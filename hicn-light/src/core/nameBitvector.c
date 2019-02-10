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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>

#include <src/core/messageHandler.h>
#include <src/core/nameBitvector.h>

#include <parc/algol/parc_Hash.h>

#include <src/utils/commands.h>

#define BLOCKS 2

const uint64_t BLOCK_SIZE = 64;
const uint64_t WIDTH = 128;
const uint64_t BLOCK_ONE = 0x1;

// the bits are encoded in the following order:
// 00100101001---101010  00100011---110100100
// [bits[0] (uint64_t)]  [bits[1] (uint64_t)]
// ^                  ^  ^                  ^
// 0                 63 64                127
// address  2200::0011 is encoded as:
//   1000 1000 0000 0010 00000 ....0100 0100
//   ^                                     ^
//   0                                   127

struct name_bitvector {
  uint64_t bits[BLOCKS];
  uint8_t len;
  uint8_t IPversion;
};

NameBitvector *nameBitvector_CreateFromInAddr(uint32_t addr, uint8_t len) {
  NameBitvector *bitvector = parcMemory_AllocateAndClear(sizeof(NameBitvector));
  parcAssertNotNull(bitvector, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(NameBitvector));

  bitvector->bits[0] = 0;
  bitvector->bits[1] = 0;

  uint8_t addr_1 = (addr & 0xff000000) >> 24;
  uint8_t addr_2 = (addr & 0x00ff0000) >> 16;
  uint8_t addr_3 = (addr & 0x0000ff00) >> 8;
  uint8_t addr_4 = (addr & 0x000000ff);

  bitvector->bits[1] = (bitvector->bits[1] | addr_4) << 8;
  bitvector->bits[1] = (bitvector->bits[1] | addr_3) << 8;
  bitvector->bits[1] = (bitvector->bits[1] | addr_2) << 8;
  bitvector->bits[1] = (bitvector->bits[1] | addr_1);
  bitvector->bits[1] = bitvector->bits[1] << 32;

  bitvector->len = len;

  bitvector->IPversion = IPv4_TYPE;

  return bitvector;
}

NameBitvector *nameBitvector_CreateFromIn6Addr(struct in6_addr *addr,
                                               uint8_t len) {
  parcAssertNotNull(addr, "addr cannot be null");

  NameBitvector *bitvector = parcMemory_AllocateAndClear(sizeof(NameBitvector));
  parcAssertNotNull(bitvector, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(NameBitvector));

  bitvector->bits[0] = 0;
  bitvector->bits[1] = 0;

  for (int i = 0; i < 8; ++i) {
    bitvector->bits[1] = (bitvector->bits[1] << 8) | addr->s6_addr[i];
  }

  for (int i = 8; i < 16; ++i) {
    bitvector->bits[0] = (bitvector->bits[0] << 8) | addr->s6_addr[i];
  }

  bitvector->len = len;

  bitvector->IPversion = IPv6_TYPE;

  return bitvector;
}

NameBitvector *nameBitvector_CreateFromAddress(const Address *prefix,
                                               uint8_t len) {
  parcAssertNotNull(prefix, "prefix cannot be null");

  NameBitvector *bitvector = NULL;
  switch (addressGetType(prefix)) {
    case ADDR_INET: {
      struct sockaddr_in addr;
      addressGetInet(prefix, &addr);
      bitvector = nameBitvector_CreateFromInAddr(addr.sin_addr.s_addr, len);
      break;
    }
    case ADDR_INET6: {
      struct sockaddr_in6 addr;
      addressGetInet6(prefix, &addr);
      bitvector = nameBitvector_CreateFromIn6Addr(&addr.sin6_addr, len);
      break;
    }
    default:
      parcTrapNotImplemented("Unkown packet type");
      break;
  }

  return bitvector;
}

NameBitvector *nameBitvector_Copy(const NameBitvector *original) {
  parcAssertNotNull(original, "original cannot be null");

  NameBitvector *copy = parcMemory_AllocateAndClear(sizeof(NameBitvector));
  parcAssertNotNull(copy, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(NameBitvector));

  copy->bits[0] = original->bits[0];
  copy->bits[1] = original->bits[1];
  copy->len = original->len;

  return copy;
}

void nameBitvector_Destroy(NameBitvector **bitvectorPtr) {
  parcAssertNotNull(bitvectorPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*bitvectorPtr,
                    "Parameter must dereference to non-null pointer");

  NameBitvector *bv = *bitvectorPtr;
  parcMemory_Deallocate((void **)&(bv));
  *bitvectorPtr = NULL;
}

uint8_t nameBitvector_GetLength(const NameBitvector *name) { return name->len; }

uint32_t nameBitvector_GetHash32(const NameBitvector *name) {
  return parcHash32_Data_Cumulative((const uint8_t *)name->bits, 16, 0);
}

bool nameBitvector_Equals(const NameBitvector *a, const NameBitvector *b) {
  if (a->bits[0] == b->bits[0] && a->bits[1] == b->bits[1] && a->len == b->len)
    return true;
  return false;
}

int nameBitvector_Compare(const NameBitvector *a, const NameBitvector *b) {
  if (a == NULL && b == NULL) {
    return 0;
  }
  if (a == NULL) {
    return -1;
  }
  if (b == NULL) {
    return +1;
  }

  if (a->bits[0] < b->bits[0]) {
    return -1;
  } else if (a->bits[0] > b->bits[0]) {
    return +1;
  } else if (a->bits[1] < b->bits[1]) {
    return -1;
  } else if (a->bits[1] > b->bits[1]) {
    return +1;
  } else if (a->len < b->len) {
    return -1;
  } else if (a->len > b->len) {
    return +1;
  } else {
    return 0;
  }
}

bool nameBitvector_StartsWith(const NameBitvector *name,
                              const NameBitvector *prefix) {
  parcAssertNotNull(name, "name cannot be NULL");
  parcAssertNotNull(prefix, "prefix cannot be NULL");
  parcAssertTrue(prefix->len > 0, "prefix length can not be 0");

  if (prefix->len > BLOCK_SIZE)
    return (name->bits[1] == prefix->bits[1]) &&
           ((name->bits[0] ^ prefix->bits[0]) >>
                (BLOCK_SIZE - (prefix->len - BLOCK_SIZE)) ==
            0);

  return ((name->bits[1] ^ prefix->bits[1]) >> (BLOCK_SIZE - prefix->len) == 0);
}

bool nameBitvector_testBit(const NameBitvector *name, uint8_t pos) {
  if (pos == WIDTH) pos = 127;

  uint8_t final_pos = (uint8_t)(WIDTH - name->len);

  // the bit to test is inside the name/prefix len
  if (pos > final_pos) {
    return (name->bits[pos / BLOCK_SIZE] & (BLOCK_ONE << (pos % BLOCK_SIZE)));
  }

  // the bit to test is outside the name/prefix len
  if (pos < final_pos) {
    return false;
  }

  // pos is equal to the name/prefix len
  return true;
}

uint64_t _diff_bit_log2(uint64_t val) {
  // base 2 log of an uint64_t. This is the same as get the position of
  // the highest bit set (or most significant bit set, MSB)
  uint64_t result = 0;

  if (val & 0xFFFFFFFF00000000) {
    val = val >> 32;
    result = result | 32;
  }
  if (val & 0xFFFF0000) {
    val = val >> 16;
    result = result | 16;
  }
  if (val & 0xFF00) {
    val = val >> 8;
    result = result | 8;
  }
  if (val & 0xF0) {
    val = val >> 4;
    result = result | 4;
  }
  if (val & 0xC) {
    val = val >> 2;
    result = result | 2;
  }
  if (val & 0x2) {
    val = val >> 1;
    result = result | 1;
  }
  return result;
}

uint8_t nameBitvector_firstDiff(const NameBitvector *a,
                                const NameBitvector *b) {
  uint8_t res = 0;
  uint64_t diff = a->bits[1] ^ b->bits[1];
  if (diff)
    res = (uint8_t)(64 + _diff_bit_log2(diff));
  else
    res = (uint8_t)_diff_bit_log2(a->bits[0] ^ b->bits[0]);

  // res is computed over the bitvector which is composed by 128 bit all the
  // times however the prefixes may be diffrent just because the have different
  // lengths example: prefix 1: 0::/30 prefix 2: 0::/20 at this point of the
  // function res would be 0 since both the bitvectors are composed by 0s but
  // the function will return 127-20, which is the position at which the two
  // prefix are different, since prefix 2 has only 20 bits

  uint8_t len_diff;
  if (a->len < b->len)
    len_diff = (uint8_t)(WIDTH - a->len);
  else
    len_diff = (uint8_t)(WIDTH - b->len);

  if (len_diff > res) res = len_diff;

  return res;
}

int nameBitvector_ToIPAddress(const NameBitvector *name,
                              ip_address_t *ip_address) {
  if (name->IPversion == IPv4_TYPE) {
    struct in_addr *addr = (struct in_addr *)(&ip_address->buffer);
    ip_address->family = AF_INET;
    ip_address->prefix_len = IPV4_ADDR_LEN_BITS;

    uint32_t tmp_addr = name->bits[1] >> 32ULL;
    uint8_t addr_1 = (tmp_addr & 0xff000000) >> 24;
    uint8_t addr_2 = (tmp_addr & 0x00ff0000) >> 16;
    uint8_t addr_3 = (tmp_addr & 0x0000ff00) >> 8;
    uint8_t addr_4 = (tmp_addr & 0x000000ff);

    addr->s_addr = 0;
    addr->s_addr = (addr->s_addr | addr_4) << 8;
    addr->s_addr = (addr->s_addr | addr_3) << 8;
    addr->s_addr = (addr->s_addr | addr_2) << 8;
    addr->s_addr = (addr->s_addr | addr_1);

  } else {
    struct in6_addr *addr = (struct in6_addr *)(&ip_address->buffer);
    ip_address->family = AF_INET6;
    ip_address->prefix_len = name->len;  // IPV6_ADDR_LEN_BITS;

    for (int i = 0; i < 8; i++) {
      addr->s6_addr[i] = (uint8_t)((name->bits[1] >> 8 * (7 - i)) & 0xFF);
    }

    int x = 0;
    for (int i = 8; i < 16; ++i) {
      addr->s6_addr[i] = (uint8_t)((name->bits[0] >> 8 * (7 - x)) & 0xFF);
      x++;
    }
  }
  return true;
}

void nameBitvector_setLen(NameBitvector *name, uint8_t len) { name->len = len; }

Address *nameBitvector_ToAddress(const NameBitvector *name) {
  if (name->IPversion == IPv4_TYPE) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);

    uint32_t tmp_addr = name->bits[1] >> 32ULL;
    uint8_t addr_1 = (tmp_addr & 0xff000000) >> 24;
    uint8_t addr_2 = (tmp_addr & 0x00ff0000) >> 16;
    uint8_t addr_3 = (tmp_addr & 0x0000ff00) >> 8;
    uint8_t addr_4 = (tmp_addr & 0x000000ff);

    addr.sin_addr.s_addr = 0;
    addr.sin_addr.s_addr = (addr.sin_addr.s_addr | addr_4) << 8;
    addr.sin_addr.s_addr = (addr.sin_addr.s_addr | addr_3) << 8;
    addr.sin_addr.s_addr = (addr.sin_addr.s_addr | addr_2) << 8;
    addr.sin_addr.s_addr = (addr.sin_addr.s_addr | addr_1);

    Address *packetAddr = addressCreateFromInet(&addr);

    return packetAddr;

  } else {
    struct sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(1234);
    addr.sin6_scope_id = 0;
    addr.sin6_flowinfo = 0;

    for (int i = 0; i < 8; i++) {
      addr.sin6_addr.s6_addr[i] =
          (uint8_t)((name->bits[1] >> 8 * (7 - i)) & 0xFF);
    }

    int x = 0;
    for (int i = 8; i < 16; ++i) {
      addr.sin6_addr.s6_addr[i] =
          (uint8_t)((name->bits[0] >> 8 * (7 - x)) & 0xFF);
      x++;
    }

    Address *packetAddr = addressCreateFromInet6(&addr);

    return packetAddr;
  }
}

char *nameBitvector_ToString(const NameBitvector *name) {
  char *output = malloc(WIDTH);

  Address *packetAddr = nameBitvector_ToAddress(name);

  sprintf(output, "prefix: %s len: %u", addressToString(packetAddr), name->len);

  addressDestroy(&packetAddr);

  return output;
}