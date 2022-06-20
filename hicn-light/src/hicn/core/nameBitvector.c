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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <hicn/core/messageHandler.h>
#include <hicn/core/nameBitvector.h>

#include <hicn/util/hash.h>
#include <hicn/ctrl/hicn-light-ng.h>

#define DEFAULT_PORT 1234

const uint64_t BV_SIZE = 64;
const uint64_t WIDTH = 128;
const uint64_t ONE = 0x1;

// address b000:0000:0000:0001:c000:0000:0000:0001 is encodend as follow
// [bits[0] uint64_t       ] [bits[1] unit64_t       ]
// ^                       ^ ^                       ^
// 63                      0 127                     64
// [1000 0000 ... 0000 1011] [1000 0000 ... 0000 0011] //binary
//    1                  b     1                  c    //hex

void nameBitvector_CreateFromInAddr(NameBitvector *bitvector, uint32_t addr,
                                    uint8_t len) {
  assert(bitvector);

  bitvector->bits[0] = 0;
  bitvector->bits[1] = 0;

  uint8_t addr_1 = (addr & 0xff000000) >> 24;
  uint8_t addr_2 = (addr & 0x00ff0000) >> 16;
  uint8_t addr_3 = (addr & 0x0000ff00) >> 8;
  uint8_t addr_4 = (addr & 0x000000ff);

  bitvector->bits[0] = (bitvector->bits[0] | addr_4) << 8;
  bitvector->bits[0] = (bitvector->bits[0] | addr_3) << 8;
  bitvector->bits[0] = (bitvector->bits[0] | addr_2) << 8;
  bitvector->bits[0] = (bitvector->bits[0] | addr_1);
  bitvector->bits[0] = bitvector->bits[0] << 32;

  bitvector->len = len;

  bitvector->IPversion = IPv4_TYPE;
}

void nameBitvector_CreateFromIn6Addr(NameBitvector *bitvector,
                                     struct in6_addr *addr, uint8_t len) {
  assert(addr);
  assert(bitvector);

  bitvector->bits[0] = 0;
  bitvector->bits[1] = 0;

  for (int i = 0; i < 8; ++i) {
    bitvector->bits[0] = (bitvector->bits[0] << 8) | addr->s6_addr[i];
  }

  for (int i = 8; i < 16; ++i) {
    bitvector->bits[1] = (bitvector->bits[1] << 8) | addr->s6_addr[i];
  }

  bitvector->len = len;

  bitvector->IPversion = IPv6_TYPE;
}

void nameBitvector_Copy(const NameBitvector *original, NameBitvector *copy) {
  assert(original);
  assert(copy);

  copy->bits[0] = original->bits[0];
  copy->bits[1] = original->bits[1];
  copy->len = original->len;
  copy->IPversion = original->IPversion;
}

uint8_t nameBitvector_GetLength(const NameBitvector *name) { return name->len; }

uint32_t nameBitvector_GetHash32(const NameBitvector *name) {
  return hash(&name->bits, 16);
}

bool nameBitvector_Equals(const NameBitvector *a, const NameBitvector *b) {
  if (nameBitvector_Compare(a, b) == 0) return true;
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

int nameBitvector_testBit(const NameBitvector *name, uint8_t pos, bool *bit) {
  if (pos >= name->len || pos > (WIDTH - 1)) return -1;

  *bit =
      (name->bits[pos / BV_SIZE] & (ONE << ((BV_SIZE - 1) - (pos % BV_SIZE))));

  return 0;
}

// TODO XXX use ffs(ll)
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

uint32_t nameBitvector_lpm(const NameBitvector *a, const NameBitvector *b) {
  uint32_t limit;
  uint32_t prefix_len;
  if (a->len < b->len)
    limit = a->len;
  else
    limit = b->len;

  uint64_t diff = a->bits[0] ^ b->bits[0];
  if (diff) {
    prefix_len = (uint32_t)(BV_SIZE - (_diff_bit_log2(diff) + 1));
    // printf("if 1 diff = %lu plen = %d\n", diff, prefix_len);
  } else {
    prefix_len = BV_SIZE;
    diff = a->bits[1] ^ b->bits[1];
    if (diff) {
      prefix_len += (BV_SIZE - (_diff_bit_log2(diff) + 1));
      // printf("if 2 diff = %lu plen = %d\n", diff, prefix_len);
    } else {
      prefix_len += BV_SIZE;
    }
  }

  if (prefix_len < limit) return prefix_len;
  return limit;
}

void nameBitvector_clear(NameBitvector *a, uint8_t start_from) {
  for (uint8_t pos = start_from; pos < WIDTH; pos++)
    a->bits[pos / BV_SIZE] &= ~(ONE << ((BV_SIZE - 1) - (pos % BV_SIZE)));
}

int nameBitvector_ToIPAddress(const NameBitvector *name, ip_prefix_t *prefix) {
  if (name->IPversion == IPv4_TYPE) {
    struct in_addr *addr = (struct in_addr *)(&prefix->address.v4.buffer);
    prefix->family = AF_INET;
    prefix->len = IPV4_ADDR_LEN_BITS;

    uint32_t tmp_addr = name->bits[0] >> 32ULL;
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
    struct in6_addr *addr = (struct in6_addr *)(&prefix->address.v6.buffer);
    prefix->family = AF_INET6;
    prefix->len = name->len;  // IPV6_ADDR_LEN_BITS;

    for (int i = 0; i < 8; i++) {
      addr->s6_addr[i] = (uint8_t)((name->bits[0] >> 8 * (7 - i)) & 0xFF);
    }

    int x = 0;
    for (int i = 8; i < 16; ++i) {
      addr->s6_addr[i] = (uint8_t)((name->bits[1] >> 8 * (7 - x)) & 0xFF);
      x++;
    }
  }
  return true;
}

void nameBitvector_setLen(NameBitvector *name, uint8_t len) { name->len = len; }

void nameBitvector_ToAddress(const NameBitvector *name, address_t *address) {
  if (name->IPversion == IPv4_TYPE) {
    struct sockaddr_in *sin = address4(address);
    sin->sin_family = AF_INET;
    sin->sin_port = htons(DEFAULT_PORT);

    uint32_t tmp_addr = name->bits[0] >> 32ULL;
    uint8_t addr_1 = (tmp_addr & 0xff000000) >> 24;
    uint8_t addr_2 = (tmp_addr & 0x00ff0000) >> 16;
    uint8_t addr_3 = (tmp_addr & 0x0000ff00) >> 8;
    uint8_t addr_4 = (tmp_addr & 0x000000ff);

    sin->sin_addr.s_addr = 0;
    sin->sin_addr.s_addr = (sin->sin_addr.s_addr | addr_4) << 8;
    sin->sin_addr.s_addr = (sin->sin_addr.s_addr | addr_3) << 8;
    sin->sin_addr.s_addr = (sin->sin_addr.s_addr | addr_2) << 8;
    sin->sin_addr.s_addr = (sin->sin_addr.s_addr | addr_1);
  } else {
    struct sockaddr_in6 *sin6 = address6(address);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(DEFAULT_PORT);
    sin6->sin6_scope_id = 0;
    sin6->sin6_flowinfo = 0;

    for (int i = 0; i < 8; i++) {
      sin6->sin6_addr.s6_addr[i] =
          (uint8_t)((name->bits[0] >> 8 * (7 - i)) & 0xFF);
    }

    int x = 0;
    for (int i = 8; i < 16; ++i) {
      sin6->sin6_addr.s6_addr[i] =
          (uint8_t)((name->bits[1] >> 8 * (7 - x)) & 0xFF);
      x++;
    }
  }
}

char *nameBitvector_ToString(const NameBitvector *name) {
  char *output = malloc(WIDTH);

  address_t address;
  nameBitvector_ToAddress(name, &address);

  // XXX TODO
#if 0
    sprintf(output, "prefix: %s len: %u", addressToString(packetAddr), name->len);
#else
  snprintf(output, WIDTH, "%s", "ENOIMPL");
#endif

  return output;
}
