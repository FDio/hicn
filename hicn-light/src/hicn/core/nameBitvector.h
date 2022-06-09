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

#ifndef name_bitvector_h
#define name_bitvector_h

#include <hicn/hicn.h>
#include <stdint.h>
#include <stdlib.h>

#include "address.h"

#define NAME_LEN 2
typedef struct __attribute__((__packed__)) {
  uint64_t bits[NAME_LEN];
  uint32_t len;
  uint32_t IPversion;
} NameBitvector;
static_assert(sizeof(NameBitvector) == 24,
              "Name prefix should be stored on 24 bytes");

#define EMPTY_NAME_BITVECTOR \
  (NameBitvector) { .bits[0] = 0, .bits[1] = 0, .len = 0, .IPversion = 0, }

void nameBitvector_CreateFromInAddr(NameBitvector *bitvector, uint32_t addr,
                                    uint8_t len);

void nameBitvector_CreateFromIn6Addr(NameBitvector *bitvector,
                                     struct in6_addr *addr, uint8_t len);

void nameBitvector_Copy(const NameBitvector *original, NameBitvector *copy);

uint8_t nameBitvector_GetLength(const NameBitvector *name);

uint32_t nameBitvector_GetHash32(const NameBitvector *name);

bool nameBitvector_Equals(const NameBitvector *a, const NameBitvector *b);

int nameBitvector_Compare(const NameBitvector *a, const NameBitvector *b);

int nameBitvector_testBit(const NameBitvector *name, uint8_t pos, bool *bit);

uint32_t nameBitvector_lpm(const NameBitvector *a, const NameBitvector *b);

void nameBitvector_clear(NameBitvector *a, uint8_t start_from);

int nameBitvector_ToIPAddress(const NameBitvector *name, ip_prefix_t *prefix);
void nameBitvector_setLen(NameBitvector *name, uint8_t len);

void nameBitvector_ToAddress(const NameBitvector *name, address_t *address);

char *nameBitvector_ToString(const NameBitvector *name);

#endif  // name_bitvector_h
