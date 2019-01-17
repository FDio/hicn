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

#ifndef name_bitvector_h
#define name_bitvector_h

#include <hicn/hicn.h>
#include <stdint.h>
#include <stdlib.h>

#include <src/utils/address.h>

struct name_bitvector;
typedef struct name_bitvector NameBitvector;

NameBitvector *nameBitvector_CreateFromInAddr(uint32_t s_addr, uint8_t len);

NameBitvector *nameBitvector_CreateFromIn6Addr(struct in6_addr *addr,
                                               uint8_t len);

NameBitvector *nameBitvector_CreateFromAddress(const Address *prefix,
                                               uint8_t len);

NameBitvector *nameBitvector_Copy(const NameBitvector *original);

void nameBitvector_Destroy(NameBitvector **bitvectorPtr);

uint8_t nameBitvector_GetLength(const NameBitvector *name);

uint32_t nameBitvector_GetHash32(const NameBitvector *name);

bool nameBitvector_Equals(const NameBitvector *a, const NameBitvector *b);

int nameBitvector_Compare(const NameBitvector *a, const NameBitvector *b);

bool nameBitvector_StartsWith(const NameBitvector *name,
                              const NameBitvector *prefix);

bool nameBitvector_testBit(const NameBitvector *name, uint8_t pos);

uint8_t nameBitvector_firstDiff(const NameBitvector *a, const NameBitvector *b);

int nameBitvector_ToIPAddress(const NameBitvector *name,
                              ip_address_t *ip_address);
void nameBitvector_setLen(NameBitvector *name, uint8_t len);

Address *nameBitvector_ToAddress(const NameBitvector *name);

char *nameBitvector_ToString(const NameBitvector *name);

#endif  // name_bitvector_h
