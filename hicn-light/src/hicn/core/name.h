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

#ifndef name_h
#define name_h

#include <stdbool.h>
#include <stdlib.h>

#include "nameBitvector.h"

typedef struct {
  NameBitvector content_name;
  uint32_t segment;
  uint32_t name_hash;
} Name;

#define EMPTY_NAME \
  (Name) { .content_name = EMPTY_NAME_BITVECTOR, .segment = 0, .name_hash = 0, }

/**
 * Creates a name from packet
 *
 */
void name_create_from_interest(const uint8_t *packet, Name *name);
void name_create_from_data(const uint8_t *packet, Name *name);

/**
 * returns a copy of the name
 */
void name_Copy(const Name *original, Name *copy);

/**
 * A hash value for use in hash tables
 *
 */
uint32_t name_HashCode(const Name *name);

/**
 * Returns the content name without the segment value
 *
 */
NameBitvector *name_GetContentName(const Name *name);

/**
 * Returns the segment value
 *
 */
uint32_t name_GetSegment(const Name *name);

/**
 * Set the sequence number of the name provided
 *
 */
void name_SetSegment(Name *name, uint32_t segment);

/**
 * Determine if two HicnName instances are equal.
 */
bool name_Equals(const Name *a, const Name *b);

/**
 * Compares two names and returns their ordering
 *
 */
int name_Compare(const Name *a, const Name *b);

/**
 * return the name in string format (bitvector + segment number)
 *
 */
char *name_ToString(const Name *name);

/**
 * @function message_setNameLen
 * @abstract Sets a message name length
 * @param [in] message - Interest message
 * @param [in] len - Name length
 */
void name_setLen(Name *name, uint8_t len);

/**
 * Creates a name from a Address
 *
 */
void name_CreateFromAddress(Name *name, int family, ip_address_t addr,
                            uint8_t len);

#ifdef WITH_POLICY
uint32_t name_GetSuffix(const Name *name);
uint8_t name_GetLen(const Name *name);
#endif /* WITH_POLICY */

#endif  // name_h
