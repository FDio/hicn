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

#ifndef name_h
#define name_h

#include <stdbool.h>
#include <stdlib.h>

#include <hicn/core/messagePacketType.h>
#include <hicn/core/nameBitvector.h>
//#include <hicn/utils/address.h>

//#include <hicn/utils/commands.h>

struct name;
typedef struct name Name;

/**
 * Creates a name from packet
 *
 */
Name *name_CreateFromPacket(const uint8_t *memory, MessagePacketType type);

/**
 * Releases one reference count, and frees memory after last reference
 */
void name_Release(Name **namePtr);

/**
 * Acquires a reference to the name so that a reference count increments.
 * Notice however that this * function is used only when a new fib entry is
 * created (mostly configuration time) probably here performance are not
 * critical.
 */
Name *name_Acquire(const Name *original);

/**
 * returns a copy of the name
 */
Name *name_Copy(const Name *original);

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
Name *name_CreateFromAddress(int family, ip_address_t addr, uint8_t len);

#ifdef WITH_POLICY
uint32_t name_GetSuffix(const Name * name);
uint8_t name_GetLen(const Name * name);
#endif /* WITH_POLICY */

#endif  // name_h
