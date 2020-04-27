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

#ifndef punting_h
#define punting_h

#include <hicn/core/address.h>

typedef struct {
  char *symbolic;
  address_t prefix;
  uint32_t len;
} punting_t;

#define punting_address(punting) (&((punting)->prefix))
#define punting_len(punting) ((punting)->len)

#if 0
struct punting;
typedef struct punting Punting;


/**
 * Creates a Punting object
 *
 * The symbolic name represents this listener and may be used by other commands.
 * It must be unique, otherwise the command will fail when sent to the
 * forwarder.
 *
 * @param [in] symbolic     name of the listener
 * @param [in] prefix       address to add to the punting rule
 * @param [in] len          prefix length
 *
 * @return non-null An Allocated object
 * @return null An error
 *
 */
Punting *puntingCreate(const char *symbolic, address_t *prefix, uint32_t len);

/**
 * Releases a reference count to the object
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in,out] etherConnPtr A pointer to an etherConn object, will be
 * null'd.
 *
 */
void puntingRelease(Punting **puntingPtr);

/**
 * Determine if two light Punting are equal.
 *
 */

bool puntingEquals(const Punting *a, const Punting *b);

/**
 * Returns the symbolic name
 *
 */
const char *puntingGetSymbolicName(const Punting *punting);

/**
 * Returns the address (INET or INET6 ip address)
 *
 */
address_t * puntingGetAddress(const Punting *punting);

uint32_t puntingPrefixLen(const Punting *punting);
#endif

#endif  // punting_h
