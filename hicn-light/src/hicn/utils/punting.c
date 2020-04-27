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

#if 0
#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_Memory.h>
#include <hicn/utils/punting.h>

struct punting {
  char *symbolic;
  address_t *prefix;
  uint32_t len;
};

Punting *puntingCreate(const char *listenerName, address_t *prefix,
                       uint32_t len) {
  parcAssertNotNull(listenerName, "Parameter listenerName must be non-null");
  parcAssertNotNull(prefix, "Parameter prefix must be non-null");

  Punting *punting = parcMemory_AllocateAndClear(sizeof(Punting));
  if (punting) {
    punting->symbolic =
        parcMemory_StringDuplicate(listenerName, strlen(listenerName));
    punting->prefix = addressCopy(prefix);
    punting->len = len;
  }

  return punting;
}

void puntingRelease(Punting **puntingPtr) {
  parcAssertNotNull(puntingPtr,
                    "Parameter puntingPtr must be non-null double pointer");
  parcAssertNotNull(*puntingPtr,
                    "Parameter puntingPtr dereference to non-null pointer");

  Punting *punting = *puntingPtr;

  if (punting->symbolic) {
    parcMemory_Deallocate((void **)&punting->symbolic);
  }

  if (punting->prefix) {
    addressDestroy(&punting->prefix);
  }

  parcMemory_Deallocate((void **)&punting);
  *puntingPtr = NULL;
}

bool puntingEquals(const Punting *a, const Punting *b) {
  if ((a == NULL && b == NULL) || a == b) {
    // both null or identically equal
    return true;
  }

  if (a == NULL || b == NULL) {
    // only one is null
    return false;
  }

  if ((strcmp(a->symbolic, b->symbolic) == 0) &&
      (addressEquals(a->prefix, b->prefix)) && (a->len == b->len)) {
    return true;
  }

  return false;
}

const char *puntingGetSymbolicName(const Punting *punting) {
  parcAssertNotNull(punting, "Parameter listener must be non-null");
  return punting->symbolic;
}

address_t * puntingGetAddress(const Punting *punting) {
  parcAssertNotNull(punting, "Parameter listener must be non-null");
  return punting->prefix;
}

uint32_t puntingPrefixLen(const Punting *punting) {
  parcAssertNotNull(punting, "Parameter listener must be non-null");
  return punting->len;
}
#endif
