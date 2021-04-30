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

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/utils/interfaceSet.h>

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_Memory.h>

#include <parc/assert/parc_Assert.h>

struct interfaceSet {
  PARCArrayList *listOfInterfaces;
};

static void _destroyInterface(void **ifaceVoidPtr) {
  interfaceDestroy((Interface **)ifaceVoidPtr);
}

InterfaceSet *interfaceSetCreate(void) {
  InterfaceSet *set = parcMemory_AllocateAndClear(sizeof(InterfaceSet));
  parcAssertNotNull(set, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(InterfaceSet));
  set->listOfInterfaces = parcArrayList_Create(_destroyInterface);
  return set;
}

void interfaceSetDestroy(InterfaceSet **setPtr) {
  parcAssertNotNull(setPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*setPtr, "Parameter must dereference to non-null pointer");

  InterfaceSet *set = *setPtr;
  parcArrayList_Destroy(&set->listOfInterfaces);
  parcMemory_Deallocate((void **)&set);
  *setPtr = NULL;
}

bool interfaceSetAdd(InterfaceSet *set, Interface *iface) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  parcAssertNotNull(iface, "Parameter iface must be non-null");

  unsigned ifaceIndex = interfaceGetInterfaceIndex(iface);
  size_t length = parcArrayList_Size(set->listOfInterfaces);
  for (size_t i = 0; i < length; i++) {
    Interface *listEntry =
        (Interface *)parcArrayList_Get(set->listOfInterfaces, i);
    unsigned entryInterfaceIndex = interfaceGetInterfaceIndex(listEntry);
    if (entryInterfaceIndex == ifaceIndex) {
      return false;
    }
  }

  parcArrayList_Add(set->listOfInterfaces, (PARCObject *)iface);
  return true;
}

size_t interfaceSetLength(const InterfaceSet *set) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  return parcArrayList_Size(set->listOfInterfaces);
}

Interface *interfaceSetGetByOrdinalIndex(InterfaceSet *set,
                                         size_t ordinalIndex) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  return (Interface *)parcArrayList_Get(set->listOfInterfaces, ordinalIndex);
}

Interface *interfaceSetGetByInterfaceIndex(const InterfaceSet *set,
                                           unsigned interfaceIndex) {
  size_t length = parcArrayList_Size(set->listOfInterfaces);
  for (size_t i = 0; i < length; i++) {
    Interface *listEntry =
        (Interface *)parcArrayList_Get(set->listOfInterfaces, i);
    unsigned entryInterfaceIndex = interfaceGetInterfaceIndex(listEntry);
    if (entryInterfaceIndex == interfaceIndex) {
      return listEntry;
    }
  }
  return NULL;
}

/**
 * Uses the system name (e.g. "en0")
 *
 *   <#Discussion#>
 *
 * @param <#param1#>
 * @return NULL if not found
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
Interface *interfaceSetGetByName(InterfaceSet *set, const char *name) {
  size_t length = parcArrayList_Size(set->listOfInterfaces);
  for (size_t i = 0; i < length; i++) {
    Interface *listEntry =
        (Interface *)parcArrayList_Get(set->listOfInterfaces, i);
    if (interfaceNameEquals(listEntry, name)) {
      return listEntry;
    }
  }
  return NULL;
}

bool interfaceSetEquals(const InterfaceSet *a, const InterfaceSet *b) {
  if (a == NULL && b == NULL) {
    return true;
  }

  if (a == NULL || b == NULL) {
    return false;
  }

  size_t length_a = parcArrayList_Size(a->listOfInterfaces);
  size_t length_b = parcArrayList_Size(b->listOfInterfaces);

  if (length_a == length_b) {
    for (size_t i = 0; i < length_a; i++) {
      Interface *iface_a =
          (Interface *)parcArrayList_Get(a->listOfInterfaces, i);

      // the set is unique by interface id, so if it exists in set b, it
      // exists there by interface id
      Interface *iface_b = interfaceSetGetByInterfaceIndex(
          b, interfaceGetInterfaceIndex(iface_a));
      if (!interfaceEquals(iface_b, iface_b)) {
        return false;
      }
    }
    return true;
  }
  return false;
}
