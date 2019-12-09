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

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>

struct listener_set {
  PARCArrayList *listOfListeners;
};

static void listenerSet_DestroyListenerOps(void **opsPtr) {
  ListenerOps *ops = *((ListenerOps **)opsPtr);
  ops->destroy(&ops);
}

ListenerSet *listenerSet_Create() {
  ListenerSet *set = parcMemory_AllocateAndClear(sizeof(ListenerSet));
  parcAssertNotNull(set, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ListenerSet));
  set->listOfListeners = parcArrayList_Create(listenerSet_DestroyListenerOps);

  return set;
}

void listenerSet_Destroy(ListenerSet **setPtr) {
  parcAssertNotNull(setPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*setPtr, "Parameter must dereference to non-null pointer");

  ListenerSet *set = *setPtr;
  parcArrayList_Destroy(&set->listOfListeners);
  parcMemory_Deallocate((void **)&set);
  *setPtr = NULL;
}

/**
 * @function listenerSet_Add
 * @abstract Adds the listener to the set
 * @discussion
 *     Unique set based on pair (EncapType, localAddress)
 *
 * @param <#param1#>
 * @return <#return#>
 */
bool listenerSet_Add(ListenerSet *set, ListenerOps *ops) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  parcAssertNotNull(ops, "Parameter ops must be non-null");

  int opsEncap = ops->getEncapType(ops);
  const address_t *opsAddress = ops->getListenAddress(ops);

  // make sure its not in the set
  size_t length = parcArrayList_Size(set->listOfListeners);
  for (size_t i = 0; i < length; i++) {
    ListenerOps *entry = parcArrayList_Get(set->listOfListeners, i);

    int entryEncap = entry->getEncapType(entry);
    const address_t *entryAddress = entry->getListenAddress(entry);

    if (opsEncap == entryEncap && address_equals(opsAddress, entryAddress)) {
      // duplicate
      return false;
    }
  }

  parcArrayList_Add(set->listOfListeners, ops);
  return true;
}

size_t listenerSet_Length(const ListenerSet *set) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  return parcArrayList_Size(set->listOfListeners);
}

/**
 * Returns the listener at the given index
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] set An allocated listener set
 * @param [in] index The index position (0 <= index < listenerSet_Count)
 *
 * @retval non-null The listener at index
 * @retval null An error
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
ListenerOps *listenerSet_Get(const ListenerSet *set, size_t index) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  return parcArrayList_Get(set->listOfListeners, index);
}

ListenerOps *listenerSet_Find(const ListenerSet *set, EncapType encapType,
                              const address_t *localAddress) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  parcAssertNotNull(localAddress, "Parameter localAddress must be non-null");

  ListenerOps *match = NULL;

  for (size_t i = 0; i < parcArrayList_Size(set->listOfListeners) && !match;
       i++) {
    ListenerOps *ops = parcArrayList_Get(set->listOfListeners, i);
    parcAssertNotNull(ops, "Got null listener ops at index %zu", i);

    if (ops->getEncapType(ops) == encapType) {
      if (address_equals(localAddress, ops->getListenAddress(ops))) {
        match = ops;
      }
    }
  }

  return match;
}

ListenerOps *listenerSet_FindById(const ListenerSet *set, unsigned id) {
  parcAssertNotNull(set, "Parameter set must be non-null");

  ListenerOps *match = NULL;

  for (size_t i = 0; i < parcArrayList_Size(set->listOfListeners) && !match;
       i++) {
    ListenerOps *ops = parcArrayList_Get(set->listOfListeners, i);
    parcAssertNotNull(ops, "Got null listener ops at index %zu", i);
    if (ops->getInterfaceIndex(ops) == id) {
        match = ops;
    }
  }

  return match;
}

int listenerSet_FindIdByListenerName(const ListenerSet *set, const char *listenerName ) {
  parcAssertNotNull(set, "Parameter set must be non-null");
  parcAssertNotNull(listenerName, "Parameter listenerName must be non-null");

  ListenerOps *match = NULL;
  int index = -1;
  for (size_t i = 0; i < parcArrayList_Size(set->listOfListeners) && !match;
       i++) {
    ListenerOps *ops = parcArrayList_Get(set->listOfListeners, i);
    parcAssertNotNull(ops, "Got null listener ops at index %zu", i);
    if (ops->getListenerName(ops) && strcmp(ops->getListenerName(ops), listenerName) == 0) {
        index = ops->getInterfaceIndex(ops);
        break;
    }
  }

  return index;
}

void listenerSet_RemoveById(const ListenerSet *set, unsigned id) {
  parcAssertNotNull(set, "Parameter set must be non-null");

  for (size_t i = 0; i < parcArrayList_Size(set->listOfListeners);
       i++) {
    ListenerOps *ops = parcArrayList_Get(set->listOfListeners, i);
    parcAssertNotNull(ops, "Got null listener ops at index %zu", i);
    if (ops->getInterfaceIndex(ops) == id) {
       parcArrayList_RemoveAndDestroyAtIndex(set->listOfListeners, i);
       break;
    }
  }
}
