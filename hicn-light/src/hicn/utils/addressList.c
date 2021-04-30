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

#include <parc/assert/parc_Assert.h>

#include <hicn/utils/addressList.h>

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_Buffer.h>
#include <parc/algol/parc_Memory.h>

struct address_list {
  PARCArrayList *listOfAddress;
};

static void _addressListFreeAddress(void **addressVoidPtr) {
  Address **addressPtr = (Address **)addressVoidPtr;
  addressDestroy(addressPtr);
}

AddressList *addressListCreate() {
  AddressList *list = parcMemory_AllocateAndClear(sizeof(AddressList));
  parcAssertNotNull(list, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(AddressList));
  list->listOfAddress = parcArrayList_Create(_addressListFreeAddress);
  parcAssertNotNull(list->listOfAddress, "Got null from parcArrayList_Create");

  return list;
}

void addressListDestroy(AddressList **addressListPtr) {
  parcAssertNotNull(addressListPtr,
                    "Parameter must be non-null double pointer");
  parcAssertNotNull(*addressListPtr,
                    "Parameter must dereference to non-null pointer");
  AddressList *list = *addressListPtr;

  parcArrayList_Destroy(&list->listOfAddress);
  parcMemory_Deallocate((void **)&list);
  *addressListPtr = NULL;
}

AddressList *addressListAppend(AddressList *list, Address *address) {
  parcAssertNotNull(list, "Parameter list must be non-null");
  parcAssertNotNull(address, "Parameter address must be non-null");

  parcArrayList_Add(list->listOfAddress, (PARCObject *)address);
  return list;
}

AddressList *addressListCopy(const AddressList *original) {
  parcAssertNotNull(original, "Parameter must be non-null");

  AddressList *copy = addressListCreate();
  for (int i = 0; i < parcArrayList_Size(original->listOfAddress); i++) {
    Address *address = (Address *)parcArrayList_Get(original->listOfAddress, i);
    parcArrayList_Add(copy->listOfAddress, (PARCObject *)addressCopy(address));
  }

  return copy;
}

bool addressListEquals(const AddressList *a, const AddressList *b) {
  parcAssertNotNull(a, "Parameter a must be non-null");
  parcAssertNotNull(b, "Parameter b must be non-null");

  if (a == b) {
    return true;
  }

  if (parcArrayList_Size(a->listOfAddress) !=
      parcArrayList_Size(b->listOfAddress)) {
    return false;
  }

  for (size_t i = 0; i < parcArrayList_Size(a->listOfAddress); i++) {
    const Address *addr_a = (Address *)parcArrayList_Get(a->listOfAddress, i);
    const Address *addr_b = (Address *)parcArrayList_Get(b->listOfAddress, i);
    if (!addressEquals(addr_a, addr_b)) {
      return false;
    }
  }
  return true;
}

size_t addressListLength(const AddressList *list) {
  parcAssertNotNull(list, "Parameter must be non-null");
  return parcArrayList_Size(list->listOfAddress);
}

const Address *addressListGetItem(const AddressList *list, size_t item) {
  parcAssertNotNull(list, "Parameter must be non-null");
  parcAssertTrue(item < addressListLength(list),
                 "Asked for item %zu beyond end of list %zu", item,
                 addressListLength(list));

  return (Address *)parcArrayList_Get(list->listOfAddress, item);
}

char *addressListToString(const AddressList *list) {
  PARCBufferComposer *composer = parcBufferComposer_Create();

  for (size_t i = 0; i < addressListLength(list); i++) {
    char *addressString = addressToString(addressListGetItem(list, i));
    parcBufferComposer_PutString(composer, addressString);
    if (i < (addressListLength(list) - 1)) {
      parcBufferComposer_PutString(composer, " ");
    }
    parcMemory_Deallocate((void **)&addressString);
  }

  PARCBuffer *buffer = parcBufferComposer_ProduceBuffer(composer);
  char *result = parcBuffer_ToString(buffer);
  parcBuffer_Release(&buffer);
  parcBufferComposer_Release(&composer);

  return result;
}
