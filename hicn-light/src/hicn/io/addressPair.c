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

#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/io/addressPair.h>

struct address_pair {
  Address *local;
  Address *remote;
};

static void _addressPair_Destroy(AddressPair **addressPairPtr) {
  AddressPair *pair = *addressPairPtr;

  addressDestroy(&pair->local);
  addressDestroy(&pair->remote);
}

parcObject_ExtendPARCObject(AddressPair, _addressPair_Destroy, NULL,
                            addressPair_ToString, addressPair_Equals, NULL,
                            addressPair_HashCode, NULL);

parcObject_ImplementAcquire(addressPair, AddressPair);

parcObject_ImplementRelease(addressPair, AddressPair);

AddressPair *addressPair_Create(const Address *local, const Address *remote) {
  parcAssertNotNull(local, "Parameter local must be non-null");
  parcAssertNotNull(remote, "Parameter remote must be non-null");

  AddressPair *pair = parcObject_CreateInstance(AddressPair);
  parcAssertNotNull(pair, "Got null from parcObject_Create()");

  pair->local = addressCopy(local);
  pair->remote = addressCopy(remote);

  return pair;
}

bool addressPair_Equals(const AddressPair *a, const AddressPair *b) {
  if (a == b) {
    return true;
  }
  if (a == NULL || b == NULL) {
    return false;
  }

  if (addressEquals(a->local, b->local)) {
    if (addressEquals(a->remote, b->remote)) {
      return true;
    }
  }

  return false;
}

bool addressPair_EqualsAddresses(const AddressPair *a, const Address *local,
                                 const Address *remote) {
  if (a == NULL || local == NULL || remote == NULL) {
    return false;
  }

  if (addressEquals(a->local, local)) {
    if (addressEquals(a->remote, remote)) {
      return true;
    }
  }

  return false;
}

char *addressPair_ToString(const AddressPair *pair) {
  parcAssertNotNull(pair, "Parameter pair must be non-null");

  char *local = addressToString(pair->local);
  char *remote = addressToString(pair->remote);

  char *output;
  int failure = asprintf(&output, "{ .local=%s, .remote=%s }", local, remote);
  parcAssertTrue(failure > -1, "Error on asprintf");

  parcMemory_Deallocate((void **)&local);
  parcMemory_Deallocate((void **)&remote);

  return output;
}

const Address *addressPair_GetLocal(const AddressPair *pair) {
  parcAssertNotNull(pair, "Parameter pair must be non-null");
  return pair->local;
}

const Address *addressPair_GetRemote(const AddressPair *pair) {
  parcAssertNotNull(pair, "Parameter pair must be non-null");
  return pair->remote;
}

/**
 * @function addressPair_HashCode
 * @abstract Hash useful for tables.  Consistent with Equals.
 * @discussion
 *   Returns a non-cryptographic hash that is consistent with equals.  That is,
 *   if a == b, then hash(a) == hash(b).
 *
 */
PARCHashCode addressPair_HashCode(const AddressPair *pair) {
  PARCHashCode hashpair[2];
  hashpair[0] = addressHashCode(pair->local);
  hashpair[1] = addressHashCode(pair->remote);
  return parcHashCode_Hash((const uint8_t *)hashpair, sizeof(hashpair));
}
