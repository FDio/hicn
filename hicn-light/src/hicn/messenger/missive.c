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

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/messenger/missive.h>

struct missive {
  MissiveType missiveType;
  unsigned connectionid;
};

parcObject_Override(Missive, PARCObject, .isLockable = false);

Missive *missive_Create(MissiveType missiveType, unsigned connectionid) {
  Missive *missive = parcObject_CreateInstance(Missive);
  missive->missiveType = missiveType;
  missive->connectionid = connectionid;
  return missive;
}

Missive *missive_Acquire(const Missive *missive) {
  return parcObject_Acquire(missive);
}

void missive_Release(Missive **missivePtr) {
  parcObject_Release((void **)missivePtr);
}

MissiveType missive_GetType(const Missive *missive) {
  parcAssertNotNull(missive, "Parameter missive must be non-null");
  return missive->missiveType;
}

unsigned missive_GetConnectionId(const Missive *missive) {
  parcAssertNotNull(missive, "Parameter missive must be non-null");
  return missive->connectionid;
}
