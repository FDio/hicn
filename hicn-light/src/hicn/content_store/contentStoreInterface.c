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

#include <hicn/content_store/contentStoreInterface.h>

void contentStoreInterface_Release(ContentStoreInterface **storeImplPtr) {
  (*storeImplPtr)->release(storeImplPtr);
}

bool contentStoreInterface_PutContent(ContentStoreInterface *storeImpl,
                                      Message *content,
                                      uint64_t currentTimeTicks) {
  return storeImpl->putContent(storeImpl, content, currentTimeTicks);
}

bool contentStoreInterface_RemoveContent(ContentStoreInterface *storeImpl,
                                         Message *content) {
  return storeImpl->removeContent(storeImpl, content);
}

Message *contentStoreInterface_MatchInterest(ContentStoreInterface *storeImpl,
                                             Message *interest,
                                             uint64_t currentTimeTicks) {
  return storeImpl->matchInterest(storeImpl, interest, currentTimeTicks);
}

size_t contentStoreInterface_GetObjectCapacity(
    ContentStoreInterface *storeImpl) {
  return storeImpl->getObjectCapacity(storeImpl);
}

size_t contentStoreInterface_GetObjectCount(ContentStoreInterface *storeImpl) {
  return storeImpl->getObjectCount(storeImpl);
}

void contentStoreInterface_Log(ContentStoreInterface *storeImpl) {
  storeImpl->log(storeImpl);
}

void *contentStoreInterface_GetPrivateData(ContentStoreInterface *storeImpl) {
  return storeImpl->_privateData;
}
