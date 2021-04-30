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

/**
 * Generic interface to PIT table
 *
 */

#include <parc/assert/parc_Assert.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/processor/pit.h>

void *pit_Closure(const PIT *pit) { return pit->closure; }

void pit_Release(PIT **pitPtr) { (*pitPtr)->release(pitPtr); }

PITVerdict pit_ReceiveInterest(PIT *pit, Message *interestMessage) {
  return pit->receiveInterest(pit, interestMessage);
}

NumberSet *pit_SatisfyInterest(PIT *pit, const Message *objectMessage) {
  return pit->satisfyInterest(pit, objectMessage);
}

void pit_RemoveInterest(PIT *pit, const Message *interestMessage) {
  pit->removeInterest(pit, interestMessage);
}

PitEntry *pit_GetPitEntry(const PIT *pit, const Message *interestMessage) {
  return pit->getPitEntry(pit, interestMessage);
}
