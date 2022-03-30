/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef __TLOCK_H__
#define __TLOCK_H__

// limit on the number of locks: it shoud be matched with the  number of
// hicn-state leaves
#define MAX_LOCK_SIZE 5

volatile long int En[MAX_LOCK_SIZE], De[MAX_LOCK_SIZE];  // For Ticket Algorithm

void Ticket_init(int Lock_Number, long int init);
void Ticket_Lock(int Lock_Number);
void Ticket_Unlock(int Lock_Number);

#endif /* __IETF_HICN_H__ */