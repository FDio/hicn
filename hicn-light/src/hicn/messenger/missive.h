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
 * @file missive.h
 * @brief A Missive is a status message sent over a broadcast channel inside
 * hicn-light
 *
 * Recipients use {@link messenger_Register} to receive missives.  They are
 * broadcast to all recipients.
 *
 */
#ifndef missive_h
#define missive_h

#include <hicn/messenger/missiveType.h>

struct missive;
typedef struct missive Missive;

/**
 * Creates a Missive and sets the reference count to 1
 *
 * A Missive may be sent to listeners of the Messenger to inform them of events
 * on a connection id.
 *
 * @param [in] MissiveType The event type
 * @param [in] connectionid The relevant conneciton id
 *
 * @return non-null A message
 * @retrun null An error
 */
Missive *missive_Create(MissiveType missiveType, unsigned connectionid);

/**
 * Acquire a reference counted copy
 *
 * Increases the reference count by 1 and returns the original object.
 *
 * @param [in] missive An allocated missive
 *
 * @return non-null The original missive with increased reference count
 */
Missive *missive_Acquire(const Missive *missive);

/**
 * Releases a reference counted copy.
 *
 *  If it is the last reference, the missive is freed.
 *
 * @param [in,out] missivePtr Double pointer to a missive, will be nulled.
 */
void missive_Release(Missive **missivePtr);

/**
 * Returns the type of the missive
 *
 * Returns the type of event the missive represents
 *
 * @param [in] missive An allocated missive
 *
 * @return MissiveType The event type
 */
MissiveType missive_GetType(const Missive *missive);

/**
 * Returns the connection ID of the missive
 *
 * An event is usually associated with a connection id (i.e. the I/O channel
 * that originaged the event).
 *
 * @param [in] missive An allocated missive
 *
 * @return number The relevant connection id.
 */
unsigned missive_GetConnectionId(const Missive *missive);
#endif  // missive_h
