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
 * @file pitVerdict.h
 * @brief Adding an entry to the PIT will return NEW or EXISTING
 *
 * Adding an entry to the PIT will return NEW or EXISTING
 *
 */

#ifndef pitVerdict_h
#define pitVerdict_h

/**
 * @typedef PitVerdict
 * @abstract The verdit of the PIT for receiving a message
 * @constant PITVerdict_Forward The message made a new PIT entry, the interest
 * should be forwarded
 * @constant PITVerdict_Aggregate The Interest was aggregated in the PIT, does
 * not need to be forwarded
 */
#ifdef WITH_POLICY
typedef enum { PITVerdict_Forward, PITVerdict_Aggregate, PITVerdict_Retransmit } PITVerdict;
#else
typedef enum { PITVerdict_Forward, PITVerdict_Aggregate } PITVerdict;
#endif /* WITH_POLICY */
#endif  // pitVerdict_h
