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
 * @file pitStandard.h
 * @brief The Pending Interest Table
 *
 * Implements the standard Pending Interest Table.
 *
 */

#ifndef pitStandard_h
#define pitStandard_h

#include <hicn/processor/pit.h>

/**
 * Creates a PIT table
 *
 * Creates and allocates an emtpy PIT table.  The Forwarder reference is
 * used for logging and for time functions.
 *
 * @param [in] hicn-light The releated Forwarder
 *
 * @return non-null a PIT table
 * @return null An error
 */
PIT *pitStandard_Create(Forwarder *forwarder);
#endif  // pit_h
