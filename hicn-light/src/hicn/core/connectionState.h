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
 * @file connection_state.h
 * @brief Represents the state of a connection
 *
 */

#ifndef connection_state_h
#define connection_state_h

#define foreach_connection_state        \
    _(UNDEFINED)                        \
    _(DOWN)                             \
    _(UP)                               \
    _(N)

typedef enum {
#define _(x) CONNECTION_STATE_ ## x,
foreach_connection_state
#undef _
} connection_state_t;

#endif /* connection_state_h */
