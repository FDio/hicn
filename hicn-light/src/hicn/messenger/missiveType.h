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
 * @file missiveType
 * @brief Defines what a Missive represents
 *
 * Currently, missives only carry information about the state of a connection
 * (created, up, down, closed, destroyed).
 *
 */

#ifndef missiveType_h
#define missiveType_h

/**
 * @typedef Represents the state of a connection
 * @abstract CREATE is the initial state.  UP & DOWN are recurrent states.
 * CLOSED is transient.  DESTROYED is the terminal state.
 * @constant MissiveType_ConnectionCreate    Connection created (new)
 * @constant MissiveType_ConnectionUp        Connection is active and passing
 * data
 * @constant MissiveType_ConnectionDown      Connection is inactive and cannot
 * pass data
 * @constant MissiveType_ConnectionClosed    Connection closed and will be
 * destroyed
 * @constant MissiveType_ConnectionDestroyed Connection destroyed
 * @discussion State transitions:
 *                initial   -> CREATE
 *                CREATE    -> (UP | DOWN)
 *                UP        -> (DOWN | DESTROYED)
 *                DOWN      -> (UP | CLOSED | DESTROYED)
 *                CLOSED    -> DESTROYED
 *                DESTROYED -> terminal
 */
typedef enum {
  MissiveType_ConnectionCreate,
  MissiveType_ConnectionUp,
  MissiveType_ConnectionDown,
  MissiveType_ConnectionClosed,
  MissiveType_ConnectionDestroyed
} MissiveType;
#endif  // missiveType_h
