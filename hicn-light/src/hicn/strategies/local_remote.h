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

/**
 * Forward on a single path. If the incoming interest arrives from a local face,
 * the interest shuold be forwarded only on a remote face. Viceversa, if the
 * interest comes from remote it should be sent to a local face. Notice that if
 * the condition cannot be satified (e.g. an interest comes from a local face
 * and only an other local face can be satified to send the interest) the
 * interest is dropped
 */

#ifndef HICNLIGHT_STRATEGY_LOCAL_REMOTE_H
#define HICNLIGHT_STRATEGY_LOCAL_REMOTE_H

typedef struct {
  void *_;
} strategy_loc_rem_nexthop_state_t;

typedef struct {
  void *_;
} strategy_loc_rem_state_t;

typedef struct {
  void *_;
} strategy_loc_rem_options_t;

#endif /* HICNLIGHT_STRATEGY_LOCAL_REMOTE_H */
