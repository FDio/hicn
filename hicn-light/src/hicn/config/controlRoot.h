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
 * @file control_Root.h
 * @brief Root of the command tree
 *
 * Implements the root of the command tree.  This is the one module that
 * needs to be seeded to the control state to build the whole tree.
 *
 */

#ifndef Control_Root_h
#define Control_Root_h

#include <hicn/config/controlState.h>
CommandOps *controlRoot_Create(ControlState *state);
CommandOps *controlRoot_HelpCreate(ControlState *state);
#endif  // Control_Root_h
