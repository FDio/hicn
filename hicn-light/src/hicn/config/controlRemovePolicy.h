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
 * @file control_RemovePolicy.h
 * @brief Remove a policy from the FIB
 *
 * Implements the "remove policy" and "help remove policy" nodes of the command
 * tree
 *
 */

#ifndef Control_RemovePolicy_h
#define Control_RemovePolicy_h

#ifdef WITH_POLICY

#include <hicn/config/controlState.h>
CommandOps *controlRemovePolicy_Create(ControlState *state);
CommandOps *controlRemovePolicy_HelpCreate(ControlState *state);

#endif /* WITH_POLICY */

#endif  // Control_RemovePolicy_h
