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
 * @file control_AddConnection.h
 * @brief Command-line "add connection" node
 *
 * Implements the "add connection" node of the CLI tree
 *
 *
 */

#ifndef controlAddConnection_h
#define controlAddConnection_h

#include <hicn/config/controlState.h>
CommandOps *controlAddConnection_Create(ControlState *state);
CommandOps *controlAddConnection_HelpCreate(ControlState *state);
#endif  // controlAddConnection_h
