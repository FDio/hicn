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

#ifdef WITH_POLICY

#include <hicn/hicn-light/config.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/assert/parc_Assert.h>

#include <parc/security/parc_Security.h>

#include <parc/algol/parc_Memory.h>

#include <hicn/config/controlUpdate.h>
#include <hicn/config/controlUpdateConnection.h>

static void _controlUpdate_Init(CommandParser *parser, CommandOps *ops);
static CommandReturn _controlUpdate_Execute(CommandParser *parser,
                                          CommandOps *ops, PARCList *args);
static CommandReturn _controlUpdate_HelpExecute(CommandParser *parser,
                                              CommandOps *ops, PARCList *args);

static const char *_commandUpdate = "update";
static const char *_commandUpdateHelp = "help update";

CommandOps *controlUpdate_Create(ControlState *state) {
  return commandOps_Create(state, _commandUpdate, _controlUpdate_Init,
                           _controlUpdate_Execute, commandOps_Destroy);
}

CommandOps *controlUpdate_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandUpdateHelp, NULL,
                           _controlUpdate_HelpExecute, commandOps_Destroy);
}

// =====================================================

static CommandReturn _controlUpdate_HelpExecute(CommandParser *parser,
                                              CommandOps *ops, PARCList *args) {
  //CommandOps *ops_update_connections = controlUpdateConnections_HelpCreate(NULL);
  // CommandOps *ops_update_interfaces = controlUpdateInterfaces_HelpCreate(NULL);
  //CommandOps *ops_update_routes = controlUpdateRoutes_HelpCreate(NULL);
  CommandOps *ops_update_listeners = controlUpdateConnection_HelpCreate(NULL);

  printf("Available commands:\n");
  //printf("   %s\n", ops_update_connections->command);
  // printf("   %s\n", ops_update_interfaces->command);
  //printf("   %s\n", ops_update_routes->command);
  printf("   %s\n", ops_update_listeners->command);
  printf("\n");

 // commandOps_Destroy(&ops_update_connections);
  // commandOps_Destroy(&ops_update_interfaces);
  //commandOps_Destroy(&ops_update_routes);
  commandOps_Destroy(&ops_update_listeners);

  return CommandReturn_Success;
}

static void _controlUpdate_Init(CommandParser *parser, CommandOps *ops) {
  ControlState *state = ops->closure;
  //controlState_RegisterCommand(state, controlUpdateConnections_HelpCreate(state));
  // controlState_RegisterCommand(state,
  // controlUpdateInterfaces_HelpCreate(state));
  controlState_RegisterCommand(state, controlUpdateConnection_HelpCreate(state));
  //controlState_RegisterCommand(state, controlUpdateRoutes_HelpCreate(state));
  //controlState_RegisterCommand(state, controlUpdateConnections_Create(state));
  // controlState_RegisterCommand(state, controlUpdateInterfaces_Create(state));
  //controlState_RegisterCommand(state, controlUpdateRoutes_Create(state));
  controlState_RegisterCommand(state, controlUpdateConnection_Create(state));
}

static CommandReturn _controlUpdate_Execute(CommandParser *parser,
                                          CommandOps *ops, PARCList *args) {
  return _controlUpdate_HelpExecute(parser, ops, args);
}

#endif /* WITH_POLICY */
