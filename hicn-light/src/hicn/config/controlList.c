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

#include <hicn/hicn-light/config.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/assert/parc_Assert.h>

#include <parc/security/parc_Security.h>

#include <parc/algol/parc_Memory.h>

#include <hicn/config/controlList.h>
#include <hicn/config/controlListConnections.h>
//#include <hicn/config/controlListInterfaces.h>
#include <hicn/config/controlListListeners.h>
#include <hicn/config/controlListRoutes.h>
#include <hicn/config/controlListStrategies.h>
#ifdef WITH_POLICY
#include <hicn/config/controlListPolicies.h>
#endif /* WITH_POLICY */

static void _controlList_Init(CommandParser *parser, CommandOps *ops);
static CommandReturn _controlList_Execute(CommandParser *parser,
                                          CommandOps *ops, PARCList *args);
static CommandReturn _controlList_HelpExecute(CommandParser *parser,
                                              CommandOps *ops, PARCList *args);

static const char *_commandList = "list";
static const char *_commandListHelp = "help list";

CommandOps *controlList_Create(ControlState *state) {
  return commandOps_Create(state, _commandList, _controlList_Init,
                           _controlList_Execute, commandOps_Destroy);
}

CommandOps *controlList_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandListHelp, NULL,
                           _controlList_HelpExecute, commandOps_Destroy);
}

// =====================================================

static CommandReturn _controlList_HelpExecute(CommandParser *parser,
                                              CommandOps *ops, PARCList *args) {
  CommandOps *ops_list_connections = controlListConnections_HelpCreate(NULL);
  // CommandOps *ops_list_interfaces = controlListInterfaces_HelpCreate(NULL);
  CommandOps *ops_list_routes = controlListRoutes_HelpCreate(NULL);
  CommandOps *ops_list_listeners = controlListListeners_HelpCreate(NULL);
  CommandOps *ops_list_strategies = controlListStrategies_HelpCreate(NULL);
#ifdef WITH_POLICY
  CommandOps *ops_list_policies = controlListPolicies_HelpCreate(NULL);
#endif /* WITH_POLICY */

  printf("Available commands:\n");
  printf("   %s\n", ops_list_connections->command);
  // printf("   %s\n", ops_list_interfaces->command);
  printf("   %s\n", ops_list_routes->command);
  printf("   %s\n", ops_list_listeners->command);
  printf("   %s\n", ops_list_strategies->command);
#ifdef WITH_POLICY
  printf("   %s\n", ops_list_policies->command);
#endif /* WITH_POLICY */
  printf("\n");

  commandOps_Destroy(&ops_list_connections);
  // commandOps_Destroy(&ops_list_interfaces);
  commandOps_Destroy(&ops_list_routes);
  commandOps_Destroy(&ops_list_listeners);
  commandOps_Destroy(&ops_list_strategies);
#ifdef WITH_POLICY
  commandOps_Destroy(&ops_list_policies);
#endif /* WITH_POLICY */

  return CommandReturn_Success;
}

static void _controlList_Init(CommandParser *parser, CommandOps *ops) {
  ControlState *state = ops->closure;
  controlState_RegisterCommand(state, controlListConnections_HelpCreate(state));
  // controlState_RegisterCommand(state,
  // controlListInterfaces_HelpCreate(state));
  controlState_RegisterCommand(state, controlListListeners_HelpCreate(state));
  controlState_RegisterCommand(state, controlListRoutes_HelpCreate(state));
  controlState_RegisterCommand(state, controlListStrategies_HelpCreate(state));
  controlState_RegisterCommand(state, controlListConnections_Create(state));
  // controlState_RegisterCommand(state, controlListInterfaces_Create(state));
  controlState_RegisterCommand(state, controlListRoutes_Create(state));
  controlState_RegisterCommand(state, controlListListeners_Create(state));
  controlState_RegisterCommand(state, controlListStrategies_Create(state));
#ifdef WITH_POLICY
  controlState_RegisterCommand(state, controlListPolicies_HelpCreate(state));
  controlState_RegisterCommand(state, controlListPolicies_Create(state));
#endif /* WITH_POLICY */
}

static CommandReturn _controlList_Execute(CommandParser *parser,
                                          CommandOps *ops, PARCList *args) {
  return _controlList_HelpExecute(parser, ops, args);
}

// ======================================================================
