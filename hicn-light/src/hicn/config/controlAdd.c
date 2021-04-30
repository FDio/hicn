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

#include <parc/assert/parc_Assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/algol/parc_Memory.h>

#include <hicn/config/controlAdd.h>
#include <hicn/config/controlAddConnection.h>
#include <hicn/config/controlAddListener.h>
#include <hicn/config/controlAddPunting.h>
#include <hicn/config/controlAddRoute.h>
#ifdef WITH_POLICY
#include <hicn/config/controlAddPolicy.h>
#endif /* WITH_POLICY */

// ===================================================

static void _controlAdd_Init(CommandParser *parser, CommandOps *ops);

static CommandReturn _controlAdd_Execute(CommandParser *parser, 
                                         CommandOps *ops,
                                         PARCList *args,
                                         char *output,
                                         size_t output_size);

static CommandReturn _controlAdd_HelpExecute(CommandParser *parser,
                                             CommandOps *ops,
                                             PARCList *args,
                                             char *output,
                                             size_t output_size);

// ===================================================

static const char *command_add = "add";
static const char *help_command_add = "help add";

CommandOps *webControlAdd_Create(ControlState *state) {
  return commandOps_Create(state, command_add, _controlAdd_Init,
                           _controlAdd_Execute, commandOps_Destroy);
}

CommandOps *controlAdd_CreateHelp(ControlState *state) {
  return commandOps_Create(state, help_command_add, NULL,
                           _controlAdd_HelpExecute, commandOps_Destroy);
}

// ===================================================

static CommandReturn _controlAdd_HelpExecute(CommandParser *parser,
                                             CommandOps *ops,
                                             PARCList *args,
                                             char *output,
                                             size_t output_size) {
  CommandOps *ops_add_connection = controlAddConnection_Create(NULL);
  CommandOps *ops_add_route = controlAddRoute_Create(NULL);
  CommandOps *ops_add_punting = controlAddPunting_Create(NULL);
  CommandOps *ops_add_listener = controlAddListener_Create(NULL);
#ifdef WITH_POLICY
  CommandOps *ops_add_policy = controlAddPolicy_Create(NULL);
#endif /* WITH_POLICY */
#ifdef WITH_POLICY
  snprintf(output, output_size, "Available commands:\n   %s\n   %s\n   %s\n   %s\n   %s\n\n",
                                  ops_add_connection->command,
                                  ops_add_route->command,
                                  ops_add_punting->command,
                                  ops_add_listener->command,
                                  ops_add_policy->command);
#else
  snprintf(output, output_size, "Available commands:\n   %s\n   %s\n   %s\n   %s\n\n",
                                  ops_add_connection->command,
                                  ops_add_route->command,
                                  ops_add_punting->command,
                                  ops_add_listener->command);

#endif /* WITH_POLICY */

  commandOps_Destroy(&ops_add_connection);
  commandOps_Destroy(&ops_add_route);
  commandOps_Destroy(&ops_add_punting);
  commandOps_Destroy(&ops_add_listener);
#ifdef WITH_POLICY
  commandOps_Destroy(&ops_add_policy);
#endif /* WITH_POLICY */
  return CommandReturn_Success;
}

static void _controlAdd_Init(CommandParser *parser, CommandOps *ops) {
  ControlState *state = ops->closure;
  controlState_RegisterCommand(state, controlAddListener_HelpCreate(state));
  controlState_RegisterCommand(state, controlAddListener_Create(state));
  controlState_RegisterCommand(state, controlAddConnection_HelpCreate(state));
  controlState_RegisterCommand(state, controlAddRoute_HelpCreate(state));
  controlState_RegisterCommand(state, controlAddConnection_Create(state));
  controlState_RegisterCommand(state, controlAddRoute_Create(state));
  controlState_RegisterCommand(state, controlAddPunting_Create(state));
  controlState_RegisterCommand(state, controlAddPunting_HelpCreate(state));
#ifdef WITH_POLICY
  controlState_RegisterCommand(state, controlAddPolicy_HelpCreate(state));
  controlState_RegisterCommand(state, controlAddPolicy_Create(state));
#endif /* WITH_POLICY */
}

static CommandReturn _controlAdd_Execute(CommandParser *parser,
                                         CommandOps *ops,
                                         PARCList *args,
                                         char *output,
                                         size_t output_size) {
  return _controlAdd_HelpExecute(parser, ops, args, output, output_size);
}
