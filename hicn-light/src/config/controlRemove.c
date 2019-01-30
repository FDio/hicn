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

#include <src/config.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <parc/assert/parc_Assert.h>

#include <parc/security/parc_Security.h>

#include <parc/algol/parc_Memory.h>

#include <src/config/controlRemove.h>
#include <src/config/controlRemoveConnection.h>
#include <src/config/controlRemovePunting.h>
#include <src/config/controlRemoveRoute.h>

static void _controlRemove_Init(CommandParser *parser, CommandOps *ops);
static CommandReturn _controlRemove_Execute(CommandParser *parser,
                                            CommandOps *ops, PARCList *args);
static CommandReturn _controlRemove_HelpExecute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args);

static const char *_commandRemove = "remove";
static const char *_commandRemoveHelp = "help remove";

// ====================================================

CommandOps *controlRemove_Create(ControlState *state) {
  return commandOps_Create(state, _commandRemove, _controlRemove_Init,
                           _controlRemove_Execute, commandOps_Destroy);
}

CommandOps *controlRemove_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandRemoveHelp, NULL,
                           _controlRemove_HelpExecute, commandOps_Destroy);
}

// ==============================================

static CommandReturn _controlRemove_HelpExecute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args) {
  CommandOps *ops_remove_connection = controlRemoveConnection_Create(NULL);
  CommandOps *ops_remove_route = controlRemoveRoute_Create(NULL);
  CommandOps *ops_remove_punting = controlRemovePunting_Create(NULL);

  printf("Available commands:\n");
  printf("   %s\n", ops_remove_connection->command);
  printf("   %s\n", ops_remove_route->command);
  printf("   %s\n", ops_remove_punting->command);
  printf("\n");

  commandOps_Destroy(&ops_remove_connection);
  commandOps_Destroy(&ops_remove_route);
  commandOps_Destroy(&ops_remove_punting);
  return CommandReturn_Success;
}

static void _controlRemove_Init(CommandParser *parser, CommandOps *ops) {
  ControlState *state = ops->closure;
  controlState_RegisterCommand(state,
                               controlRemoveConnection_HelpCreate(state));
  controlState_RegisterCommand(state, controlRemoveRoute_HelpCreate(state));
  controlState_RegisterCommand(state, controlRemoveConnection_Create(state));
  controlState_RegisterCommand(state, controlRemoveRoute_Create(state));
  controlState_RegisterCommand(state, controlRemovePunting_Create(state));
  controlState_RegisterCommand(state, controlRemovePunting_HelpCreate(state));
}

static CommandReturn _controlRemove_Execute(CommandParser *parser,
                                            CommandOps *ops, PARCList *args) {
  return _controlRemove_HelpExecute(parser, ops, args);
}
