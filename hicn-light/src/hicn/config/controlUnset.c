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

#include <parc/algol/parc_Memory.h>
#include <parc/security/parc_Security.h>

#include <hicn/config/controlUnset.h>
#include <hicn/config/controlUnsetDebug.h>

static void _controlUnset_Init(CommandParser *parser, CommandOps *ops);

static CommandReturn _controlUnset_Execute(CommandParser *parser,
                                           CommandOps *ops, PARCList *args);
static CommandReturn _controlUnset_HelpExecute(CommandParser *parser,
                                               CommandOps *ops, PARCList *args);

static const char *_commandUnset = "unset";
static const char *_commandUnsetHelp = "help unset";

// ===========================================================

CommandOps *controlUnset_Create(ControlState *state) {
  return commandOps_Create(state, _commandUnset, _controlUnset_Init,
                           _controlUnset_Execute, commandOps_Destroy);
}

CommandOps *controlUnset_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandUnsetHelp, NULL,
                           _controlUnset_HelpExecute, commandOps_Destroy);
}

// ===========================================================

static void _controlUnset_Init(CommandParser *parser, CommandOps *ops) {
  ControlState *state = ops->closure;
  controlState_RegisterCommand(state, controlUnsetDebug_Create(state));
  controlState_RegisterCommand(state, controlUnsetDebug_HelpCreate(state));
}

static CommandReturn _controlUnset_HelpExecute(CommandParser *parser,
                                               CommandOps *ops,
                                               PARCList *args) {
  CommandOps *ops_help_unset_debug = controlUnsetDebug_HelpCreate(NULL);

  printf("Available commands:\n");
  printf("   %s\n", ops_help_unset_debug->command);
  printf("\n");

  commandOps_Destroy(&ops_help_unset_debug);
  return CommandReturn_Success;
}

static CommandReturn _controlUnset_Execute(CommandParser *parser,
                                           CommandOps *ops, PARCList *args) {
  return _controlUnset_HelpExecute(parser, ops, args);
}
