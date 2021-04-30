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

#include <hicn/config/controlSet.h>
#include <hicn/config/controlSetDebug.h>
#include <hicn/config/controlSetStrategy.h>
#include <hicn/config/controlSetWldr.h>

static void _controlSet_Init(CommandParser *parser, CommandOps *ops);
static CommandReturn _controlSet_Execute(CommandParser *parser,
                                         CommandOps *ops,
                                         PARCList *args,
                                         char *output,
                                         size_t output_size);
static CommandReturn _controlSet_HelpExecute(CommandParser *parser,
                                             CommandOps *ops,
                                             PARCList *args,
                                             char *output,
                                             size_t output_size);

static const char *_commandSet = "set";
static const char *_commandSetHelp = "help set";

// ===========================================================

CommandOps *controlSet_Create(ControlState *state) {
  return commandOps_Create(state, _commandSet, _controlSet_Init,
                           _controlSet_Execute, commandOps_Destroy);
}

CommandOps *controlSet_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandSetHelp, NULL,
                           _controlSet_HelpExecute, commandOps_Destroy);
}

// ===========================================================

static void _controlSet_Init(CommandParser *parser, CommandOps *ops) {
  ControlState *state = ops->closure;
  controlState_RegisterCommand(state, controlSetDebug_Create(state));
  controlState_RegisterCommand(state, controlSetDebug_HelpCreate(state));
  controlState_RegisterCommand(state, controlSetStrategy_Create(state));
  controlState_RegisterCommand(state, controlSetStrategy_HelpCreate(state));
  controlState_RegisterCommand(state, controlSetWldr_Create(state));
  controlState_RegisterCommand(state, controlSetWldr_HelpCreate(state));
}

static CommandReturn _controlSet_HelpExecute(CommandParser *parser,
                                             CommandOps *ops,
                                             PARCList *args,
                                             char *output,
                                             size_t output_size) {
  CommandOps *ops_help_set_debug = controlSetDebug_HelpCreate(NULL);
  CommandOps *ops_help_set_strategy = controlSetStrategy_HelpCreate(NULL);
  CommandOps *ops_help_set_wldr = controlSetWldr_HelpCreate(NULL);

  snprintf(output, output_size, "Available commands:\n   %s\n   %s\n   %s\n\n",
                                ops_help_set_debug->command,
                                ops_help_set_strategy->command,
                                ops_help_set_wldr->command);

  commandOps_Destroy(&ops_help_set_debug);
  commandOps_Destroy(&ops_help_set_strategy);
  commandOps_Destroy(&ops_help_set_wldr);
  return CommandReturn_Success;
}

static CommandReturn _controlSet_Execute(CommandParser *parser,
                                         CommandOps *ops,
                                         PARCList *args,
                                         char *output,
                                         size_t output_size) {
  return _controlSet_HelpExecute(parser, ops, args, output, output_size);
}
