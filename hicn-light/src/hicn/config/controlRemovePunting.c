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

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>

#include <hicn/config/controlRemovePunting.h>

static CommandReturn _controlRemovePunting_Execute(CommandParser *parser,
                                                   CommandOps *ops,
                                                   PARCList *args);
static CommandReturn _controlRemovePunting_HelpExecute(CommandParser *parser,
                                                       CommandOps *ops,
                                                       PARCList *args);

// ===================================================

static const char *_commandRemovePunting = "remove punting";
static const char *_commandRemovePuntingHelp = "help punting connection";

// ====================================================

CommandOps *controlRemovePunting_Create(ControlState *state) {
  return commandOps_Create(state, _commandRemovePunting, NULL,
                           _controlRemovePunting_Execute, commandOps_Destroy);
}

CommandOps *controlRemovePunting_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandRemovePuntingHelp, NULL,
                           _controlRemovePunting_HelpExecute,
                           commandOps_Destroy);
}

// ====================================================

// ====================================================

static CommandReturn _controlRemovePunting_HelpExecute(CommandParser *parser,
                                                       CommandOps *ops,
                                                       PARCList *args) {
  printf("remove punting <symbolic> <prefix>\n");
  return CommandReturn_Success;
}

static CommandReturn _controlRemovePunting_Execute(CommandParser *parser,
                                                   CommandOps *ops,
                                                   PARCList *args) {
  printf("command not implemented\n");
  return _controlRemovePunting_HelpExecute(parser, ops, args);
}

// ==================================================
