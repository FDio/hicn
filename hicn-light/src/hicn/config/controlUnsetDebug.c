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

#include <hicn/config/controlUnsetDebug.h>
#include <hicn/core/dispatcher.h>
#include <hicn/core/forwarder.h>

static CommandReturn _controlUnsetDebug_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args,
                                                char *output,
                                                size_t output_size);
static CommandReturn _controlUnsetDebug_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args,
                                                    char *output,
                                                    size_t output_size);

static const char *_commandUnsetDebug = "unset debug";
static const char *_commandUnsetDebugHelp = "help unset debug";

// ====================================================

CommandOps *controlUnsetDebug_Create(ControlState *state) {
  return commandOps_Create(state, _commandUnsetDebug, NULL,
                           _controlUnsetDebug_Execute, commandOps_Destroy);
}

CommandOps *controlUnsetDebug_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandUnsetDebugHelp, NULL,
                           _controlUnsetDebug_HelpExecute, commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlUnsetDebug_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args,
                                                    char *output,
                                                    size_t output_size) {
  snprintf(output, output_size, "unset debug: will disable the debug flag\n\n");
  return CommandReturn_Success;
}

static CommandReturn _controlUnsetDebug_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args,
                                                char *output,
                                                size_t output_size) {
  if (parcList_Size(args) != 2) {
    _controlUnsetDebug_HelpExecute(parser, ops, args, output, output_size);
    return CommandReturn_Failure;
  }

  ControlState *state = ops->closure;
  controlState_SetDebug(state, false);
  snprintf(output, output_size, "Debug flag cleared\n\n");

  return CommandReturn_Success;
}
