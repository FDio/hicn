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

#include <hicn/config/controlListInterfaces.h>

static CommandReturn _controlListInterfaces_Execute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args,
                                                    char *output,
                                                    size_t output_size);
static CommandReturn _controlListInterfaces_HelpExecute(CommandParser *parser,
                                                        CommandOps *ops,
                                                        PARCList *args,
                                                        char *output,
                                                        size_t output_size);

static const char *_commandListInterfaces = "list interfaces";
static const char *_commandListInterfacesHelp = "help list interfaces";

// ====================================================

CommandOps *controlListInterfaces_Create(ControlState *state) {
  return commandOps_Create(state, _commandListInterfaces, NULL,
                           _controlListInterfaces_Execute, commandOps_Destroy);
}

CommandOps *controlListInterfaces_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandListInterfacesHelp, NULL,
                           _controlListInterfaces_HelpExecute,
                           commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlListInterfaces_HelpExecute(CommandParser *parser,
                                                        CommandOps *ops,
                                                        PARCList *args,
                                                        char *output,
                                                        size_t output_size) {
  snprintf(output, output_size, "list interfaces\n\n")
  return CommandReturn_Success;
}

static CommandReturn _controlListInterfaces_Execute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args,
                                                    char *output,
                                                    size_t output_size) {
  if (parcList_Size(args) != 2) {
    _controlListInterfaces_HelpExecute(parser, ops, args, output, output_size);
    return CommandReturn_Failure;
  }

  //==========================        NOT IMPLEMENTED
  //===========================

  return CommandReturn_Success;
}
