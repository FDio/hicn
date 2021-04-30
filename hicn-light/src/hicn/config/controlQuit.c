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

#include <hicn/config/controlQuit.h>

static CommandReturn _controlQuit_Execute(CommandParser *parser,
                                          CommandOps *ops,
                                          PARCList *args,
                                          char *output,
                                          size_t output_size);
static CommandReturn _controlQuit_HelpExecute(CommandParser *parser,
                                              CommandOps *ops,
                                              PARCList *args,
                                              char *output,
                                              size_t output_size);

static const char *_commandQuit = "quit";
static const char *_commandQuitHelp = "help quit";

// ====================================================

CommandOps *controlQuit_Create(ControlState *state) {
  return commandOps_Create(state, _commandQuit, NULL, _controlQuit_Execute,
                           commandOps_Destroy);
}

CommandOps *controlQuit_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandQuitHelp, NULL,
                           _controlQuit_HelpExecute, commandOps_Destroy);
}

// ==============================================

static CommandReturn _controlQuit_HelpExecute(CommandParser *parser,
                                              CommandOps *ops,
                                              PARCList *args,
                                              char *output,
                                              size_t output_size) {
  snprintf(output, output_size, "Exits the interactive control program\n\n");
  return CommandReturn_Success;
}

static CommandReturn _controlQuit_Execute(CommandParser *parser,
                                          CommandOps *ops,
                                          PARCList *args,
                                          char *output,
                                          size_t output_size) {
  snprintf(output, output_size, "exiting interactive shell\n");
  return CommandReturn_Exit;
}
