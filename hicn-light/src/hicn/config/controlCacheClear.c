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

#include <hicn/config/controlCacheClear.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlCacheClear_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args);
static CommandReturn _controlCacheClear_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args);

static const char *_commandCacheClear = "cache clear";
static const char *_commandCacheClearHelp = "help cache clear";

// ====================================================

CommandOps *controlCacheClear_Create(ControlState *state) {
  return commandOps_Create(state, _commandCacheClear, NULL,
                           _controlCacheClear_Execute, commandOps_Destroy);
}

CommandOps *controlCacheClear_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandCacheClearHelp, NULL,
                           _controlCacheClear_HelpExecute, commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlCacheClear_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args) {
  printf("cache clear\n");
  printf("\n");

  return CommandReturn_Success;
}

static CommandReturn _controlCacheClear_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args) {
  if (parcList_Size(args) != 2) {
    _controlCacheClear_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  ControlState *state = ops->closure;
  // send message and receive response
  struct iovec *response = utils_SendRequest(state, CACHE_CLEAR, NULL, 0);

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}
