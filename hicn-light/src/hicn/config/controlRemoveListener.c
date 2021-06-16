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

#include <hicn/config/controlRemoveListener.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlRemoveListener_Execute(CommandParser *parser,
                                                      CommandOps *ops,
                                                      PARCList *args);
static CommandReturn _controlRemoveListener_HelpExecute(CommandParser *parser,
                                                          CommandOps *ops,
                                                          PARCList *args);

// ===================================================

static const char *_commandRemoveListener = "remove listener";
static const char *_commandRemoveListenerHelp = "help remove listener";

// ====================================================

CommandOps *controlRemoveListener_Create(ControlState *state) {
  return commandOps_Create(state, _commandRemoveListener, NULL,
                           _controlRemoveListener_Execute,
                           commandOps_Destroy);
}

CommandOps *controlRemoveListener_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandRemoveListenerHelp, NULL,
                           _controlRemoveListener_HelpExecute,
                           commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlRemoveListener_HelpExecute(CommandParser *parser,
                                                          CommandOps *ops,
                                                          PARCList *args) {
  printf("command:\n");
  printf("    remove listener <symbolic|id>\n");
  return CommandReturn_Success;
}

static CommandReturn _controlRemoveListener_Execute(CommandParser *parser,
                                                      CommandOps *ops,
                                                      PARCList *args) {
  ControlState *state = ops->closure;

  if (parcList_Size(args) != 3) {
    _controlRemoveListener_HelpExecute(parser, ops, args);
    return false;
  }

  if ((strcmp(parcList_GetAtIndex(args, 0), "remove") != 0) ||
      (strcmp(parcList_GetAtIndex(args, 1), "listener") != 0)) {
    _controlRemoveListener_HelpExecute(parser, ops, args);
    return false;
  }

  const char *listenerId = parcList_GetAtIndex(args, 2);

if (!utils_ValidateSymbolicName(listenerId) &&
      !utils_IsNumber(listenerId)) {
    printf(
        "ERROR: Invalid symbolic or listenerId:\nsymbolic name must begin with an "
        "alpha followed by alphanum;\nlistenerId must be an integer\n");
    return CommandReturn_Failure;
  }

  // allocate command payload
  remove_listener_command *removeListenerCommand =
      parcMemory_AllocateAndClear(sizeof(remove_listener_command));
  // fill payload
  //removeListenerCommand->listenerId = atoi(listenerId);
  snprintf(removeListenerCommand->symbolicOrListenerid, SYMBOLIC_NAME_LEN, "%s", listenerId);

  // send message and receive response
  struct iovec *response =
      utils_SendRequest(state, REMOVE_LISTENER, removeListenerCommand,
                        sizeof(remove_listener_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}
