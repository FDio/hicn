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

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>
#include <src/utils/address.h>

#include <src/config/controlRemoveConnection.h>

#include <src/utils/commands.h>
#include <src/utils/utils.h>

static CommandReturn _controlRemoveConnection_Execute(CommandParser *parser,
                                                      CommandOps *ops,
                                                      PARCList *args);
static CommandReturn _controlRemoveConnection_HelpExecute(CommandParser *parser,
                                                          CommandOps *ops,
                                                          PARCList *args);

// ===================================================

static const char *_commandRemoveConnection = "remove connection";
static const char *_commandRemoveConnectionHelp = "help remove connection";

// ====================================================

CommandOps *controlRemoveConnection_Create(ControlState *state) {
  return commandOps_Create(state, _commandRemoveConnection, NULL,
                           _controlRemoveConnection_Execute,
                           commandOps_Destroy);
}

CommandOps *controlRemoveConnection_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandRemoveConnectionHelp, NULL,
                           _controlRemoveConnection_HelpExecute,
                           commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlRemoveConnection_HelpExecute(CommandParser *parser,
                                                          CommandOps *ops,
                                                          PARCList *args) {
  printf("command:\n");
  printf("    remove connection <symbolic|id>\n");
  return CommandReturn_Success;
}

static CommandReturn _controlRemoveConnection_Execute(CommandParser *parser,
                                                      CommandOps *ops,
                                                      PARCList *args) {
  ControlState *state = ops->closure;

  if (parcList_Size(args) != 3) {
    _controlRemoveConnection_HelpExecute(parser, ops, args);
    return false;
  }

  if ((strcmp(parcList_GetAtIndex(args, 0), "remove") != 0) ||
      (strcmp(parcList_GetAtIndex(args, 1), "connection") != 0)) {
    _controlRemoveConnection_HelpExecute(parser, ops, args);
    return false;
  }

  const char *symbolicOrConnid = parcList_GetAtIndex(args, 2);

  if (!utils_ValidateSymbolicName(symbolicOrConnid) &&
      !utils_IsNumber(symbolicOrConnid)) {
    printf(
        "ERROR: Invalid symbolic or connid:\nsymbolic name must begin with an "
        "alpha followed by alphanum;\nconnid must be an integer\n");
    return CommandReturn_Failure;
  }

  // allocate command payload
  remove_connection_command *removeConnectionCommand =
      parcMemory_AllocateAndClear(sizeof(remove_connection_command));
  // fill payload
  strcpy(removeConnectionCommand->symbolicOrConnid, symbolicOrConnid);

  // send message and receive response
  struct iovec *response =
      utils_SendRequest(state, REMOVE_CONNECTION, removeConnectionCommand,
                        sizeof(remove_connection_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}
