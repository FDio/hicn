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
#include <hicn/utils/punting.h>

#include <hicn/config/controlAddPunting.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlAddPunting_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args);
static CommandReturn _controlAddPunting_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args);

static const char *_commandAddPunting = "add punting";
static const char *_commandAddPuntingHelp = "help add punting";

static const int _indexSymbolic = 2;
static const int _indexPrefix = 3;

CommandOps *controlAddPunting_Create(ControlState *state) {
  return commandOps_Create(state, _commandAddPunting, NULL,
                           _controlAddPunting_Execute, commandOps_Destroy);
}

CommandOps *controlAddPunting_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddPuntingHelp, NULL,
                           _controlAddPunting_HelpExecute, commandOps_Destroy);
}

// =====================================================

static CommandReturn _controlAddPunting_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args) {
  printf("add punting <symbolic> <prefix>\n");
  printf("    <symbolic> : listener symbolic name\n");
  printf(
      "    <address>  : prefix to add as a punting rule. (example "
      "1234::0/64)\n");
  printf("\n");

  return CommandReturn_Success;
}

static CommandReturn _controlAddPunting_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args) {
  ControlState *state = ops->closure;

  if (parcList_Size(args) != 4) {
    _controlAddPunting_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  const char *symbolicOrConnid = parcList_GetAtIndex(args, _indexSymbolic);

  if (!utils_ValidateSymbolicName(symbolicOrConnid) &&
      !utils_IsNumber(symbolicOrConnid)) {
    printf(
        "ERROR: Invalid symbolic or connid:\n"
        "symbolic name must begin with an alpha followed by alphanum;\nconnid "
        "must be an integer\n");
    return CommandReturn_Failure;
  }

  const char *prefixStr = parcList_GetAtIndex(args, _indexPrefix);
  char *addr = (char *)malloc((strlen(prefixStr) + 1) * sizeof(char));

  // separate address and len
  char *slash;
  uint32_t len = 0;
  strcpy(addr, prefixStr);
  slash = strrchr(addr, '/');
  if (slash != NULL) {
    len = atoi(slash + 1);
    *slash = '\0';
  }

  // allocate command payload
  add_punting_command *addPuntingCommand =
      parcMemory_AllocateAndClear(sizeof(add_punting_command));

  // check and set IP address
  if (inet_pton(AF_INET, addr, &addPuntingCommand->address.v4.as_u32) == 1) {
    if (len > 32) {
      printf("ERROR: exceeded INET mask length, max=32\n");
      parcMemory_Deallocate(&addPuntingCommand);
      free(addr);
      return CommandReturn_Failure;
    }
    addPuntingCommand->family = AF_INET;
  } else if (inet_pton(AF_INET6, addr, &addPuntingCommand->address.v6.as_in6addr) == 1) {
    if (len > 128) {
      printf("ERROR: exceeded INET6 mask length, max=128\n");
      parcMemory_Deallocate(&addPuntingCommand);
      free(addr);
      return CommandReturn_Failure;
    }
    addPuntingCommand->family = AF_INET6;
  } else {
    printf("Error: %s is not a valid network address \n", addr);
    parcMemory_Deallocate(&addPuntingCommand);
    free(addr);
    return CommandReturn_Failure;
  }

  free(addr);

  // Fill remaining payload fields
  addPuntingCommand->len = len;
  strcpy(addPuntingCommand->symbolicOrConnid, symbolicOrConnid);

  // send message and receive response
  struct iovec *response = utils_SendRequest(
      state, ADD_PUNTING, addPuntingCommand, sizeof(add_punting_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}

// ======================================================================
