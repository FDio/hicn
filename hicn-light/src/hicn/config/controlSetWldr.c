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

#include <hicn/config/controlSetDebug.h>
#include <hicn/core/dispatcher.h>
#include <hicn/core/forwarder.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlSetWldr_Execute(CommandParser *parser,
                                             CommandOps *ops,
                                             PARCList *args,
                                             char *output,
                                             size_t output_size);
static CommandReturn _controlSetWldr_HelpExecute(CommandParser *parser,
                                                 CommandOps *ops,
                                                 PARCList *args,
                                                 char *output,
                                                 size_t output_size);

static const char *_commandSetWldr = "set wldr";
static const char *_commandSetWldrHelp = "help set wldr";

// ====================================================

CommandOps *controlSetWldr_Create(ControlState *state) {
  return commandOps_Create(state, _commandSetWldr, NULL,
                           _controlSetWldr_Execute, commandOps_Destroy);
}

CommandOps *controlSetWldr_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandSetWldrHelp, NULL,
                           _controlSetWldr_HelpExecute, commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlSetWldr_HelpExecute(CommandParser *parser,
                                                 CommandOps *ops,
                                                 PARCList *args,
                                                 char *output,
                                                 size_t output_size) {
  snprintf(output, output_size, "set wldr <on|off> <connection_id>\n\n");

  return CommandReturn_Success;
}

static CommandReturn _controlSetWldr_Execute(CommandParser *parser,
                                             CommandOps *ops,
                                             PARCList *args,
                                             char *output,
                                             size_t output_size) {
  ControlState *state = ops->closure;

  if (parcList_Size(args) != 4) {
    _controlSetWldr_HelpExecute(parser, ops, args, output, output_size);
    return CommandReturn_Failure;
  }

  if (((strcmp(parcList_GetAtIndex(args, 0), "set") != 0) ||
       (strcmp(parcList_GetAtIndex(args, 1), "wldr") != 0))) {
    _controlSetWldr_HelpExecute(parser, ops, args, output, output_size);
    return CommandReturn_Failure;
  }

  bool active;
  if (strcmp(parcList_GetAtIndex(args, 2), "on") == 0) {
    active = true;
  } else if (strcmp(parcList_GetAtIndex(args, 2), "off") == 0) {
    active = false;
  } else {
    _controlSetWldr_HelpExecute(parser, ops, args, output, output_size);
    return CommandReturn_Failure;
  }

  // check if valid connid
  const char *symbolicOrConnid = parcList_GetAtIndex(args, 3);

  if (!utils_ValidateSymbolicName(symbolicOrConnid) &&
      !utils_IsNumber(symbolicOrConnid)) {
    snprintf(output, output_size,
        "ERROR: Invalid symbolic or connid:\nsymbolic name must begin with an "
        "alpha followed by alphanum;\nconnid must be an integer\n");
    return CommandReturn_Failure;
  }

  // allocate command payload
  set_wldr_command *setWldrCommand =
      parcMemory_AllocateAndClear(sizeof(set_wldr_command));
  strcpy(setWldrCommand->symbolicOrConnid, symbolicOrConnid);
  if (active) {
    setWldrCommand->activate = ACTIVATE_ON;
  } else {
    setWldrCommand->activate = ACTIVATE_OFF;
  }

  // send message and receive response
  struct iovec *response = utils_SendRequest(state, SET_WLDR, setWldrCommand,
                                             sizeof(set_wldr_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}
