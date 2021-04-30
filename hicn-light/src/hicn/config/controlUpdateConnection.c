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

#ifdef WITH_POLICY

#include <hicn/hicn-light/config.h>

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>

#include <hicn/config/controlUpdateConnection.h>

#include <hicn/policy.h>
#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlUpdateConnection_Execute(CommandParser *parser,
                                                 CommandOps *ops,
                                                 PARCList *args,
                                                 char *output,
                                                 size_t output_size);
static CommandReturn _controlUpdateConnection_HelpExecute(CommandParser *parser,
                                                     CommandOps *ops,
                                                     PARCList *args,
                                                     char *output,
                                                     size_t output_size);

static const char *command_update_connection = "update connection";
static const char *command_help_update_connection = "help update connection";

CommandOps *controlUpdateConnection_Create(ControlState *state) {
  return commandOps_Create(state, command_update_connection, NULL,
                           _controlUpdateConnection_Execute, commandOps_Destroy);
}

CommandOps *controlUpdateConnection_HelpCreate(ControlState *state) {
  return commandOps_Create(state, command_help_update_connection, NULL,
                           _controlUpdateConnection_HelpExecute, commandOps_Destroy);
}

// ====================================================

static const int _indexSymbolic = 2;
static const int _indexTags = 3;

static CommandReturn _controlUpdateConnection_HelpExecute(CommandParser *parser,
                                                     CommandOps *ops,
                                                     PARCList *args,
                                                     char *output,
                                                     size_t output_size) {
  
  snprintf(output, output_size,
                     "commands:\n"
                     "   update connection <symbolic | id> <tags> \n"
                     "\n"
                     "   symbolic:        User defined name for connection, must start with "
                     "alpha and be alphanum\n"
                     "         id:        Identifier for the connection\n"
                     "   tags:            A string representing tags\n");
  return CommandReturn_Success;
}


static CommandReturn _controlUpdateConnection_Execute(CommandParser *parser,
                                                 CommandOps *ops,
                                                 PARCList *args,
                                                 char *output,
                                                 size_t output_size) {
  if ((parcList_Size(args) != 3) && (parcList_Size(args) != 4)) {
    _controlUpdateConnection_HelpExecute(parser, ops, args, output, output_size);
    return CommandReturn_Failure;
  }

  const char *symbolicOrConnid = parcList_GetAtIndex(args, _indexSymbolic);

  if (!utils_ValidateSymbolicName(symbolicOrConnid) &&
      !utils_IsNumber(symbolicOrConnid)) {
    snprintf(output, output_size,
        "ERROR: Invalid symbolic or connid:\nsymbolic name must begin with an "
        "alpha followed by alphanum;\nconnid must be an integer\n");
    return CommandReturn_Failure;
  }

  policy_tags_t tags = POLICY_TAGS_EMPTY;
  if (parcList_Size(args) == 4) {
    const char *str_tags = parcList_GetAtIndex(args, _indexTags);
  
    for (unsigned i = 0; str_tags[i] != 0; i++) {
      switch(tolower(str_tags[i])) {
        case 'e':
          policy_tags_add(&tags, POLICY_TAG_WIRED);
          break;
        case 'w':
          policy_tags_add(&tags, POLICY_TAG_WIFI);
          break;
        case 'c':
          policy_tags_add(&tags, POLICY_TAG_CELLULAR);
          break;
        case 'b':
          policy_tags_add(&tags, POLICY_TAG_BEST_EFFORT);
          break;
        case 'r':
          policy_tags_add(&tags, POLICY_TAG_REALTIME);
          break;
        case 'm':
          policy_tags_add(&tags, POLICY_TAG_MULTIPATH);
          break;
        case 't':
          policy_tags_add(&tags, POLICY_TAG_TRUSTED);
          break;
      }
    }
  }
  ControlState *state = ops->closure;

  // allocate command payload
  update_connection_command *updateConnectionCommand =
      parcMemory_AllocateAndClear(sizeof(update_connection_command));
  updateConnectionCommand->tags = tags;
  strcpy(updateConnectionCommand->symbolicOrConnid, symbolicOrConnid);

  // send message and receive response
  struct iovec *response = utils_SendRequest(
      state, UPDATE_CONNECTION, updateConnectionCommand, sizeof(update_connection_command));

  if (!response)  // get NULL pointer
    return CommandReturn_Failure;

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}

#endif /* WITH_POLICY */
