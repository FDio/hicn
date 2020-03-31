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
#include <parc/algol/parc_List.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>
#include <parc/assert/parc_Assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <hicn/config/controlRemovePolicy.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlRemovePolicy_Execute(CommandParser *parser,
                                                 CommandOps *ops,
                                                 PARCList *args);
static CommandReturn _controlRemovePolicy_HelpExecute(CommandParser *parser,
                                                     CommandOps *ops,
                                                     PARCList *args);

// ===================================================

static const char *_commandRemovePolicy = "remove policy";
static const char *_commandRemovePolicyHelp = "help remove policy";

// ====================================================

CommandOps *controlRemovePolicy_Create(ControlState *state) {
  return commandOps_Create(state, _commandRemovePolicy, NULL,
                           _controlRemovePolicy_Execute, commandOps_Destroy);
}

CommandOps *controlRemovePolicy_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandRemovePolicyHelp, NULL,
                           _controlRemovePolicy_HelpExecute, commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlRemovePolicy_HelpExecute(CommandParser *parser,
                                                     CommandOps *ops,
                                                     PARCList *args) {
  printf("commands:\n");
  printf("    remove policy <prefix>\n");
  return CommandReturn_Success;
}

static CommandReturn _controlRemovePolicy_Execute(CommandParser *parser,
                                                 CommandOps *ops,
                                                 PARCList *args) {
  ControlState *state = ops->closure;

  if (parcList_Size(args) != 3) {
    _controlRemovePolicy_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  const char *prefixStr = parcList_GetAtIndex(args, 2);
  char *addr = (char *)malloc(sizeof(char) * (strlen(prefixStr) + 1));

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
  remove_policy_command *removePolicyCommand =
      parcMemory_AllocateAndClear(sizeof(remove_policy_command));

  // check and set IP address
  if (inet_pton(AF_INET, addr, &removePolicyCommand->address.v4.as_u32) == 1) {
    if (len > 32) {
      printf("ERROR: exceeded INET mask length, max=32\n");
      parcMemory_Deallocate(&removePolicyCommand);
      free(addr);
      return CommandReturn_Failure;
    }
    removePolicyCommand->family = AF_INET;
  } else if (inet_pton(AF_INET6, addr, &removePolicyCommand->address.v6.as_in6addr) ==
             1) {
    if (len > 128) {
      printf("ERROR: exceeded INET6 mask length, max=128\n");
      parcMemory_Deallocate(&removePolicyCommand);
      free(addr);
      return CommandReturn_Failure;
    }
    removePolicyCommand->family = AF_INET6;
  } else {
    printf("Error: %s is not a valid network address \n", addr);
    parcMemory_Deallocate(&removePolicyCommand);
    free(addr);
    return CommandReturn_Failure;
  }

  free(addr);
  // Fill remaining payload fields
  removePolicyCommand->len = len;

  // send message and receive response
  struct iovec *response = utils_SendRequest(
      state, REMOVE_POLICY, removePolicyCommand, sizeof(remove_policy_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}

#endif /* WITH_POLICY */
