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

#include <hicn/config/controlAddRoute.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlAddRoute_Execute(CommandParser *parser,
                                              CommandOps *ops, PARCList *args);
static CommandReturn _controlAddRoute_HelpExecute(CommandParser *parser,
                                                  CommandOps *ops,
                                                  PARCList *args);

static const char *_commandAddRoute = "add route";
static const char *_commandAddRouteHelp = "help add route";

CommandOps *controlAddRoute_Create(ControlState *state) {
  return commandOps_Create(state, _commandAddRoute, NULL,
                           _controlAddRoute_Execute, commandOps_Destroy);
}

CommandOps *controlAddRoute_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddRouteHelp, NULL,
                           _controlAddRoute_HelpExecute, commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlAddRoute_HelpExecute(CommandParser *parser,
                                                  CommandOps *ops,
                                                  PARCList *args) {
  printf("commands:\n");
  printf("   add route <symbolic | connid> <prefix> <cost>\n");
  printf("\n");
  printf("   symbolic:  The symbolic name for an exgress\n");
  printf(
      "   connid:    The egress connection id (see 'help list connections')\n");
  printf(
      "   prefix:    The hicn name as IPv4 or IPv6 address (e.g 1234::0/64)\n");
  printf("   cost:      positive integer representing cost\n");
  printf("\n");
  return CommandReturn_Success;
}

static CommandReturn _controlAddRoute_Execute(CommandParser *parser,
                                              CommandOps *ops, PARCList *args) {
  ControlState *state = ops->closure;

  if (parcList_Size(args) != 5) {
    _controlAddRoute_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  const char *symbolicOrConnid = parcList_GetAtIndex(args, 2);

  if (!utils_ValidateSymbolicName(symbolicOrConnid) &&
      !utils_IsNumber(symbolicOrConnid)) {
    printf(
        "ERROR: Invalid symbolic or connid:\nsymbolic name must begin with an "
        "alpha followed by alphanum;\nconnid must be an integer\n");
    return CommandReturn_Failure;
  }

  unsigned cost = atoi(parcList_GetAtIndex(args, 4));

  if (cost == 0) {
    printf("ERROR: cost must be positive integer, got %u from '%s'\n", cost,
           (char *)parcList_GetAtIndex(args, 4));
    return CommandReturn_Failure;
  }

  const char *prefixStr = parcList_GetAtIndex(args, 3);
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
  cmd_route_add_t *cmd =
      parcMemory_AllocateAndClear(sizeof(cmd_route_add_t));

  // check and set IP address
  if (inet_pton(AF_INET, addr, &cmd->address.v4.as_u32) == 1) {
    if (len > 32) {
      printf("ERROR: exceeded INET mask length, max=32\n");
      parcMemory_Deallocate(&cmd);
      free(addr);
      return CommandReturn_Failure;
    }
    cmd->family = AF_INET;
  } else if (inet_pton(AF_INET6, addr, &cmd->address.v6.as_in6addr) == 1) {
    if (len > 128) {
      printf("ERROR: exceeded INET6 mask length, max=128\n");
      parcMemory_Deallocate(&cmd);
      free(addr);
      return CommandReturn_Failure;
    }
    cmd->family = AF_INET6;
  } else {
    printf("Error: %s is not a valid network address \n", addr);
    parcMemory_Deallocate(&cmd);
    free(addr);
    return CommandReturn_Failure;
  }

  free(addr);

  // Fill remaining payload fields
  cmd->len = len;
  cmd->cost = (uint16_t)cost;
  strcpy(cmd->symbolicOrConnid, symbolicOrConnid);

  // send message and receive response
  struct iovec *response = utils_SendRequest(state, COMMAND_TYPE_ROUTE_ADD, cmd,
                                             sizeof(cmd_route_add_t));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}
