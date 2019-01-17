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

#include <src/config/controlAddRoute.h>

#include <src/utils/commands.h>
#include <src/utils/utils.h>

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
  char addr[strlen(prefixStr) + 1];

  // separate address and len
  char *slash;
  uint32_t len = 0;
  strcpy(addr, prefixStr);
  slash = strrchr(addr, '/');
  if (slash != NULL) {
    len = atoi(slash + 1);
    *slash = '\0';
  }

  if (len == 0) {
    printf("ERROR: a prefix can not be of length 0\n");
    return CommandReturn_Failure;
  }

  // allocate command payload
  add_route_command *addRouteCommand =
      parcMemory_AllocateAndClear(sizeof(add_route_command));

  // check and set IP address
  if (inet_pton(AF_INET, addr, &addRouteCommand->address.ipv4) == 1) {
    if (len > 32) {
      printf("ERROR: exceeded INET mask length, max=32\n");
      parcMemory_Deallocate(&addRouteCommand);
      return CommandReturn_Failure;
    }
    addRouteCommand->addressType = ADDR_INET;
  } else if (inet_pton(AF_INET6, addr, &addRouteCommand->address.ipv6) == 1) {
    if (len > 128) {
      printf("ERROR: exceeded INET6 mask length, max=128\n");
      parcMemory_Deallocate(&addRouteCommand);
      return CommandReturn_Failure;
    }
    addRouteCommand->addressType = ADDR_INET6;
  } else {
    printf("Error: %s is not a valid network address \n", addr);
    parcMemory_Deallocate(&addRouteCommand);
    return CommandReturn_Failure;
  }

  // Fill remaining payload fields
  addRouteCommand->len = len;
  addRouteCommand->cost = (uint16_t)cost;
  strcpy(addRouteCommand->symbolicOrConnid, symbolicOrConnid);

  // send message and receive response
  struct iovec *response = utils_SendRequest(state, ADD_ROUTE, addRouteCommand,
                                             sizeof(add_route_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}
