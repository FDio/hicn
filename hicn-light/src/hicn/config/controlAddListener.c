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
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>

#include <hicn/config/controlAddListener.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlAddListener_Execute(CommandParser *parser,
                                                 CommandOps *ops,
                                                 PARCList *args);
static CommandReturn _controlAddListener_HelpExecute(CommandParser *parser,
                                                     CommandOps *ops,
                                                     PARCList *args);

static const char *command_add_listener = "add listener";
static const char *command_help_add_listener = "help add listener";

CommandOps *controlAddListener_Create(ControlState *state) {
  return commandOps_Create(state, command_add_listener, NULL,
                           _controlAddListener_Execute, commandOps_Destroy);
}

CommandOps *controlAddListener_HelpCreate(ControlState *state) {
  return commandOps_Create(state, command_help_add_listener, NULL,
                           _controlAddListener_HelpExecute, commandOps_Destroy);
}

// ====================================================

static const int _indexProtocol = 2;
static const int _indexSymbolic = 3;
static const int _indexAddress = 4;
static const int _indexPort = 5;
static const int _indexInterfaceName = 6;

static CommandReturn _controlAddListener_HelpExecute(CommandParser *parser,
                                                     CommandOps *ops,
                                                     PARCList *args) {
  printf("commands:\n");
#ifdef __linux__
  printf("   add listener hicn <symbolic> <localAddress> \n");
#endif
  printf("   add listener udp <symbolic> <localAddress> <port> <interface>\n");
  printf("   add listener tcp <symbolic> <localAddress> <port> <interface>\n");
  printf("\n");
  printf(
      "   symbolic:        User defined name for listener, must start with "
      "alpha and be alphanum\n");
#ifdef __linux__
  printf("   protocol:        hicn | udp\n");
#else
  printf("   protocol:        udp\n");
#endif
  printf(
      "   localAddress:    IPv4 or IPv6 address (or prefix protocol = hicn) "
      "assigend to the local interface\n");
  printf("   port:            Udp port\n");

  printf("   interface:            interface\n");
  printf("\n");
  printf("Notes:\n");
  printf("   The symblic name must be unique or the source will reject it.\n");
#ifdef __linux__
  printf(
      "    If protocol = hicn: the address 0::0 indicates the main listern, "
      "for which we can set punting rules.\n");
#endif
  return CommandReturn_Success;
}

static CommandReturn _CreateListener(CommandParser *parser, CommandOps *ops,
                                     const char *symbolic, const char *addr,
                                     const char *port, char *interfaceName, listener_mode mode,
                                     connection_type type) {
  ControlState *state = ops->closure;

  // allocate command payload
  add_listener_command *addListenerCommand =
      parcMemory_AllocateAndClear(sizeof(add_listener_command));

  // check and set IP address
  if (inet_pton(AF_INET, addr, &addListenerCommand->address.v4.as_u32) == 1) {
    addListenerCommand->family = AF_INET;

  } else if (inet_pton(AF_INET6, addr, &addListenerCommand->address.v6.as_in6addr) == 1) {
    addListenerCommand->family = AF_INET6;

  } else {
    printf("Error: %s is not a valid network address \n", addr);
    parcMemory_Deallocate(&addListenerCommand);
    return CommandReturn_Failure;
  }

  // Fill remaining payload fields
  size_t name_size = strlen((const char *)interfaceName);
  if(name_size > SYMBOLIC_NAME_LEN){
    //cut the string
    name_size = SYMBOLIC_NAME_LEN;
  }

  memcpy(addListenerCommand->interfaceName, interfaceName, name_size);
  addListenerCommand->listenerMode = mode;
  addListenerCommand->connectionType = type;
  addListenerCommand->port = htons((uint16_t)atoi(port));
  strcpy(addListenerCommand->symbolic, symbolic);

  // send message and receive response
  struct iovec *response = utils_SendRequest(
      state, ADD_LISTENER, addListenerCommand, sizeof(add_listener_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}

static CommandReturn _controlAddListener_Execute(CommandParser *parser,
                                                 CommandOps *ops,
                                                 PARCList *args) {
  if (parcList_Size(args) != 5 && parcList_Size(args) != 7) {
    _controlAddListener_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  CommandReturn result = CommandReturn_Failure;

  const char *symbolic = parcList_GetAtIndex(args, _indexSymbolic);

  if (!utils_ValidateSymbolicName(symbolic)) {
    printf(
        "Error: symbolic name must begin with an alpha and be alphanum "
        "after\n");
    return result;
  }

  const char *protocol = parcList_GetAtIndex(args, _indexProtocol);
  const char *host = parcList_GetAtIndex(args, _indexAddress);
  char *interfaceName = parcList_GetAtIndex(args, _indexInterfaceName);
  if ((strcasecmp("hicn", protocol) == 0)) {
    const char *port =
        "1234";  // this is a random port number that will be ignored

    // here we discard the prefix len if it exists, since we don't use it in
    // code but we let libhicn to find the right ip address.
    return _CreateListener(parser, ops, symbolic, host, port, "hicn", HICN_MODE,
                           HICN_CONN);
  }
  const char *port = parcList_GetAtIndex(args, _indexPort);

  if ((strcasecmp("udp", protocol) == 0)) {
    return _CreateListener(parser, ops, symbolic, host, port, interfaceName, IP_MODE,
                           UDP_CONN);
  } else if ((strcasecmp("tcp", protocol) == 0)) {
    return _CreateListener(parser, ops, symbolic, host, port, interfaceName, IP_MODE,
                           TCP_CONN);
  } else {
    _controlAddListener_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  if (result == CommandReturn_Failure) printf("creation failed\n");

  return result;
}
