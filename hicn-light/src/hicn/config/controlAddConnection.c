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

#include <src/hicn/config.h>

#include <ctype.h>
#include <parc/assert/parc_Assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>

#include <hicn/config/controlAddConnection.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

// ===================================================

static void _controlAddConnection_Init(CommandParser *parser, CommandOps *ops);
static CommandReturn _controlAddConnection_HelpExecute(CommandParser *parser,
                                                       CommandOps *ops,
                                                       PARCList *args);
static CommandReturn _controlAddConnection_Execute(CommandParser *parser,
                                                   CommandOps *ops,
                                                   PARCList *args);

// ===================================================

static CommandReturn _controlAddConnection_HicnHelpExecute(
    CommandParser *parser, CommandOps *ops, PARCList *args);
static CommandReturn _controlAddConnection_HicnExecute(CommandParser *parser,
                                                       CommandOps *ops,
                                                       PARCList *args);

static CommandReturn _controlAddConnection_UdpHelpExecute(CommandParser *parser,
                                                          CommandOps *ops,
                                                          PARCList *args);
static CommandReturn _controlAddConnection_UdpExecute(CommandParser *parser,
                                                      CommandOps *ops,
                                                      PARCList *args);

static CommandReturn _controlAddConnection_TcpHelpExecute(CommandParser *parser,
                                                          CommandOps *ops,
                                                          PARCList *args);
static CommandReturn _controlAddConnection_TcpExecute(CommandParser *parser,
                                                      CommandOps *ops,
                                                      PARCList *args);

// ===================================================

static const char *_commandAddConnection = "add connection";
static const char *_commandAddConnectionHicn = "add connection hicn";
static const char *_commandAddConnectionUdp = "add connection udp";
static const char *_commandAddConnectionTcp = "add connection tcp";
static const char *_commandAddConnectionHelp = "help add connection";
static const char *_commandAddConnectionHicnHelp = "help add connection hicn";
static const char *_commandAddConnectionUdpHelp = "help add connection udp";
static const char *_commandAddConnectionTcpHelp = "help add connection tcp";

// ===================================================

CommandOps *controlAddConnection_Create(ControlState *state) {
  return commandOps_Create(state, _commandAddConnection,
                           _controlAddConnection_Init,
                           _controlAddConnection_Execute, commandOps_Destroy);
}

CommandOps *controlAddConnection_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddConnectionHelp, NULL,
                           _controlAddConnection_HelpExecute,
                           commandOps_Destroy);
}

// ===================================================

static CommandOps *_controlAddConnection_HicnCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddConnectionHicn, NULL,
                           _controlAddConnection_HicnExecute,
                           commandOps_Destroy);
}

static CommandOps *_controlAddConnection_UdpCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddConnectionUdp, NULL,
                           _controlAddConnection_UdpExecute,
                           commandOps_Destroy);
}

static CommandOps *_controlAddConnection_TcpCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddConnectionTcp, NULL,
                           _controlAddConnection_TcpExecute,
                           commandOps_Destroy);
}

// ===================================================

static CommandOps *_controlAddConnection_HicnHelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddConnectionHicnHelp, NULL,
                           _controlAddConnection_HicnHelpExecute,
                           commandOps_Destroy);
}

static CommandOps *_controlAddConnection_UdpHelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddConnectionUdpHelp, NULL,
                           _controlAddConnection_UdpHelpExecute,
                           commandOps_Destroy);
}

static CommandOps *_controlAddConnection_TcpHelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddConnectionTcpHelp, NULL,
                           _controlAddConnection_TcpHelpExecute,
                           commandOps_Destroy);
}

// ===================================================

static CommandReturn _controlAddConnection_HelpExecute(CommandParser *parser,
                                                       CommandOps *ops,
                                                       PARCList *args) {
  printf("Available commands:\n");
  printf("   %s\n", _commandAddConnectionHicn);
  printf("   %s\n", _commandAddConnectionUdp);
  printf("   %s\n", _commandAddConnectionTcp);
  printf("\n");
  return CommandReturn_Success;
}

static void _controlAddConnection_Init(CommandParser *parser, CommandOps *ops) {
  ControlState *state = ops->closure;
  controlState_RegisterCommand(state,
                               _controlAddConnection_HicnHelpCreate(state));
  controlState_RegisterCommand(state,
                               _controlAddConnection_UdpHelpCreate(state));
  controlState_RegisterCommand(state,
                               _controlAddConnection_TcpHelpCreate(state));

  controlState_RegisterCommand(state, _controlAddConnection_HicnCreate(state));
  controlState_RegisterCommand(state, _controlAddConnection_UdpCreate(state));
  controlState_RegisterCommand(state, _controlAddConnection_TcpCreate(state));
}

static CommandReturn _controlAddConnection_Execute(CommandParser *parser,
                                                   CommandOps *ops,
                                                   PARCList *args) {
  return _controlAddConnection_HelpExecute(parser, ops, args);
}

// ===================================================
// functions general to all connection types

/**
 * Create a tunnel in the forwarder based on the addresses
 *
 * Caller retains ownership of memory.
 * The symbolic name will be used to refer to this connection. It must be unqiue
 * otherwise the forwarder will reject this commend.
 *
 * @param [in] parser An allocated CommandParser
 * @param [in] ops Allocated CommandOps (needed to extract ControlState)
 * @param [in] localAddress the local IP and port.  The port may be the wildcard
 * value.
 * @param [in] remoteAddress The remote IP and port (both must be specified)
 * @param [in] tunnelType The tunneling protocol
 * @param [in] symbolic The symbolic name for the connection (must be unique)
 *
 * @return <#value#> <#explanation#>
 *
 * Example:
 * @code
 * {
 *      struct sockaddr_in *anyAddress = parcNetwork_SockInet4AddressAny();
 *      struct sockaddr_in *remote     =
 * parcNetwork_SockInet4Address("192.168.1.2", 9695);
 *
 *      Address *localAddress = addressCreateFromInet(anyAddress);
 *      Address *remoteAddress = addressCreateFromInet(remote);
 *
 *      control_CreateTunnel(state, localAddress, remoteAddress, IPTUN_TCP,
 * "conn7");
 *
 *      addressDestroy(&localAddress);
 *      addressDestroy(&remoteAddress);
 *      parcMemory_Deallocate((void **)&remote);
 *      parcMemory_Deallocate((void **)&anyAddress);
 * }
 * @endcode
 */

static CommandReturn _controlAddConnection_CreateTunnel(
    CommandParser *parser, CommandOps *ops, const char *local_ip,
    const char *local_port, const char *remote_ip, const char *remote_port,
    connection_type tunnelType, const char *symbolic) {
  ControlState *state = ops->closure;
  // a request like this always has an interface index of 0 [FIELD REMOVED]
  // unsigned int interfaceIndex = 0;

  // allocate command payload
  add_connection_command *addConnectionCommand =
      parcMemory_AllocateAndClear(sizeof(add_connection_command));

  // check and set IP addresses
  if (inet_pton(AF_INET, remote_ip, &addConnectionCommand->remoteIp.ipv4) ==
          1 &&
      inet_pton(AF_INET, local_ip, &addConnectionCommand->localIp.ipv4) == 1) {
    addConnectionCommand->ipType = ADDR_INET;

  } else if (inet_pton(AF_INET6, remote_ip,
                       &addConnectionCommand->remoteIp.ipv6) == 1 &&
             inet_pton(AF_INET6, local_ip,
                       &addConnectionCommand->localIp.ipv6) == 1) {
    addConnectionCommand->ipType = ADDR_INET6;

  } else {
    printf("Error: local address %s not same type as remote address %s\n",
           local_ip, remote_ip);
    parcMemory_Deallocate(&addConnectionCommand);
    return CommandReturn_Failure;
  }

  // Fill remaining payload fields
  addConnectionCommand->connectionType = tunnelType;
  strcpy(addConnectionCommand->symbolic, symbolic);
  addConnectionCommand->remotePort = htons((uint16_t)atoi(remote_port));
  addConnectionCommand->localPort = htons((uint16_t)atoi(local_port));

  // send message and receive response
  struct iovec *response =
      utils_SendRequest(state, ADD_CONNECTION, addConnectionCommand,
                        sizeof(add_connection_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}

static CommandReturn _controlAddConnection_IpHelp(CommandParser *parser,
                                                  CommandOps *ops,
                                                  PARCList *args,
                                                  const char *protocol) {
  printf("add connection hicn <symbolic> <remote_ip> <local_ip>\n");
  printf(
      "add connection udp <symbolic> <remote_ip> <port> <local_ip> <port>\n");
  printf(
      "  <symbolic>              : symbolic name, e.g. 'conn1' (must be "
      "unique, start with alpha)\n");
  printf(
      "  <remote_ip>  : the IPv4 or IPv6 or hostname of the remote system\n");
  printf("  <local_ip>              : optional local IP address to bind to\n");
  printf("\n");
  return CommandReturn_Success;
}

static CommandReturn _controlAddConnection_HicnHelpExecute(
    CommandParser *parser, CommandOps *ops, PARCList *args) {
  _controlAddConnection_IpHelp(parser, ops, args, "hicn");

  return CommandReturn_Success;
}

static CommandReturn _controlAddConnection_HicnExecute(CommandParser *parser,
                                                       CommandOps *ops,
                                                       PARCList *args) {
  static const int _indexSymbolic = 3;
  static const int _indexRemAddr = 4;
  static const int _indexLocAddr = 5;

  if (parcList_Size(args) != 6) {
    _controlAddConnection_HicnHelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  char *symbolic = parcList_GetAtIndex(args, _indexSymbolic);

  if (!utils_ValidateSymbolicName(symbolic)) {
    printf(
        "Invalid symbolic name.  Must begin with alpha and contain only "
        "alphanum.\n");
    return CommandReturn_Failure;
  }

  char *remote_ip = parcList_GetAtIndex(args, _indexRemAddr);
  char *local_ip = parcList_GetAtIndex(args, _indexLocAddr);
  char *port = "1234";  // this is a random port number that will be ignored

  return _controlAddConnection_CreateTunnel(
      parser, ops, local_ip, port, remote_ip, port, HICN_CONN, symbolic);
}

static CommandReturn _controlAddConnection_UdpHelpExecute(CommandParser *parser,
                                                          CommandOps *ops,
                                                          PARCList *args) {
  _controlAddConnection_IpHelp(parser, ops, args, "udp");

  return CommandReturn_Success;
}

static CommandReturn _controlAddConnection_UdpExecute(CommandParser *parser,
                                                      CommandOps *ops,
                                                      PARCList *args) {
  static const int _indexSymbolic = 3;
  static const int _indexRemAddr = 4;
  static const int _indexRemPort = 5;
  static const int _indexLocAddr = 6;
  static const int _indexLocPort = 7;

  if (parcList_Size(args) != 8) {
    _controlAddConnection_UdpHelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  char *symbolic = parcList_GetAtIndex(args, _indexSymbolic);

  if (!utils_ValidateSymbolicName(symbolic)) {
    printf(
        "Invalid symbolic name.  Must begin with alpha and contain only "
        "alphanum.\n");
    return CommandReturn_Failure;
  }

  char *remote_ip = parcList_GetAtIndex(args, _indexRemAddr);
  char *local_ip = parcList_GetAtIndex(args, _indexLocAddr);

  char *remote_port = parcList_GetAtIndex(args, _indexRemPort);
  char *local_port = parcList_GetAtIndex(args, _indexLocPort);

  return _controlAddConnection_CreateTunnel(parser, ops, local_ip, local_port,
                                            remote_ip, remote_port, UDP_CONN,
                                            symbolic);
}

static CommandReturn _controlAddConnection_TcpHelpExecute(CommandParser *parser,
                                                          CommandOps *ops,
                                                          PARCList *args) {
  _controlAddConnection_IpHelp(parser, ops, args, "tcp");

  return CommandReturn_Success;
}

static CommandReturn _controlAddConnection_TcpExecute(CommandParser *parser,
                                                      CommandOps *ops,
                                                      PARCList *args) {
  static const int _indexSymbolic = 3;
  static const int _indexRemAddr = 4;
  static const int _indexRemPort = 5;
  static const int _indexLocAddr = 6;
  static const int _indexLocPort = 7;

  if (parcList_Size(args) != 8) {
    _controlAddConnection_UdpHelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  char *symbolic = parcList_GetAtIndex(args, _indexSymbolic);

  if (!utils_ValidateSymbolicName(symbolic)) {
    printf(
        "Invalid symbolic name.  Must begin with alpha and contain only "
        "alphanum.\n");
    return CommandReturn_Failure;
  }

  char *remote_ip = parcList_GetAtIndex(args, _indexRemAddr);
  char *local_ip = parcList_GetAtIndex(args, _indexLocAddr);

  char *remote_port = parcList_GetAtIndex(args, _indexRemPort);
  char *local_port = parcList_GetAtIndex(args, _indexLocPort);

  return _controlAddConnection_CreateTunnel(parser, ops, local_ip, local_port,
                                            remote_ip, remote_port, TCP_CONN,
                                            symbolic);
}
