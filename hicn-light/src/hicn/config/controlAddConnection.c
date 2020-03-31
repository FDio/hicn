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
#include <hicn/face.h>

// ===================================================

static void _controlAddConnection_Init(CommandParser *parser, CommandOps *ops);
static CommandReturn _controlAddConnection_HelpExecute(CommandParser *parser,
                                                       CommandOps *ops,
                                                       PARCList *args);
static CommandReturn _controlAddConnection_Execute(CommandParser *parser,
                                                   CommandOps *ops,
                                                   PARCList *args);

// ===================================================

#ifdef __linux__
static CommandReturn _controlAddConnection_HicnHelpExecute(
    CommandParser *parser, CommandOps *ops, PARCList *args);
static CommandReturn _controlAddConnection_HicnExecute(CommandParser *parser,
                                                       CommandOps *ops,
                                                       PARCList *args);
#endif

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
#ifdef __linux__
static const char *_commandAddConnectionHicn = "add connection hicn";
#endif
static const char *_commandAddConnectionUdp = "add connection udp";
static const char *_commandAddConnectionTcp = "add connection tcp";
static const char *_commandAddConnectionHelp = "help add connection";
#ifdef __linux__
static const char *_commandAddConnectionHicnHelp = "help add connection hicn";
#endif
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

#ifdef __linux__
static CommandOps *_controlAddConnection_HicnCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddConnectionHicn, NULL,
                           _controlAddConnection_HicnExecute,
                           commandOps_Destroy);
}
#endif

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
#ifdef __linux__
static CommandOps *_controlAddConnection_HicnHelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddConnectionHicnHelp, NULL,
                           _controlAddConnection_HicnHelpExecute,
                           commandOps_Destroy);
}
#endif

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
#ifdef __linux__
  printf("   %s\n", _commandAddConnectionHicn);
#endif
  printf("   %s\n", _commandAddConnectionUdp);
  printf("   %s\n", _commandAddConnectionTcp);
  printf("\n");
  return CommandReturn_Success;
}

static void _controlAddConnection_Init(CommandParser *parser, CommandOps *ops) {
  ControlState *state = ops->closure;
#ifdef __linux__
  controlState_RegisterCommand(state,
                               _controlAddConnection_HicnHelpCreate(state));
#endif
  controlState_RegisterCommand(state,
                               _controlAddConnection_UdpHelpCreate(state));
  controlState_RegisterCommand(state,
                               _controlAddConnection_TcpHelpCreate(state));
#ifdef __linux__
  controlState_RegisterCommand(state, _controlAddConnection_HicnCreate(state));
#endif
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
 * @param [in] type The tunneling protocol
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
    face_type_t type, const char *symbolic) {
  ControlState *state = ops->closure;
  // a request like this always has an interface index of 0 [FIELD REMOVED]
  // unsigned int interfaceIndex = 0;

  // allocate command payload
  cmd_connection_add_t *cmd =
      parcMemory_AllocateAndClear(sizeof(cmd_connection_add_t));

  // check and set IP addresses
  if (inet_pton(AF_INET, remote_ip, &cmd->remote_ip.v4.as_u32) ==
          1 &&
      inet_pton(AF_INET, local_ip, &cmd->local_ip.v4.as_u32) == 1) {
    cmd->family = AF_INET;

  } else if (inet_pton(AF_INET6, remote_ip,
                       &cmd->remote_ip.v6.as_in6addr) == 1 &&
             inet_pton(AF_INET6, local_ip,
                       &cmd->local_ip.v6.as_in6addr) == 1) {
    cmd->family = AF_INET6;

  } else {
    printf("Error: local address %s not same type as remote address %s\n",
           local_ip, remote_ip);
    parcMemory_Deallocate(&cmd);
    return CommandReturn_Failure;
  }

  // Fill remaining payload fields
  cmd->type = type;
  strcpy(cmd->symbolic, symbolic);
  cmd->remote_port = htons((uint16_t)atoi(remote_port));
  cmd->local_port = htons((uint16_t)atoi(local_port));

  // send message and receive response
  struct iovec *response =
      utils_SendRequest(state, COMMAND_TYPE_CONNECTION_ADD, cmd,
                        sizeof(cmd_connection_add_t));

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
#ifdef __linux__
  printf("add connection hicn <symbolic> <remote_ip> <local_ip>\n");
#endif
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

#ifdef __linux__
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
      parser, ops, local_ip, port, remote_ip, port, FACE_TYPE_HICN, symbolic);
}
#endif

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
                                            remote_ip, remote_port, FACE_TYPE_UDP,
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
                                            remote_ip, remote_port, FACE_TYPE_TCP,
                                            symbolic);
}
