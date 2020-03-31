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

#include <hicn/config/controlListConnections.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlListConnections_Execute(CommandParser *parser,
                                                     CommandOps *ops,
                                                     PARCList *args);
static CommandReturn _controlListConnections_HelpExecute(CommandParser *parser,
                                                         CommandOps *ops,
                                                         PARCList *args);

static const char *_commandListConnections = "list connections";
static const char *_commandListConnectionsHelp = "help list connections";

// XXX TODO in connection{_state}.h
const char *connTypeString[6] = {"GRE", "TCP", "UDP", "MCAST", "L2", "HICN"};
const char *stateString[3] = {"UNKNOWN", "DOWN", "UP"};

CommandOps *controlListConnections_Create(ControlState *state) {
  return commandOps_Create(state, _commandListConnections, NULL,
                           _controlListConnections_Execute, commandOps_Destroy);
}

CommandOps *controlListConnections_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandListConnectionsHelp, NULL,
                           _controlListConnections_HelpExecute,
                           commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlListConnections_HelpExecute(CommandParser *parser,
                                                         CommandOps *ops,
                                                         PARCList *args) {
  printf("list connections: displays a 1-line summary of each connection\n");
  printf("\n");
  printf("The columns are:\n");
  printf("   connection id : an integer index for the connection\n");
  printf("   state         : UP or DOWN\n");
  printf(
      "   local address : the local network address associated with the "
      "connection\n");
  printf(
      "   remote address: the remote network address associated with the "
      "connection\n");
  printf(
      "   protocol      : the network protocol (tcp, udp, gre, mcast, "
      "ether)\n");
  printf("\n");
  return CommandReturn_Success;
}

static CommandReturn _controlListConnections_Execute(CommandParser *parser,
                                                     CommandOps *ops,
                                                     PARCList *args) {
  if (parcList_Size(args) != 2) {
    _controlListConnections_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }
#ifdef WITH_POLICY
  char flags_str[POLICY_TAG_N+1];
  char *s;
#endif /* WITH_POLICY */

  ControlState *state = ops->closure;

  // send message and receive response
  struct iovec *response = utils_SendRequest(state, LIST_CONNECTIONS, NULL, 0);
  if (!response) {  // get NULL pointer = FAILURE
    return CommandReturn_Failure;
  }

  // Process/Print message
  header_control_message *receivedHeader =
      (header_control_message *)response[0].iov_base;
  uint8_t *receivedPayload = (uint8_t *)response[1].iov_base;

  char *sourceString = NULL;
  char *destinationString = NULL;

  // Allocate output to pass to the main function if the call is not interactive
  char **commandOutputMain = NULL;
  if (!controlState_IsInteractive(state) && receivedHeader->length > 0) {
    commandOutputMain =
        parcMemory_Allocate(sizeof(char *) * receivedHeader->length);
    for (size_t j = 0; j < receivedHeader->length; j++) {
      commandOutputMain[j] = parcMemory_Allocate(sizeof(char) * 256);
    }
  }

#ifdef WITH_POLICY
  printf("%5s %10s %12s %6s %40s %40s %5s %s %s\n", "id", "name", "admin_state", "state", "source", "destination", "type", "priority", "flags");
#else
  printf("%5s %10s %12s %6s %40s %40s %5s\n", "id", "name", "admin_state", "state", "source", "destination", "type");
#endif /* WITH_POLICY */

  // Process/Print payload

  for (int i = 0; i < receivedHeader->length; i++) {
    list_connections_command *listConnectionsCommand =
        (list_connections_command *)(receivedPayload +
                                     (i * sizeof(list_connections_command)));

    sourceString = utils_CommandAddressToString(
        listConnectionsCommand->connectionData.family,
        &listConnectionsCommand->connectionData.localIp,
        &listConnectionsCommand->connectionData.localPort);

    destinationString = utils_CommandAddressToString(
        listConnectionsCommand->connectionData.family,
        &listConnectionsCommand->connectionData.remoteIp,
        &listConnectionsCommand->connectionData.remotePort);

    PARCBufferComposer *composer = parcBufferComposer_Create();

#ifdef WITH_POLICY

    s = flags_str;
#define _(x, y) *s++ = policy_tags_has(listConnectionsCommand->connectionData.tags, POLICY_TAG_ ## x) ? y : '.';
foreach_policy_tag
#undef _
    *s = '\0';

    parcBufferComposer_Format(
        composer, "%5d %10s %12s %6s %40s %40s %5s [%6d] [%s]", listConnectionsCommand->connid, listConnectionsCommand->connectionName,
        stateString[listConnectionsCommand->connectionData.admin_state],
        stateString[listConnectionsCommand->state], sourceString,
        destinationString,
        connTypeString[listConnectionsCommand->connectionData.connectionType],
        listConnectionsCommand->connectionData.priority,
        flags_str);

#else
    parcBufferComposer_Format(
        composer, "%5d %10s %12s %6s %40s %40s %5s", listConnectionsCommand->connid, listConnectionsCommand->connectionName,
        stateString[listConnectionsCommand->admin_state],
        stateString[listConnectionsCommand->state], sourceString,
        destinationString,
        connTypeString[listConnectionsCommand->connectionData.connectionType]);
#endif /* WITH_POLICY */

    PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
    char *result = parcBuffer_ToString(tempBuffer);
    parcBuffer_Release(&tempBuffer);

    if (!controlState_IsInteractive(state)) {
      strcpy(commandOutputMain[i], result);
    }

    puts(result);
    parcMemory_Deallocate((void **)&result);
    parcBufferComposer_Release(&composer);
  }

  controlState_SetCommandOutput(state, commandOutputMain);

  // DEALLOCATE
  parcMemory_Deallocate((void **)&sourceString);
  parcMemory_Deallocate((void **)&destinationString);
  parcMemory_Deallocate(&receivedHeader);   // free response[0].iov_base
  parcMemory_Deallocate(&receivedPayload);  // free response[1].iov_base
  parcMemory_Deallocate(&response);         // free iovec pointer

  return CommandReturn_Success;
}
