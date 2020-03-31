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
#include <parc/algol/parc_Time.h>

#include <hicn/config/controlListRoutes.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlListRoutes_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args);
static CommandReturn _controlListRoutes_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args);

static const char *_commandListRoutes = "list routes";
static const char *_commandListRoutesHelp = "help list routes";

// ====================================================

CommandOps *controlListRoutes_Create(ControlState *state) {
  return commandOps_Create(state, _commandListRoutes, NULL,
                           _controlListRoutes_Execute, commandOps_Destroy);
}

CommandOps *controlListRoutes_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandListRoutesHelp, NULL,
                           _controlListRoutes_HelpExecute, commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlListRoutes_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args) {
  printf("command: list routes\n");
  printf("\n");
  printf(
      "This command will fetch the prefix routing table.  For each route, it "
      "will list:\n");
  printf("   iface:    interface\n");
  printf(
      "   protocol: the routing protocol, such as STATIC, CONNECTED, etc.\n");
  printf(
      "   type:     LMP or EXACT (longest matching prefix or exact match)\n");
  printf("   cost:     The route cost, lower being preferred\n");
  printf("   next:     List of next hops by interface id\n");
  printf("   prefix:   name prefix\n");
  printf("\n");
  return CommandReturn_Success;
}

static CommandReturn _controlListRoutes_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args) {
  if (parcList_Size(args) != 2) {
    _controlListRoutes_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  ControlState *state = ops->closure;

  // send message and receive response
  struct iovec *response = utils_SendRequest(state, LIST_ROUTES, NULL, 0);
  if (!response) {  // get NULL pointer = FAILURE
    return CommandReturn_Failure;
  }

  // Process/Print message
  header_control_message *receivedHeader =
      (header_control_message *)response[0].iov_base;
  uint8_t *receivedPayload = (uint8_t *)response[1].iov_base;

  // Allocate output to pass to the main function if the call is not interactive
  char **commandOutputMain = NULL;
  if (!controlState_IsInteractive(state) && receivedHeader->length > 0) {
    commandOutputMain =
        parcMemory_Allocate(sizeof(char *) * receivedHeader->length);
    for (size_t j = 0; j < receivedHeader->length; j++) {
      commandOutputMain[j] = parcMemory_Allocate(sizeof(char) * 128);
    }
  }

  char *addrString = NULL;
  in_port_t port = htons(1234);  // this is a random port number that is ignored

  if (receivedHeader->length > 0) {
    printf("%6.6s %8.8s %70.70s %s\n", "iface", "cost", "prefix", "len");
  } else {
    printf(" --- No entry in the list \n");
  }

  for (int i = 0; i < receivedHeader->length; i++) {
    list_routes_command *listRoutesCommand =
        (list_routes_command *)(receivedPayload +
                                (i * sizeof(list_routes_command)));

    addrString = utils_CommandAddressToString(
        listRoutesCommand->family, &listRoutesCommand->address, &port);

    PARCBufferComposer *composer = parcBufferComposer_Create();

    parcBufferComposer_Format(
        composer, "%6u %8u %70.70s %3d", listRoutesCommand->connid,
        listRoutesCommand->cost, addrString, listRoutesCommand->len);

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
  parcMemory_Deallocate((void **)&addrString);
  parcMemory_Deallocate(&receivedHeader);   // free response[0].iov_base
  parcMemory_Deallocate(&receivedPayload);  // free response[1].iov_base
  parcMemory_Deallocate(&response);         // free iovec pointer

  return CommandReturn_Success;
}
