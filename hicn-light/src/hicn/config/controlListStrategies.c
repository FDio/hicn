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

#include <hicn/config/controlListStrategies.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

#include <hicn/strategy.h>

static CommandReturn _controlListStrategies_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args);
static CommandReturn _controlListStrategies_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args);

static const char *_commandListStrategies = "list strategies";
static const char *_commandListStrategiesHelp = "help list strategies";

// ====================================================

CommandOps *controlListStrategies_Create(ControlState *state) {
  return commandOps_Create(state, _commandListStrategies, NULL,
                           _controlListStrategies_Execute, commandOps_Destroy);
}

CommandOps *controlListStrategies_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandListStrategiesHelp, NULL,
                           _controlListStrategies_HelpExecute, commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlListStrategies_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args) {
  printf("command: list strategies\n");
  printf("\n");
  printf(
      "This command will fetch the prefix routing table.  For each prefix, it "
      "will list the associated strategy and related prefixes.\n");
  printf("\n");
  return CommandReturn_Success;
}

static CommandReturn _controlListStrategies_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args) {
  if (parcList_Size(args) != 2) {
    _controlListStrategies_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  ControlState *state = ops->closure;

  // send message and receive response
  struct iovec *response = utils_SendRequest(state, LIST_STRATEGIES, NULL, 0);
  if (!response) {  // get NULL pointer = FAILURE
    return CommandReturn_Failure;
  }

  // Process/Print message
  header_control_message *receivedHeader =
      (header_control_message *)response[0].iov_base;
  list_strategies_command * listStrategiesCommand = (list_strategies_command*)response[1].iov_base;

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

  if (receivedHeader->length == 0) {
    printf(" --- No entry in the list \n");
  }

  for (unsigned i = 0; i < receivedHeader->length; i++) {
    addrString = utils_CommandAddressToString(
        listStrategiesCommand[i].addressType, &listStrategiesCommand[i].address, &port);

    PARCBufferComposer *composer = parcBufferComposer_Create();

#define MAXSZ_RELATED_PREFIXES 1024
    char related_prefixes_str[MAXSZ_RELATED_PREFIXES];
    size_t pos = 0;
    int rc;
    related_prefixes_str[0] = '\0'; /* safeguard */
    if (listStrategiesCommand[i].related_prefixes > 0) {
        rc = snprintf(related_prefixes_str+pos, MAXSZ_RELATED_PREFIXES - pos, " Related prefixes:");
        assert(rc > 0);
        assert(rc < MAXSZ_RELATED_PREFIXES - pos);
        pos+= rc;
        for (unsigned j = 0; j < listStrategiesCommand[i].related_prefixes; j++) {
            addrString = utils_CommandAddressToString(
                    listStrategiesCommand[i].addresses_type[j],
                    &listStrategiesCommand[i].addresses[j], &port);
            rc = snprintf(related_prefixes_str + pos, MAXSZ_RELATED_PREFIXES - pos,
                    " %s/%d", addrString, listStrategiesCommand[i].lens[j]);
            assert(rc > 0);
            assert(rc < MAXSZ_RELATED_PREFIXES - pos);
            pos+= rc;
        }
    }

    parcBufferComposer_Format(composer, "%70.70s %3d %s %s", addrString,
            listStrategiesCommand->len,
            HICN_STRATEGY_STR[listStrategiesCommand[i].strategyType],
            related_prefixes_str);

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
  parcMemory_Deallocate(&listStrategiesCommand);
  parcMemory_Deallocate(&response);         // free iovec pointer

  return CommandReturn_Success;
}
