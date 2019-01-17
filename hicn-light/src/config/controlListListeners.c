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

#include <stdbool.h>
#include <stdint.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>

#include <parc/assert/parc_Assert.h>
#include <parc/algol/parc_Memory.h>

#include <src/config/controlListListeners.h>
#include <src/utils/commands.h>
#include <src/utils/utils.h>

static CommandReturn _controlListListeners_Execute(CommandParser *parser, CommandOps *ops, PARCList *args);
static CommandReturn _controlListListeners_HelpExecute(CommandParser *parser, CommandOps *ops, PARCList *args);

static const char *_commandListListeners = "list listeners";
static const char *_commandListListenersHelp = "help list listeners";
static const char *listenerType[5] = {"TCP", "UDP", "ETHER", "LOCAL", "HICN"};

// ====================================================

CommandOps *
controlListListeners_Create(ControlState *state)
{
    return commandOps_Create(state,
                                    _commandListListeners,
                                    NULL,
                                    _controlListListeners_Execute,
                                    commandOps_Destroy);
}

CommandOps *
controlListListeners_HelpCreate(ControlState *state)
{
    return commandOps_Create(state,
                                    _commandListListenersHelp,
                                    NULL,
                                    _controlListListeners_HelpExecute,
                                    commandOps_Destroy);
}

// ====================================================

static CommandReturn
_controlListListeners_HelpExecute(CommandParser *parser, CommandOps *ops, PARCList *args)
{
    printf("list listeners\n");
    printf("\n");

    return CommandReturn_Success;
}

static CommandReturn
_controlListListeners_Execute(CommandParser *parser, CommandOps *ops, PARCList *args)
{
    if (parcList_Size(args) != 2) {
        _controlListListeners_HelpExecute(parser, ops, args);
        return CommandReturn_Failure;
    }

    ControlState *state = ops->closure;

    //send message and receive response
    struct iovec *response = utils_SendRequest(state, LIST_LISTENERS, NULL, 0);
    if (!response){ //get NULL pointer = FAILURE
        return CommandReturn_Failure;
    }

    //Process/Print message
    header_control_message *receivedHeader = (header_control_message *) response[0].iov_base;
    uint8_t *receivedPayload = (uint8_t *) response[1].iov_base;

    //Allocate output to pass to the main function if the call is not interactive
    char **commandOutputMain = NULL;
    if(!controlState_IsInteractive(state) && receivedHeader->length > 0){
        commandOutputMain = parcMemory_Allocate(sizeof(char *) * receivedHeader->length);
        for (size_t j = 0; j < receivedHeader->length; j++){
            commandOutputMain[j] = parcMemory_Allocate(sizeof(char) * 128);
        }
    }

    char* addrString = NULL;
    if(receivedHeader->length>0){
        printf("%6.6s %50.70s %s\n", "iface", "address", "type");
    } else {
        printf(" --- No entry in the list \n");
    }

    for (int i = 0; i < receivedHeader->length; i++) {

        list_listeners_command *listListenersCommand = (list_listeners_command *)
            (receivedPayload + (i * sizeof(list_listeners_command)));

        addrString = utils_CommandAddressToString(listListenersCommand->addressType,
                                                            &listListenersCommand->address,
                                                            &listListenersCommand->port);


        PARCBufferComposer *composer = parcBufferComposer_Create();

        parcBufferComposer_Format(composer, "%6u %50.70s %3s",
                                listListenersCommand->connid,
                                addrString,
                                listenerType[listListenersCommand->encapType]
                                );

        PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
        char *result = parcBuffer_ToString(tempBuffer);
        parcBuffer_Release(&tempBuffer);

        if(!controlState_IsInteractive(state)){
            strcpy(commandOutputMain[i], result);
        }

        puts(result);
        parcMemory_Deallocate((void **) &result);
        parcBufferComposer_Release(&composer);
    }

    controlState_SetCommandOutput(state, commandOutputMain);

    //DEALLOCATE
    parcMemory_Deallocate((void **) &addrString);
    parcMemory_Deallocate(&receivedHeader);         //free response[0].iov_base
    parcMemory_Deallocate(&receivedPayload);        //free response[1].iov_base
    parcMemory_Deallocate(&response);               //free iovec pointer

    return CommandReturn_Success;
}
