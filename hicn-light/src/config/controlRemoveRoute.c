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
#include <ctype.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_Network.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_List.h>

#include <src/utils/address.h>

#include <src/config/controlRemoveRoute.h>

#include <src/utils/commands.h>
#include <src/utils/utils.h>

static CommandReturn _controlRemoveRoute_Execute(CommandParser *parser, CommandOps *ops, PARCList *args);
static CommandReturn _controlRemoveRoute_HelpExecute(CommandParser *parser, CommandOps *ops, PARCList *args);

// ===================================================

static const char *_commandRemoveRoute = "remove route";
static const char *_commandRemoveRouteHelp = "help remove route";

// ====================================================

CommandOps *
controlRemoveRoute_Create(ControlState *state)
{
    return commandOps_Create(state,
                                    _commandRemoveRoute,
                                    NULL,
                                    _controlRemoveRoute_Execute,
                                    commandOps_Destroy);
}

CommandOps *
controlRemoveRoute_HelpCreate(ControlState *state)
{
    return commandOps_Create(state,
                                    _commandRemoveRouteHelp,
                                    NULL,
                                    _controlRemoveRoute_HelpExecute,
                                    commandOps_Destroy);
}

// ====================================================


static CommandReturn
_controlRemoveRoute_HelpExecute(CommandParser *parser, CommandOps *ops, PARCList *args)
{
    printf("commands:\n");
    printf("    remove route <symbolic | connid> <prefix>\n");
    return CommandReturn_Success;
}

static CommandReturn
_controlRemoveRoute_Execute(CommandParser *parser, CommandOps *ops, PARCList *args)
{

    ControlState *state = ops->closure;

    if (parcList_Size(args) != 4) {
        _controlRemoveRoute_HelpExecute(parser, ops, args);
        return CommandReturn_Failure;
    }

    const char *symbolicOrConnid = parcList_GetAtIndex(args, 2);

   if (!utils_ValidateSymbolicName(symbolicOrConnid) &&
        !utils_IsNumber(symbolicOrConnid))
    {
        printf("ERROR: Invalid symbolic or connid:\nsymbolic name must begin with an alpha followed by alphanum;\nconnid must be an integer\n");
        return CommandReturn_Failure;
    }

    const char *prefixStr = parcList_GetAtIndex(args, 3);
    char addr[strlen (prefixStr) + 1];

    //separate address and len
    char *slash;
    uint32_t len = 0;
    strcpy (addr, prefixStr);
    slash = strrchr (addr, '/');
    if (slash != NULL){
        len = atoi(slash + 1);
        *slash = '\0';
    }

    if(len == 0){
        printf("ERROR: a prefix can not be of length 0\n");
        return CommandReturn_Failure;
    }

    //allocate command payload
    remove_route_command *removeRouteCommand = parcMemory_AllocateAndClear(sizeof(remove_route_command));

    //check and set IP address
    if(inet_pton(AF_INET, addr, &removeRouteCommand->address.ipv4) == 1){
        if(len>32){
            printf("ERROR: exceeded INET mask length, max=32\n");
            parcMemory_Deallocate(&removeRouteCommand);
            return CommandReturn_Failure;
        }
        removeRouteCommand->addressType = ADDR_INET;
    } else if(inet_pton(AF_INET6, addr, &removeRouteCommand->address.ipv6) == 1){
        if(len>128){
            printf("ERROR: exceeded INET6 mask length, max=128\n");
            parcMemory_Deallocate(&removeRouteCommand);
            return CommandReturn_Failure;
        }
        removeRouteCommand->addressType = ADDR_INET6;
    } else {
        printf("Error: %s is not a valid network address \n", addr);
        parcMemory_Deallocate(&removeRouteCommand);
        return CommandReturn_Failure;
    }

    //Fill remaining payload fields
    removeRouteCommand->len = len;
    strcpy(removeRouteCommand->symbolicOrConnid, symbolicOrConnid);

    //send message and receive response
    struct iovec *response =
        utils_SendRequest(state, REMOVE_ROUTE, removeRouteCommand, sizeof(remove_route_command));

    if (!response){ //get NULL pointer
        return CommandReturn_Failure;
    }

    parcMemory_Deallocate(&response);               //free iovec pointer
    return CommandReturn_Success;

}
