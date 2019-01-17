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
#include <parc/algol/parc_Network.h>

#include <src/core/forwarder.h>
#include <src/core/dispatcher.h>
#include <src/config/controlSetDebug.h>

#include <src/utils/commands.h>
#include <src/utils/utils.h>

static CommandReturn _controlSetStrategy_Execute(CommandParser *parser, CommandOps *ops, PARCList *args);
static CommandReturn _controlSetStrategy_HelpExecute(CommandParser *parser, CommandOps *ops, PARCList *args);

static const char *_commandSetStrategy = "set strategy";
static const char *_commandSetStrategyHelp = "help set strategy";

static const char *_commandSetStrategyOptions[LAST_STRATEGY_VALUE]= {"loadbalancer",
                                                                        "random",
                                                                        "random_per_dash_segment",
                                                                        "loadbalancer_with_delay",
                                                                        "loadbalancer_by_rate",
                                                                        "loadbalancer_best_route"
                                                                        };

// ====================================================

CommandOps *
controlSetStrategy_Create(ControlState *state)
{
    return commandOps_Create(state,
                                    _commandSetStrategy,
                                    NULL,
                                    _controlSetStrategy_Execute,
                                    commandOps_Destroy);
}

CommandOps *
controlSetStrategy_HelpCreate(ControlState *state)
{
    return commandOps_Create(state,
                                    _commandSetStrategyHelp,
                                    NULL,
                                    _controlSetStrategy_HelpExecute,
                                    commandOps_Destroy);
}

// ====================================================


strategy_type _validStrategy(const char *strategy){

    strategy_type validStrategy = LAST_STRATEGY_VALUE;

    for (int i = 0; i < LAST_STRATEGY_VALUE; i++){
        if(strcmp(_commandSetStrategyOptions[i], strategy) == 0){
            validStrategy = i;
            break;
        }
    }
    return validStrategy;
}




static CommandReturn
_controlSetStrategy_HelpExecute(CommandParser *parser, CommandOps *ops, PARCList *args)
{
    printf("set strategy <prefix> <strategy>\n");
    printf("prefix: ipv4/ipv6 address (ex: 1234::/64)\n");
    printf("strategy: strategy identifier\n");
    printf("available strategies:\n");
    printf("    random\n");
    printf("    loadbalancer\n");
    printf("    random_per_dash_segment\n");
    printf("    loadbalancer_with_delay\n");
    printf("\n");
    return CommandReturn_Success;
}

static CommandReturn
_controlSetStrategy_Execute(CommandParser *parser, CommandOps *ops, PARCList *args)
{
    ControlState *state = ops->closure;

    if (parcList_Size(args) != 4) {
        _controlSetStrategy_HelpExecute(parser, ops, args);
        return CommandReturn_Failure;
    }

    if (((strcmp(parcList_GetAtIndex(args, 0), "set") != 0) || (strcmp(parcList_GetAtIndex(args, 1), "strategy") != 0))) {
        _controlSetStrategy_HelpExecute(parser, ops, args);
        return CommandReturn_Failure;
    }

    const char *prefixStr = parcList_GetAtIndex(args, 2);
    char addr[strlen (prefixStr) + 1];
    //separate address and len
    char *slash;
    uint32_t len = UINT32_MAX;
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
    set_strategy_command *setStrategyCommand = parcMemory_AllocateAndClear(sizeof(set_strategy_command));

    //check and set IP address
    if(inet_pton(AF_INET, addr, &setStrategyCommand->address.ipv4) == 1){
        if(len == UINT32_MAX){
            printf("Netmask not specified: set to 32 by default\n");
            len = 32;
        }else if(len>32){
            printf("ERROR: exceeded INET mask length, max=32\n");
            parcMemory_Deallocate(&setStrategyCommand);
            return CommandReturn_Failure;
        }
        setStrategyCommand->addressType = ADDR_INET;
    } else if(inet_pton(AF_INET6, addr, &setStrategyCommand->address.ipv6) == 1){
        if(len == UINT32_MAX){
            printf("Netmask not specified: set to 128 by default\n");
            len = 128;
        }else if(len>128){
            printf("ERROR: exceeded INET6 mask length, max=128\n");
            parcMemory_Deallocate(&setStrategyCommand);
            return CommandReturn_Failure;
        }
         setStrategyCommand->addressType = ADDR_INET6;
    } else {
        printf("Error: %s is not a valid network address \n", addr);
        parcMemory_Deallocate(&setStrategyCommand);
        return CommandReturn_Failure;
    }

    const char *strategyStr = parcList_GetAtIndex(args, 3);
    //check valid strategy
    strategy_type strategy;
    if ((strategy = _validStrategy(strategyStr)) == LAST_STRATEGY_VALUE) {
        printf("Error: invalid strategy \n");
        parcMemory_Deallocate(&setStrategyCommand);
        _controlSetStrategy_HelpExecute(parser, ops, args);
        return CommandReturn_Failure;
    }

    //Fill remaining payload fields
    setStrategyCommand->len = len;
    setStrategyCommand->strategyType = strategy;

    //send message and receive response
    struct iovec *response =
        utils_SendRequest(state, SET_STRATEGY, setStrategyCommand, sizeof(set_strategy_command));

    if (!response){ //get NULL pointer
        return CommandReturn_Failure;
    }

    parcMemory_Deallocate(&response);               //free iovec pointer
    return CommandReturn_Success;
}
