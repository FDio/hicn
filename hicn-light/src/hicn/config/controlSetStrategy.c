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
#include <parc/algol/parc_Network.h>

#include <hicn/config/controlSetDebug.h>
#include <hicn/core/dispatcher.h>
#include <hicn/core/forwarder.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlSetStrategy_Execute(CommandParser *parser,
                                                 CommandOps *ops,
                                                 PARCList *args);
static CommandReturn _controlSetStrategy_HelpExecute(CommandParser *parser,
                                                     CommandOps *ops,
                                                     PARCList *args);

static const char *_commandSetStrategy = "set strategy";
static const char *_commandSetStrategyHelp = "help set strategy";

static const char *_commandSetStrategyOptions[STRATEGY_TYPE_N] = {
    "(undefined)",
    "loadbalancer",
    "random",
    "low_latency",
};

// ====================================================

CommandOps *controlSetStrategy_Create(ControlState *state) {
  return commandOps_Create(state, _commandSetStrategy, NULL,
                           _controlSetStrategy_Execute, commandOps_Destroy);
}

CommandOps *controlSetStrategy_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandSetStrategyHelp, NULL,
                           _controlSetStrategy_HelpExecute, commandOps_Destroy);
}

// ====================================================

strategy_type_t _validStrategy(const char *strategy) {
  strategy_type_t validStrategy = STRATEGY_TYPE_UNDEFINED;

  for (int i = 0; i < STRATEGY_TYPE_N; i++) {
    if (strcmp(_commandSetStrategyOptions[i], strategy) == 0) {
      validStrategy = i;
      break;
    }
  }
  return validStrategy;
}

static void _getAddressAndLen(const char * prefixStr, char *addr, uint32_t *len){
  char *slash;
  strcpy(addr, prefixStr);
  slash = strrchr(addr, '/');
  if (slash != NULL) {
    *len = atoi(slash + 1);
    *slash = '\0';
  }
}

static bool _checkAndSetIp(set_strategy_command * setStrategyCommand,
                          int index, char * addr, uint32_t len){
  // check and set IP address
  int res;
  if(index == -1)
    res = inet_pton(AF_INET, addr, &setStrategyCommand->address.v4.as_u32);
  else
    res = inet_pton(AF_INET, addr,
              &setStrategyCommand->low_latency.addresses[index].v4.as_u32);

  if(res == 1) {
    if (len == UINT32_MAX) {
      printf("Netmask not specified: set to 32 by default\n");
      len = 32;
    } else if (len > 32) {
      printf("ERROR: exceeded INET mask length, max=32\n");
      return false;
    }
    if(index == -1)
      setStrategyCommand->family = AF_INET;
    else
      setStrategyCommand->low_latency.families[index] = AF_INET;

  } else {

    if(index == -1)
      res = inet_pton(AF_INET6, addr,
            &setStrategyCommand->address.v6.as_in6addr);
    else
      res = inet_pton(AF_INET6, addr,
            &setStrategyCommand->low_latency.addresses[index].v6.as_in6addr);

    if(res == 1) {
      if (len == UINT32_MAX) {
        printf("Netmask not specified: set to 128 by default\n");
        len = 128;
      } else if (len > 128) {
        printf("ERROR: exceeded INET6 mask length, max=128\n");
        return false;
      }

      if(index == -1)
        setStrategyCommand->family = AF_INET6;
      else
        setStrategyCommand->low_latency.families[index] = AF_INET6;

    } else {
      printf("Error: %s is not a valid network address \n", addr);
      return false;
    }
  }
  return true;
}

static CommandReturn _controlSetStrategy_HelpExecute(CommandParser *parser,
                                                     CommandOps *ops,
                                                     PARCList *args) {
  printf("set strategy <prefix> <strategy> ");
  printf("[related_prefix1 related_preifx2  ...]\n");
  printf("prefix: ipv4/ipv6 address (ex: 1234::/64)\n");
  printf("strategy: strategy identifier\n");
  printf("optinal: list of related prefixes (max %u)\n",
                          MAX_FWD_STRATEGY_RELATED_PREFIXES);
  printf("available strategies:\n");
  printf("    random\n");
  printf("    loadbalancer\n");
  printf("    low_latency\n");
  printf("\n");
  return CommandReturn_Success;
}


static CommandReturn _controlSetStrategy_Execute(CommandParser *parser,
                                                 CommandOps *ops,
                                                 PARCList *args) {
  ControlState *state = ops->closure;

  if (parcList_Size(args) < 4 ||
          parcList_Size(args) > (4 + MAX_FWD_STRATEGY_RELATED_PREFIXES)) {
    _controlSetStrategy_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  if (((strcmp(parcList_GetAtIndex(args, 0), "set") != 0) ||
       (strcmp(parcList_GetAtIndex(args, 1), "strategy") != 0))) {
    _controlSetStrategy_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  const char *prefixStr = parcList_GetAtIndex(args, 2);
  char *addr = (char *)malloc(sizeof(char) * (strlen(prefixStr) + 1));
  uint32_t len = UINT32_MAX;
  _getAddressAndLen(prefixStr, addr, &len);

  // allocate command payload
  set_strategy_command *setStrategyCommand =
      parcMemory_AllocateAndClear(sizeof(set_strategy_command));

  bool success = _checkAndSetIp(setStrategyCommand, -1, addr, len);
  if(!success){
    parcMemory_Deallocate(&setStrategyCommand);
    free(addr);
    return CommandReturn_Failure;
  }

  const char *strategyStr = parcList_GetAtIndex(args, 3);
  // check valid strategy
  strategy_type_t strategy;
  if ((strategy = _validStrategy(strategyStr)) == STRATEGY_TYPE_UNDEFINED) {
    printf("Error: invalid strategy \n");
    parcMemory_Deallocate(&setStrategyCommand);
    _controlSetStrategy_HelpExecute(parser, ops, args);
    free(addr);
    return CommandReturn_Failure;
  }

  free(addr);

  // Fill remaining payload fields
  setStrategyCommand->len = len;
  setStrategyCommand->strategy_type = strategy;

  //check additional prefixes
  if(parcList_Size(args) > 4){
    uint32_t index = 4; //first realted prefix
    uint32_t addr_index = 0;
    setStrategyCommand->related_prefixes = parcList_Size(args) - 4;
    while(index < parcList_Size(args)){
      const char *str = parcList_GetAtIndex(args, index);
      char *rel_addr = (char *)malloc(sizeof(char) * (strlen(str) + 1));
      uint32_t rel_len = UINT32_MAX;
      _getAddressAndLen(str, rel_addr, &rel_len);
      bool success = _checkAndSetIp(setStrategyCommand, addr_index,
                                          rel_addr, rel_len);
      if(!success){
        parcMemory_Deallocate(&setStrategyCommand);
        free(rel_addr);
        return CommandReturn_Failure;
      }
      setStrategyCommand->low_latency.lens[addr_index] = rel_len;
      free(rel_addr);
      index++;
      addr_index++;
    }
  }else{
    setStrategyCommand->related_prefixes = 0;
  }

  // send message and receive response
  struct iovec *response = utils_SendRequest(
      state, SET_STRATEGY, setStrategyCommand, sizeof(set_strategy_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}
