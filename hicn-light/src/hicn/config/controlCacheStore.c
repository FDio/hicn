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

#include <hicn/config/controlCacheStore.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlCacheStore_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args);
static CommandReturn _controlCacheStore_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args);

static const char *_commandCacheStore = "cache store";
static const char *_commandCacheStoreHelp = "help cache store";

// ====================================================

CommandOps *controlCacheStore_Create(ControlState *state) {
  return commandOps_Create(state, _commandCacheStore, NULL,
                           _controlCacheStore_Execute, commandOps_Destroy);
}

CommandOps *controlCacheStore_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandCacheStoreHelp, NULL,
                           _controlCacheStore_HelpExecute, commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlCacheStore_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args) {
  printf("cache store [on|off]\n");
  printf("\n");

  return CommandReturn_Success;
}

static CommandReturn _controlCacheStore_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args) {
  if (parcList_Size(args) != 3) {
    _controlCacheStore_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  bool active;
  if (strcmp(parcList_GetAtIndex(args, 2), "on") == 0) {
    active = true;
  } else if (strcmp(parcList_GetAtIndex(args, 2), "off") == 0) {
    active = false;
  } else {
    _controlCacheStore_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  cache_store_command *cacheStoreCommand =
      parcMemory_AllocateAndClear(sizeof(cache_store_command));
  if (active) {
    cacheStoreCommand->activate = ACTIVATE_ON;
  } else {
    cacheStoreCommand->activate = ACTIVATE_OFF;
  }

  ControlState *state = ops->closure;
  // send message and receive response
  struct iovec *response = utils_SendRequest(
      state, CACHE_STORE, cacheStoreCommand, sizeof(cache_store_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}
