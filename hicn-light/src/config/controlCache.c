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
#include <stdio.h>
#include <stdlib.h>

#include <parc/assert/parc_Assert.h>

#include <parc/security/parc_Security.h>

#include <parc/algol/parc_Memory.h>

#include <src/config/controlCache.h>
#include <src/config/controlCacheClear.h>
#include <src/config/controlCacheServe.h>
#include <src/config/controlCacheStore.h>

static void _controlCache_Init(CommandParser *parser, CommandOps *ops);
static CommandReturn _controlCache_Execute(CommandParser *parser,
                                           CommandOps *ops, PARCList *args);
static CommandReturn _controlCache_HelpExecute(CommandParser *parser,
                                               CommandOps *ops, PARCList *args);

static const char *_commandCache = "cache";
static const char *_commandCacheHelp = "help cache";

CommandOps *controlCache_Create(ControlState *state) {
  return commandOps_Create(state, _commandCache, _controlCache_Init,
                           _controlCache_Execute, commandOps_Destroy);
}

CommandOps *controlCache_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandCacheHelp, NULL,
                           _controlCache_HelpExecute, commandOps_Destroy);
}

// =====================================================

static CommandReturn _controlCache_HelpExecute(CommandParser *parser,
                                               CommandOps *ops,
                                               PARCList *args) {
  CommandOps *ops_cache_serve = controlCacheServe_HelpCreate(NULL);
  CommandOps *ops_cache_store = controlCacheStore_HelpCreate(NULL);
  CommandOps *ops_cache_clear = controlCacheClear_HelpCreate(NULL);

  printf("Available commands:\n");
  printf("   %s\n", ops_cache_serve->command);
  printf("   %s\n", ops_cache_store->command);
  printf("   %s\n", ops_cache_clear->command);
  printf("\n");

  commandOps_Destroy(&ops_cache_serve);
  commandOps_Destroy(&ops_cache_store);
  commandOps_Destroy(&ops_cache_clear);

  return CommandReturn_Success;
}

static void _controlCache_Init(CommandParser *parser, CommandOps *ops) {
  ControlState *state = ops->closure;
  controlState_RegisterCommand(state, controlCacheServe_HelpCreate(state));
  controlState_RegisterCommand(state, controlCacheStore_HelpCreate(state));
  controlState_RegisterCommand(state, controlCacheClear_HelpCreate(state));
  controlState_RegisterCommand(state, controlCacheServe_Create(state));
  controlState_RegisterCommand(state, controlCacheStore_Create(state));
  controlState_RegisterCommand(state, controlCacheClear_Create(state));
}

static CommandReturn _controlCache_Execute(CommandParser *parser,
                                           CommandOps *ops, PARCList *args) {
  return _controlCache_HelpExecute(parser, ops, args);
}

// ======================================================================
