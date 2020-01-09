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

#include <hicn/config/controlAdd.h>
#include <hicn/config/controlCache.h>
#include <hicn/config/controlList.h>
#include <hicn/config/controlMapMe.h>
#include <hicn/config/controlQuit.h>
#include <hicn/config/controlRemove.h>
#include <hicn/config/controlRoot.h>
#include <hicn/config/controlSet.h>
#include <hicn/config/controlUnset.h>
#ifdef WITH_POLICY
#include <hicn/config/controlUpdate.h>
#endif /* WITH_POLICY */

static void _controlRoot_Init(CommandParser *parser, CommandOps *ops);
static CommandReturn _controlRoot_Execute(CommandParser *parser,
                                          CommandOps *ops, PARCList *args);
static CommandReturn _controlRoot_HelpExecute(CommandParser *parser,
                                              CommandOps *ops, PARCList *args);

static const char *_commandRoot = "";
static const char *_commandRootHelp = "help";

// ====================================================

CommandOps *controlRoot_Create(ControlState *state) {
  return commandOps_Create(state, _commandRoot, _controlRoot_Init,
                           _controlRoot_Execute, commandOps_Destroy);
}

CommandOps *controlRoot_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandRootHelp, NULL,
                           _controlRoot_HelpExecute, commandOps_Destroy);
}

// ===================================================

static CommandReturn _controlRoot_HelpExecute(CommandParser *parser,
                                              CommandOps *ops, PARCList *args) {
  printf("Command-line execution:\n");
  printf(
      "   controller [--server <server-ip>] [--port <server-port>] "
      "command\n");
  printf("\n");
  printf("Interactive execution:\n");
  printf("   controller [--server <server-ip>] [--port <server-port>]\n");
  printf("\n");
  printf(
      "If the keystore is not specified, the default path is used. Keystore "
      "must exist prior to running program.\n");
  printf("If the password is not specified, the user will be prompted.\n");
  printf("\n");

  CommandOps *ops_help_add = controlAdd_CreateHelp(NULL);
  CommandOps *ops_help_list = controlList_HelpCreate(NULL);
  CommandOps *ops_help_quit = controlQuit_HelpCreate(NULL);
  CommandOps *ops_help_remove = controlRemove_HelpCreate(NULL);
  CommandOps *ops_help_set = controlSet_HelpCreate(NULL);
  CommandOps *ops_help_unset = controlUnset_HelpCreate(NULL);
  CommandOps *ops_help_cache = controlCache_HelpCreate(NULL);
  CommandOps *ops_help_mapme = controlMapMe_HelpCreate(NULL);
#ifdef WITH_POLICY
  CommandOps *ops_help_update = controlUpdate_HelpCreate(NULL);
#endif /* WITH_POLICY */

  printf("Available commands:\n");
  printf("   %s\n", ops_help_add->command);
  printf("   %s\n", ops_help_list->command);
  printf("   %s\n", ops_help_quit->command);
  printf("   %s\n", ops_help_remove->command);
  printf("   %s\n", ops_help_set->command);
  printf("   %s\n", ops_help_unset->command);
  printf("   %s\n", ops_help_cache->command);
  printf("   %s\n", ops_help_mapme->command);
#ifdef WITH_POLICY
  printf("   %s\n", ops_help_update->command);
#endif /* WITH_POLICY */
  printf("\n");

  commandOps_Destroy(&ops_help_add);
  commandOps_Destroy(&ops_help_list);
  commandOps_Destroy(&ops_help_quit);
  commandOps_Destroy(&ops_help_remove);
  commandOps_Destroy(&ops_help_set);
  commandOps_Destroy(&ops_help_unset);
  commandOps_Destroy(&ops_help_cache);
  commandOps_Destroy(&ops_help_mapme);
#ifdef WITH_POLICY
  commandOps_Destroy(&ops_help_update);
#endif /* WITH_POLICY */

  return CommandReturn_Success;
}

static void _controlRoot_Init(CommandParser *parser, CommandOps *ops) {
  ControlState *state = ops->closure;

  controlState_RegisterCommand(state, controlAdd_CreateHelp(state));
  controlState_RegisterCommand(state, controlList_HelpCreate(state));
  controlState_RegisterCommand(state, controlQuit_HelpCreate(state));
  controlState_RegisterCommand(state, controlRemove_HelpCreate(state));
  controlState_RegisterCommand(state, controlSet_HelpCreate(state));
  controlState_RegisterCommand(state, controlUnset_HelpCreate(state));
  controlState_RegisterCommand(state, controlCache_HelpCreate(state));
  controlState_RegisterCommand(state, controlMapMe_HelpCreate(state));
#ifdef WITH_POLICY
  controlState_RegisterCommand(state, controlUpdate_HelpCreate(state));
#endif /* WITH_POLICY */

  controlState_RegisterCommand(state, webControlAdd_Create(state));
  controlState_RegisterCommand(state, controlList_Create(state));
  controlState_RegisterCommand(state, controlQuit_Create(state));
  controlState_RegisterCommand(state, controlRemove_Create(state));
  controlState_RegisterCommand(state, controlSet_Create(state));
  controlState_RegisterCommand(state, controlUnset_Create(state));
  controlState_RegisterCommand(state, controlCache_Create(state));
  controlState_RegisterCommand(state, controlMapMe_Create(state));
#ifdef WITH_POLICY
  controlState_RegisterCommand(state, controlUpdate_Create(state));
#endif /* WITH_POLICY */
}

static CommandReturn _controlRoot_Execute(CommandParser *parser,
                                          CommandOps *ops, PARCList *args) {
  return CommandReturn_Success;
}

// ======================================================================
