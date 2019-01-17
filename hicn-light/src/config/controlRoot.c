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

#include <src/config/controlRoot.h>
#include <src/config/controlAdd.h>
#include <src/config/controlList.h>
#include <src/config/controlQuit.h>
#include <src/config/controlRemove.h>
#include <src/config/controlSet.h>
#include <src/config/controlUnset.h>
#include <src/config/controlCache.h>
#include <src/config/controlMapMe.h>

static void _controlRoot_Init(CommandParser *parser, CommandOps *ops);
static CommandReturn _controlRoot_Execute(CommandParser *parser, CommandOps *ops, PARCList *args);
static CommandReturn _controlRoot_HelpExecute(CommandParser *parser, CommandOps *ops, PARCList *args);

static const char *_commandRoot = "";
static const char *_commandRootHelp = "help";

// ====================================================

CommandOps *
controlRoot_Create(ControlState *state)
{
    return commandOps_Create(state,
                                    _commandRoot,
                                    _controlRoot_Init,
                                    _controlRoot_Execute,
                                    commandOps_Destroy);
}

CommandOps *
controlRoot_HelpCreate(ControlState *state)
{
    return commandOps_Create(state,
                                    _commandRootHelp,
                                    NULL,
                                    _controlRoot_HelpExecute,
                                    commandOps_Destroy);
}

// ===================================================

static CommandReturn
_controlRoot_HelpExecute(CommandParser *parser, CommandOps *ops, PARCList *args)
{
    printf("Command-line execution:\n");
    printf("   controller [--keystore <keystorepath>] [--password <password>] command\n");
    printf("\n");
    printf("Interactive execution:\n");
    printf("   controller [--keystore <keystorepath>] [--password <password>]\n");
    printf("\n");
    printf("If the keystore is not specified, the default path is used. Keystore must exist prior to running program.\n");
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

    printf("Available commands:\n");
    printf("   %s\n", ops_help_add->command);
    printf("   %s\n", ops_help_list->command);
    printf("   %s\n", ops_help_quit->command);
    printf("   %s\n", ops_help_remove->command);
    printf("   %s\n", ops_help_set->command);
    printf("   %s\n", ops_help_unset->command);
    printf("   %s\n", ops_help_cache->command);
    printf("   %s\n", ops_help_mapme->command);
    printf("\n");

    commandOps_Destroy(&ops_help_add);
    commandOps_Destroy(&ops_help_list);
    commandOps_Destroy(&ops_help_quit);
    commandOps_Destroy(&ops_help_remove);
    commandOps_Destroy(&ops_help_set);
    commandOps_Destroy(&ops_help_unset);
    commandOps_Destroy(&ops_help_cache);
    commandOps_Destroy(&ops_help_mapme);

    return CommandReturn_Success;
}

static void
_controlRoot_Init(CommandParser *parser, CommandOps *ops)
{
    ControlState *state = ops->closure;

    controlState_RegisterCommand(state, controlAdd_CreateHelp(state));
    controlState_RegisterCommand(state, controlList_HelpCreate(state));
    controlState_RegisterCommand(state, controlQuit_HelpCreate(state));
    controlState_RegisterCommand(state, controlRemove_HelpCreate(state));
    controlState_RegisterCommand(state, controlSet_HelpCreate(state));
    controlState_RegisterCommand(state, controlUnset_HelpCreate(state));
    controlState_RegisterCommand(state, controlCache_HelpCreate(state));
    controlState_RegisterCommand(state, controlMapMe_HelpCreate(state));

    controlState_RegisterCommand(state, webControlAdd_Create(state));
    controlState_RegisterCommand(state, controlList_Create(state));
    controlState_RegisterCommand(state, controlQuit_Create(state));
    controlState_RegisterCommand(state, controlRemove_Create(state));
    controlState_RegisterCommand(state, controlSet_Create(state));
    controlState_RegisterCommand(state, controlUnset_Create(state));
    controlState_RegisterCommand(state, controlCache_Create(state));
    controlState_RegisterCommand(state, controlMapMe_Create(state));
}

static CommandReturn
_controlRoot_Execute(CommandParser *parser, CommandOps *ops, PARCList *args)
{
    return CommandReturn_Success;
}

// ======================================================================
