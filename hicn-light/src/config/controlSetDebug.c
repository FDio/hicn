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


#include <src/core/forwarder.h>
#include <src/core/dispatcher.h>
#include <src/config/controlSetDebug.h>


static CommandReturn _controlSetDebug_Execute(CommandParser *parser, CommandOps *ops, PARCList *args);
static CommandReturn _controlSetDebug_HelpExecute(CommandParser *parser, CommandOps *ops, PARCList *args);

static const char *_commandSetDebug = "set debug";
static const char *_commandSetDebugHelp = "help set debug";

// ====================================================

CommandOps *
controlSetDebug_Create(ControlState *state)
{
    return commandOps_Create(state,
                                    _commandSetDebug,
                                    NULL,
                                    _controlSetDebug_Execute,
                                    commandOps_Destroy);
}

CommandOps *
controlSetDebug_HelpCreate(ControlState *state)
{
    return commandOps_Create(state,
                                    _commandSetDebugHelp,
                                    NULL,
                                    _controlSetDebug_HelpExecute,
                                    commandOps_Destroy);
}

// ====================================================

static CommandReturn
_controlSetDebug_HelpExecute(CommandParser *parser, CommandOps *ops, PARCList *args)
{
    printf("set debug: will enable the debug flag for more verbose output\n");
    printf("\n");
    return CommandReturn_Success;
}

static CommandReturn
_controlSetDebug_Execute(CommandParser *parser, CommandOps *ops, PARCList *args)
{
    if (parcList_Size(args) != 2) {
        _controlSetDebug_HelpExecute(parser, ops, args);
        return CommandReturn_Failure;
    }

    ControlState *state = ops->closure;
    controlState_SetDebug(state, true);
    printf("Debug flag set\n\n");
    return CommandReturn_Success;
}
