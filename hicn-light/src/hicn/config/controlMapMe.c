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

#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>

#include <hicn/config/controlMapMe.h>
#include <hicn/config/controlMapMeDiscovery.h>
#include <hicn/config/controlMapMeEnable.h>
#include <hicn/config/controlMapMeRetx.h>
#include <hicn/config/controlMapMeTimescale.h>

static void _controlMapMe_Init(CommandParser *parser, CommandOps *ops);
static CommandReturn _controlMapMe_Execute(CommandParser *parser,
                                           CommandOps *ops, PARCList *args);
static CommandReturn _controlMapMe_HelpExecute(CommandParser *parser,
                                               CommandOps *ops, PARCList *args);

static const char *_commandMapMe = "mapme";
static const char *_commandMapMeHelp = "help mapme";

CommandOps *controlMapMe_Create(ControlState *state) {
  return commandOps_Create(state, _commandMapMe, _controlMapMe_Init,
                           _controlMapMe_Execute, commandOps_Destroy);
}

CommandOps *controlMapMe_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandMapMeHelp, NULL,
                           _controlMapMe_HelpExecute, commandOps_Destroy);
}

// =====================================================

static CommandReturn _controlMapMe_HelpExecute(CommandParser *parser,
                                               CommandOps *ops,
                                               PARCList *args) {
  CommandOps *ops_mapme_enable = controlMapMeEnable_HelpCreate(NULL);
  CommandOps *ops_mapme_discovery = controlMapMeDiscovery_HelpCreate(NULL);
  CommandOps *ops_mapme_timescale = controlMapMeTimescale_HelpCreate(NULL);
  CommandOps *ops_mapme_retx = controlMapMeRetx_HelpCreate(NULL);

  printf("Available commands:\n");
  printf("   %s\n", ops_mapme_enable->command);
  printf("   %s\n", ops_mapme_discovery->command);
  printf("   %s\n", ops_mapme_timescale->command);
  printf("   %s\n", ops_mapme_retx->command);
  printf("\n");

  commandOps_Destroy(&ops_mapme_enable);
  commandOps_Destroy(&ops_mapme_discovery);
  commandOps_Destroy(&ops_mapme_timescale);
  commandOps_Destroy(&ops_mapme_retx);

  return CommandReturn_Success;
}

static void _controlMapMe_Init(CommandParser *parser, CommandOps *ops) {
  ControlState *state = ops->closure;
  controlState_RegisterCommand(state, controlMapMeEnable_HelpCreate(state));
  controlState_RegisterCommand(state, controlMapMeDiscovery_HelpCreate(state));
  controlState_RegisterCommand(state, controlMapMeTimescale_HelpCreate(state));
  controlState_RegisterCommand(state, controlMapMeRetx_HelpCreate(state));
  controlState_RegisterCommand(state, controlMapMeEnable_Create(state));
  controlState_RegisterCommand(state, controlMapMeDiscovery_Create(state));
  controlState_RegisterCommand(state, controlMapMeTimescale_Create(state));
  controlState_RegisterCommand(state, controlMapMeRetx_Create(state));
}

static CommandReturn _controlMapMe_Execute(CommandParser *parser,
                                           CommandOps *ops, PARCList *args) {
  return _controlMapMe_HelpExecute(parser, ops, args);
}

// ======================================================================
