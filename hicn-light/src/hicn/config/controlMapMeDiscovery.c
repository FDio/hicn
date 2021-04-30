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
#include <hicn/config/controlMapMeDiscovery.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlMapMeDiscovery_Execute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args,
                                                    char *output,
                                                    size_t output_size);
static CommandReturn _controlMapMeDiscovery_HelpExecute(CommandParser *parser,
                                                        CommandOps *ops,
                                                        PARCList *args,
                                                        char *output,
                                                        size_t output_size);

static const char *_commandMapMeDiscovery = "mapme discovery";
static const char *_commandMapMeDiscoveryHelp = "help mapme discovery";

// ====================================================

CommandOps *controlMapMeDiscovery_Create(ControlState *state) {
  return commandOps_Create(state, _commandMapMeDiscovery, NULL,
                           _controlMapMeDiscovery_Execute, commandOps_Destroy);
}

CommandOps *controlMapMeDiscovery_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandMapMeDiscoveryHelp, NULL,
                           _controlMapMeDiscovery_HelpExecute,
                           commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlMapMeDiscovery_HelpExecute(CommandParser *parser,
                                                        CommandOps *ops,
                                                        PARCList *args,
                                                        char *output,
                                                        size_t output_size) {
  snprintf(output, output_size, "mapme discovery [on|off]\n\n");

  return CommandReturn_Success;
}

static CommandReturn _controlMapMeDiscovery_Execute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args,
                                                    char *output,
                                                    size_t output_size) {
  if (parcList_Size(args) != 3) {
    _controlMapMeDiscovery_HelpExecute(parser, ops, args, output, output_size);
    return CommandReturn_Failure;
  }

  bool active;
  if (strcmp(parcList_GetAtIndex(args, 2), "on") == 0) {
    active = true;
  } else if (strcmp(parcList_GetAtIndex(args, 2), "off") == 0) {
    active = false;
  } else {
    _controlMapMeDiscovery_HelpExecute(parser, ops, args, output, output_size);
    return CommandReturn_Failure;
  }

  mapme_activator_command *mapmeDiscoveryCommand =
      parcMemory_AllocateAndClear(sizeof(mapme_activator_command));
  if (active) {
    mapmeDiscoveryCommand->activate = ACTIVATE_ON;
  } else {
    mapmeDiscoveryCommand->activate = ACTIVATE_OFF;
  }

  ControlState *state = ops->closure;
  // send message and receive response
  struct iovec *response =
      utils_SendRequest(state, MAPME_DISCOVERY, mapmeDiscoveryCommand,
                        sizeof(mapme_activator_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}
