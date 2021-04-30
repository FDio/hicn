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
#include <hicn/config/controlMapMeRetx.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlMapMeRetx_Execute(CommandParser *parser,
                                               CommandOps *ops,
                                               PARCList *args,
                                               char *output,
                                               size_t output_size);
static CommandReturn _controlMapMeRetx_HelpExecute(CommandParser *parser,
                                                   CommandOps *ops,
                                                   PARCList *args,
                                                   char *output,
                                                   size_t output_size);

static const char *_commandMapMeRetx = "mapme retx";
static const char *_commandMapMeRetxHelp = "help mapme retx";

// ====================================================

CommandOps *controlMapMeRetx_Create(ControlState *state) {
  return commandOps_Create(state, _commandMapMeRetx, NULL,
                           _controlMapMeRetx_Execute, commandOps_Destroy);
}

CommandOps *controlMapMeRetx_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandMapMeRetxHelp, NULL,
                           _controlMapMeRetx_HelpExecute, commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlMapMeRetx_HelpExecute(CommandParser *parser,
                                                   CommandOps *ops,
                                                   PARCList *args,
                                                   char *output,
                                                   size_t output_size) {
  snprintf(output, output_size,  "mapme retx <milliseconds>\n\n");

  return CommandReturn_Success;
}

static CommandReturn _controlMapMeRetx_Execute(CommandParser *parser,
                                               CommandOps *ops,
                                               PARCList *args,
                                               char *output,
                                               size_t output_size) {
  if (parcList_Size(args) != 3) {
    _controlMapMeRetx_HelpExecute(parser, ops, args, output, output_size);
    return CommandReturn_Failure;
  }

  const char *rtx = parcList_GetAtIndex(args, 2);
  if (!utils_IsNumber(rtx)) {
    snprintf(output, output_size,
        "ERROR: retransmission value (expressed in ms) must be a positive "
        "integer \n");
    return CommandReturn_Failure;
  }

  mapme_timing_command *mapmeRetxCommand =
      parcMemory_AllocateAndClear(sizeof(mapme_timing_command));
  mapmeRetxCommand->timePeriod = (unsigned)strtold(rtx, NULL);

  ControlState *state = ops->closure;
  // send message and receive response
  struct iovec *response = utils_SendRequest(
      state, MAPME_RETX, mapmeRetxCommand, sizeof(mapme_timing_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}
