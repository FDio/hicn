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
#include <hicn/config/controlMapMeTimescale.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlMapMeTimescale_Execute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args,
                                                    char *output,
                                                    size_t output_size);
static CommandReturn _controlMapMeTimescale_HelpExecute(CommandParser *parser,
                                                        CommandOps *ops,
                                                        PARCList *args,
                                                        char *output,
                                                        size_t output_size);

static const char *_commandMapMeTimescale = "mapme timescale";
static const char *_commandMapMeTimescaleHelp = "help mapme timescale";

// ====================================================

CommandOps *controlMapMeTimescale_Create(ControlState *state) {
  return commandOps_Create(state, _commandMapMeTimescale, NULL,
                           _controlMapMeTimescale_Execute, commandOps_Destroy);
}

CommandOps *controlMapMeTimescale_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandMapMeTimescaleHelp, NULL,
                           _controlMapMeTimescale_HelpExecute,
                           commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlMapMeTimescale_HelpExecute(CommandParser *parser,
                                                        CommandOps *ops,
                                                        PARCList *args,
                                                        char *output,
                                                        size_t output_size) {
  snprintf(output, output_size, "mapme timescale <milliseconds>\n\n");
  return CommandReturn_Success;
}

static CommandReturn _controlMapMeTimescale_Execute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args,
                                                    char *output,
                                                    size_t output_size) {
  if (parcList_Size(args) != 3) {
    _controlMapMeTimescale_HelpExecute(parser, ops, args, output, output_size);
    return CommandReturn_Failure;
  }

  const char *ts = parcList_GetAtIndex(args, 2);
  if (!utils_IsNumber(ts)) {
    snprintf(output, output_size, 
        "ERROR: timescale value (expressed in ms) must be a positive integer "
        "\n");
    return CommandReturn_Failure;
  }

  mapme_timing_command *mapmeTimescaleCommand =
      parcMemory_AllocateAndClear(sizeof(mapme_timing_command));
  mapmeTimescaleCommand->timePeriod = (unsigned)strtold(ts, NULL);

  ControlState *state = ops->closure;
  // send message and receive response
  struct iovec *response =
      utils_SendRequest(state, MAPME_TIMESCALE, mapmeTimescaleCommand,
                        sizeof(mapme_timing_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}
