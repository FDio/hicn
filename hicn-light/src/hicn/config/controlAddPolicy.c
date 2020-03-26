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

#ifdef WITH_POLICY

#include <hicn/hicn-light/config.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>

#include <hicn/config/controlAddPolicy.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>
#include <hicn/utils/token.h>

static CommandReturn _controlAddPolicy_Execute(CommandParser *parser,
                                              CommandOps *ops, PARCList *args);
static CommandReturn _controlAddPolicy_HelpExecute(CommandParser *parser,
                                                  CommandOps *ops,
                                                  PARCList *args);

static const char *_commandAddPolicy = "add policy";
static const char *_commandAddPolicyHelp = "help add policy";

CommandOps *controlAddPolicy_Create(ControlState *state) {
  return commandOps_Create(state, _commandAddPolicy, NULL,
                           _controlAddPolicy_Execute, commandOps_Destroy);
}

CommandOps *controlAddPolicy_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandAddPolicyHelp, NULL,
                           _controlAddPolicy_HelpExecute, commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlAddPolicy_HelpExecute(CommandParser *parser,
                                                  CommandOps *ops,
                                                  PARCList *args) {
  printf("commands:\n");
 /* printf("   add policy <prefix> <app_name>"
            #define _(x, y) " FLAG:%s"
            foreach_policy_tag
            #undef _
            "%s",
            #define _(x, y) policy_tag_str[POLICY_TAG_ ## x],
            foreach_policy_tag
            #undef _
      "\n");*/
  printf("\n");
  printf(
      "   prefix:    The hicn name as IPv4 or IPv6 address (e.g 1234::0/64)\n");
  printf("   app_name:      The application name associated to this policy\n");
  printf("   FLAG:*:  A value among [neutral|require|prefer|avoid|prohibit] with an optional '!' character prefix for disabling changes\n");
  printf("\n");
  return CommandReturn_Success;
}

static CommandReturn _controlAddPolicy_Execute(CommandParser *parser,
                                              CommandOps *ops, PARCList *args) {
  ControlState *state = ops->closure;

  if (parcList_Size(args) != 11) {
    _controlAddPolicy_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  const char *prefixStr = parcList_GetAtIndex(args, 2);
  char *addr = (char *)malloc((strlen(prefixStr) + 1) * sizeof(char));

  // separate address and len
  char *slash;
  uint32_t len = 0;
  strcpy(addr, prefixStr);
  slash = strrchr(addr, '/');
  if (slash != NULL) {
    len = atoi(slash + 1);
    *slash = '\0';
  }

  // allocate command payload
  add_policy_command *addPolicyCommand =
      parcMemory_AllocateAndClear(sizeof(add_policy_command));

  // check and set IP address
  if (inet_pton(AF_INET, addr, &addPolicyCommand->address.v4.as_u32) == 1) {
    if (len > 32) {
      printf("ERROR: exceeded INET mask length, max=32\n");
      parcMemory_Deallocate(&addPolicyCommand);
      free(addr);
      return CommandReturn_Failure;
    }
    addPolicyCommand->addressType = ADDR_INET;
  } else if (inet_pton(AF_INET6, addr, &addPolicyCommand->address.v6.as_in6addr) == 1) {
    if (len > 128) {
      printf("ERROR: exceeded INET6 mask length, max=128\n");
      parcMemory_Deallocate(&addPolicyCommand);
      free(addr);
      return CommandReturn_Failure;
    }
    addPolicyCommand->addressType = ADDR_INET6;
  } else {
    printf("Error: %s is not a valid network address \n", addr);
    parcMemory_Deallocate(&addPolicyCommand);
    free(addr);
    return CommandReturn_Failure;
  }

  free(addr);

  addPolicyCommand->len = len;

  policy_t policy;
  snprintf((char*)policy.app_name, APP_NAME_LEN, "%s", (char*)parcList_GetAtIndex(args, 3));
  for (int i=4; i < 11; i++) {
    const char *tag = parcList_GetAtIndex(args, i);
    policy_tag_state_t tag_state;
    tag_state.disabled = (tag[0] == '!') ? 1 : 0;
    if (strcmp(&tag[tag_state.disabled], "neutral") == 0) {
      tag_state.state = POLICY_STATE_NEUTRAL;
    } else if (strcmp(&tag[tag_state.disabled], "require") == 0) {
      tag_state.state = POLICY_STATE_REQUIRE;
    } else if (strcmp(&tag[tag_state.disabled], "prefer") == 0) {
      tag_state.state = POLICY_STATE_PREFER;
    } else if (strcmp(&tag[tag_state.disabled], "avoid") == 0) {
      tag_state.state = POLICY_STATE_AVOID;
    } else if (strcmp(&tag[tag_state.disabled], "prohibit") == 0) {
      tag_state.state = POLICY_STATE_PROHIBIT;
    } else {
      printf("ERROR: invalid tag value '%s'\n", tag);
      parcMemory_Deallocate(&addPolicyCommand);
      free(addr);
      return CommandReturn_Failure;
    }

    policy.tags[i-4] = tag_state;

  }

  addPolicyCommand->policy = policy;

  // send message and receive response
  struct iovec *response = utils_SendRequest(state, ADD_POLICY, addPolicyCommand,
                                             sizeof(add_policy_command));

  if (!response) {  // get NULL pointer
    return CommandReturn_Failure;
  }

  parcMemory_Deallocate(&response);  // free iovec pointer
  return CommandReturn_Success;
}

#endif /* WITH_POLICY */
