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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Time.h>

#include <hicn/config/controlListPolicies.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

static CommandReturn _controlListPolicies_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args);
static CommandReturn _controlListPolicies_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args);

static const char *_commandListPolicies = "list policies";
static const char *_commandListPoliciesHelp = "help list policies";

// ====================================================

CommandOps *controlListPolicies_Create(ControlState *state) {
  return commandOps_Create(state, _commandListPolicies, NULL,
                           _controlListPolicies_Execute, commandOps_Destroy);
}

CommandOps *controlListPolicies_HelpCreate(ControlState *state) {
  return commandOps_Create(state, _commandListPoliciesHelp, NULL,
                           _controlListPolicies_HelpExecute, commandOps_Destroy);
}

// ====================================================

static CommandReturn _controlListPolicies_HelpExecute(CommandParser *parser,
                                                    CommandOps *ops,
                                                    PARCList *args) {
  printf("command: list policies\n");
  printf("\n");
  return CommandReturn_Success;
}

#define MAX(x,y) (x > y ? x : y)
#define MAXSZ_COLUMN MAX(MAXSZ_POLICY_TAG, MAXSZ_POLICY_TAG_STATE)

#define MAXSZ_STR_STAT 10
#define MAXSZ_APP_NAME 25

typedef struct {
  #define _(x, y) char x[MAXSZ_POLICY_TAG_STATE];
  foreach_policy_tag
  #undef _
} tag_state_str_t;

static CommandReturn _controlListPolicies_Execute(CommandParser *parser,
                                                CommandOps *ops,
                                                PARCList *args) {
  if (parcList_Size(args) != 2) {
    _controlListPolicies_HelpExecute(parser, ops, args);
    return CommandReturn_Failure;
  }

  ControlState *state = ops->closure;

  // send message and receive response
  struct iovec *response = utils_SendRequest(state, LIST_POLICIES, NULL, 0);
  if (!response) {  // get NULL pointer = FAILURE
    return CommandReturn_Failure;
  }

  // Process/Print message
  header_control_message *receivedHeader =
      (header_control_message *)response[0].iov_base;
  uint8_t *receivedPayload = (uint8_t *)response[1].iov_base;
  if (!receivedPayload) {
      printf("No payload!\n");
      return CommandReturn_Failure;
  }

  // Allocate output to pass to the main function if the call is not interactive
  char **commandOutputMain = NULL;
  if (!controlState_IsInteractive(state) && receivedHeader->length > 0) {
    commandOutputMain =
        parcMemory_Allocate(sizeof(char *) * receivedHeader->length);
    for (size_t j = 0; j < receivedHeader->length; j++) {
      commandOutputMain[j] = parcMemory_Allocate(sizeof(char) * 128);
    }
  }

  char *addrString = NULL;
  in_port_t port = htons(1234);  // this is a random port number that is ignored

  if (receivedHeader->length > 0) {
    printf("%*s %*s"
            #define _(x, y) " %*s"
            foreach_policy_tag
            #undef _
            "%s",
            MAXSZ_PREFIX, "prefix", MAXSZ_APP_NAME /*APP_NAME_LEN*/, "app_name",
            #define _(x, y) MAXSZ_COLUMN, policy_tag_str[POLICY_TAG_ ## x],
            foreach_policy_tag
            #undef _
            "\n");
  } else {
    printf(" --- No entry in the list \n");
  }

  tag_state_str_t str;

  for (int i = 0; i < receivedHeader->length; i++) {
    list_policies_command *listPoliciesCommand =
        (list_policies_command *)(receivedPayload +
                                (i * sizeof(list_policies_command)));

#if 0
    char tag_s[MAXSZ_POLICY_TAG_STATE * POLICY_TAG_N];

        policy_tag_state_snprintf((char*)&tag_s[MAXSZ_POLICY_TAG_STATE * POLICY_TAG_ ## x],      \
                MAXSZ_POLICY_TAG_STATE,                                 \
                &listPoliciesCommand->policy.tags[POLICY_TAG_ ## x]);
#endif

    #define _(x, y) policy_tag_state_snprintf(str.x, MAXSZ_POLICY_TAG_STATE, &listPoliciesCommand->policy.tags[POLICY_TAG_ ## x]);
    foreach_policy_tag
    #undef _

    addrString = utils_CommandAddressToString(
        listPoliciesCommand->family, &listPoliciesCommand->address, &port);

#if 0
    PARCBufferComposer *composer = parcBufferComposer_Create();

    parcBufferComposer_Format(
        composer, "%*s %*s"
        #define _(x, y) " %*s"
        foreach_policy_tag
        #undef _
        "%s",
        MAXSZ_PREFIX, addrString, APP_NAME_LEN, listPoliciesCommand->policy.app_name,
        #define _(x, y) MAXSZ_COLUMN, str.x,
        foreach_policy_tag
        #undef _
        "");

    PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
    char *result = parcBuffer_ToString(tempBuffer);
    parcBuffer_Release(&tempBuffer);

    if (!controlState_IsInteractive(state)) {
      strcpy(commandOutputMain[i], result);
    }

    puts(result);
    parcMemory_Deallocate((void **)&result);
    parcBufferComposer_Release(&composer);
#else
    printf("%*s %*s"
        #define _(x, y) " %*s"
        foreach_policy_tag
        #undef _
        "%s\n",
        MAXSZ_PREFIX, addrString, MAXSZ_APP_NAME /*APP_NAME_LEN*/, listPoliciesCommand->policy.app_name,
        #define _(x, y) MAXSZ_COLUMN, str.x,
        foreach_policy_tag
        #undef _
        "");

#endif
  }

#if 0
  printf("\nSTATISTICS\n\n");
  // STATISTICS
  printf("%*s %*s %*s | %*s | %*s | %*s\n",
          MAXSZ_PREFIX, "", MAXSZ_APP_NAME /*APP_NAME_LEN*/, "",
          3*MAXSZ_STR_STAT+2, "WIRED", 3*MAXSZ_STR_STAT+2, "WIFI", 3*MAXSZ_STR_STAT+2, "CELLULAR", 3*MAXSZ_STR_STAT+2, "ALL");
  printf("%*s %*s %*s %*s %*s | %*s %*s %*s | %*s %*s %*s | %*s %*s %*s\n",
            MAXSZ_PREFIX, "prefix", MAXSZ_APP_NAME /*APP_NAME_LEN*/, "app_name",
            MAXSZ_STR_STAT, "throughput", MAXSZ_STR_STAT, "latency", MAXSZ_STR_STAT, "loss_rate",
            MAXSZ_STR_STAT, "throughput", MAXSZ_STR_STAT, "latency", MAXSZ_STR_STAT, "loss_rate",
            MAXSZ_STR_STAT, "throughput", MAXSZ_STR_STAT, "latency", MAXSZ_STR_STAT, "loss_rate",
            MAXSZ_STR_STAT, "throughput", MAXSZ_STR_STAT, "latency", MAXSZ_STR_STAT, "loss_rate");
  for (int i = 0; i < receivedHeader->length; i++) {
    list_policies_command *listPoliciesCommand =
        (list_policies_command *)(receivedPayload +
                                (i * sizeof(list_policies_command)));
    addrString = utils_CommandAddressToString(
        listPoliciesCommand->family, &listPoliciesCommand->address, &port);
    printf("%*s %*s %*.2f %*.2f %*.2f | %*.2f %*.2f %*.2f | %*.2f %*.2f %*.2f | %*.2f %*.2f %*.2f\n",
        MAXSZ_PREFIX, addrString, MAXSZ_APP_NAME, listPoliciesCommand->policy.app_name,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.wired.throughput,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.wired.latency,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.wired.loss_rate,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.wifi.throughput,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.wifi.latency,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.wifi.loss_rate,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.cellular.throughput,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.cellular.latency,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.cellular.loss_rate,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.all.throughput,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.all.latency,
        MAXSZ_STR_STAT, listPoliciesCommand->prefix_stats.all.loss_rate);
 }
#endif

  controlState_SetCommandOutput(state, commandOutputMain);

  // DEALLOCATE
  parcMemory_Deallocate((void **)&addrString);
  parcMemory_Deallocate(&receivedHeader);   // free response[0].iov_base
  parcMemory_Deallocate(&receivedPayload);  // free response[1].iov_base
  parcMemory_Deallocate(&response);         // free iovec pointer

  return CommandReturn_Success;
}

#endif /* WITH_POLICY */
