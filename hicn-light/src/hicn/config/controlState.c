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
#include <string.h>

#include <parc/security/parc_Security.h>

#include <parc/algol/parc_List.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>
#include <parc/algol/parc_Time.h>
#include <parc/algol/parc_TreeRedBlack.h>

#include <hicn/config/commandParser.h>
#include <hicn/config/controlRoot.h>
#include <hicn/config/controlState.h>

#include <hicn/utils/commands.h>

struct controller_state {
  CommandParser *parser;
  bool debugFlag;

  void *userdata;
  uint8_t *(*writeRead)(ControlState *state, uint8_t *msg);
  int sockfd;
  char **commandOutput;
  bool isInteractive;
};

int controlState_connectToFwdDeamon(char *server_ip, uint16_t port) {
  int sockfd;
  struct sockaddr_in servaddr;

  if ((sockfd = (int)socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\nSocket Creation Failed \n");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));

  // Filling server information
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
  inet_pton(AF_INET, server_ip, &(servaddr.sin_addr.s_addr));

  // Establish connection
  if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    printf("\nConnection Failed: hicn-light Daemon is not running \n");
    exit(EXIT_FAILURE);
  }

  return sockfd;
}

ControlState *controlState_Create(
    void *userdata,
    uint8_t *(*writeRead)(ControlState *state, uint8_t * msg),
    bool openControllerConnetion,
    char *server_ip, uint16_t port) {
  ControlState *state = parcMemory_AllocateAndClear(sizeof(ControlState));
  parcAssertNotNull(state, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ControlState));
  state->parser = commandParser_Create();

  state->userdata = userdata;
  state->writeRead = writeRead;
  state->debugFlag = false;
  state->commandOutput = NULL;
  state->isInteractive = true;

  if (openControllerConnetion) {
    state->sockfd = controlState_connectToFwdDeamon(server_ip, port);
  } else {
    state->sockfd = 2;  // stderr
  }

  return state;
}

void controlState_Destroy(ControlState **statePtr) {
  parcAssertNotNull(statePtr, "Parameter statePtr must be non-null");
  parcAssertNotNull(*statePtr,
                    "Parameter statePtr must dereference t non-null");
  ControlState *state = *statePtr;
  // printf("sockid destroyed: %d\n", state->sockfd);
  // close the connection with the fwd deamon
  shutdown(state->sockfd, 2);

  commandParser_Destroy(&state->parser);
  parcMemory_Deallocate((void **)&state);
  *statePtr = NULL;
}

void controlState_SetDebug(ControlState *state, bool debugFlag) {
  parcAssertNotNull(state, "Parameter state must be non-null");
  state->debugFlag = debugFlag;
  commandParser_SetDebug(state->parser, debugFlag);
}

bool controlState_GetDebug(ControlState *state) {
  parcAssertNotNull(state, "Parameter state must be non-null");
  return state->debugFlag;
}

void controlState_RegisterCommand(ControlState *state, CommandOps *ops) {
  parcAssertNotNull(state, "Parameter state must be non-null");
  commandParser_RegisterCommand(state->parser, ops);
}

uint8_t *
controlState_write_read(ControlState *state, uint8_t *packet)
{
    assert(state);
    assert(packet);

    return state->writeRead(state, packet);
}

static PARCList *_controlState_ParseStringIntoTokens(
    const char *originalString) {
  PARCList *list =
      parcList(parcArrayList_Create(parcArrayList_StdlibFreeFunction),
               PARCArrayListAsPARCList);

  char *token;

  char *tofree =
      parcMemory_StringDuplicate(originalString, strlen(originalString) + 1);
  char *string = tofree;

  token = strtok(string, " \t\n");
  while (token != NULL) {
    if (strlen(token) > 0) {
      parcList_Add(list, strdup(token));
    }
    token = strtok(NULL, " \t\n");
  }

  parcMemory_Deallocate((void **)&tofree);

  return list;
}

CommandReturn controlState_DispatchCommand(ControlState *state,
                                           PARCList *args) {
  parcAssertNotNull(state, "Parameter state must be non-null");
  return commandParser_DispatchCommand(state->parser, args);
}

int controlState_Interactive(ControlState *state) {
  parcAssertNotNull(state, "Parameter state must be non-null");
  char *line = NULL;
  size_t linecap = 0;
  CommandReturn controlReturn = CommandReturn_Success;

  while (controlReturn != CommandReturn_Exit && !feof(stdin)) {
    fputs("> ", stdout);
    fflush(stdout);
    ssize_t failure = getline(&line, &linecap, stdin);
    parcAssertTrue(failure > -1, "Error getline");

    PARCList *args = _controlState_ParseStringIntoTokens(line);
    controlReturn = controlState_DispatchCommand(state, args);
    // release and get command
    parcList_Release(&args);
  }
  return 0;
}

void controlState_SetCommandOutput(ControlState *state, char **commandData) {
  state->commandOutput = commandData;
}

void controlState_ReleaseCommandOutput(ControlState *state, char **commandData,
                                       size_t commandLenght) {
  for (size_t i = 0; i < commandLenght; i++) {
    parcMemory_Deallocate(&commandData[i]);
  }
  parcMemory_Deallocate(&commandData);
  state->commandOutput = NULL;
}

char **controlState_GetCommandOutput(ControlState *state) {
  return state->commandOutput;
}

// size_t
// controlState_GetCommandLen(ControlState *state){

// }

void controlState_SetInteractiveFlag(ControlState *state, bool interactive) {
  state->isInteractive = interactive;
}

bool controlState_IsInteractive(ControlState *state) {
  return state->isInteractive;
}

int controlState_GetSockfd(ControlState *state) {
  parcAssertNotNull(state, "Parameter state must be non-null");
  return state->sockfd;
}

void *controlState_GetUserdata(ControlState *state) {
  parcAssertNotNull(state, "Parameter state must be non-null");
  return state->userdata;
}

bool controlState_isConfigFile(ControlState *state) {
  parcAssertNotNull(state, "Parameter state must be non-null");
  if (state->sockfd != 2) {
    return false;
  } else {
    return true;
  }
}
