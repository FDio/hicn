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

#include <parc/assert/parc_Assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parc/security/parc_Security.h>

#include <parc/algol/parc_List.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Time.h>
#include <parc/algol/parc_TreeRedBlack.h>

#include <hicn/config/commandParser.h>

#ifndef __ANDROID__
#ifdef HAVE_ERRNO_H
#include <errno.h>
#else
#ifndef _WIN32
extern int errno;
#endif
#endif
#endif

struct command_parser {
  // key = command, value = CommandOps
  PARCTreeRedBlack *commandTree;
  bool debugFlag;
};

static int _stringCompare(const void *key1, const void *key2) {
  return strcasecmp((const char *)key1, (const char *)key2);
}

CommandParser *commandParser_Create(void) {
  CommandParser *state = parcMemory_AllocateAndClear(sizeof(CommandParser));
  parcAssertNotNull(state, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(CommandParser));

  state->commandTree = parcTreeRedBlack_Create(_stringCompare,  // key compare
                                               NULL,            // key free
                                               NULL,            // key copy
                                               NULL,            // value equals
                                               NULL,            // value free
                                               NULL             // value copy
  );
  state->debugFlag = false;
  return state;
}

void commandParser_Destroy(CommandParser **parserPtr) {
  CommandParser *parser = *parserPtr;

  // destroy every element if it has a destroyer
  PARCArrayList *values = parcTreeRedBlack_Values(parser->commandTree);
  if (values) {
    for (int i = 0; i < parcArrayList_Size(values); i++) {
      CommandOps *ops = parcArrayList_Get(values, i);
      parcTreeRedBlack_Remove(parser->commandTree, ops->command);
      if (ops->destroyer) {
        ops->destroyer(&ops);
      }
    }
    parcArrayList_Destroy(&values);
  }

  parcTreeRedBlack_Destroy(&parser->commandTree);

  parcMemory_Deallocate((void **)&parser);
  *parserPtr = NULL;
}

void commandParser_SetDebug(CommandParser *state, bool debugFlag) {
  state->debugFlag = debugFlag;
}

bool commandParser_GetDebug(CommandParser *state) { return state->debugFlag; }

void commandParser_RegisterCommand(CommandParser *state, CommandOps *ops) {
  parcAssertNotNull(state, "Parameter state must be non-null");
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  parcAssertNotNull(ops->command, "Operation command string must be non-null");

  void *exists = parcTreeRedBlack_Get(state->commandTree, ops->command);
  parcAssertNull(exists, "Command '%s' already exists in the tree %p\n",
                 ops->command, (void *)exists);

  parcTreeRedBlack_Insert(state->commandTree, (void *)ops->command,
                          (void *)ops);

  // if the command being registered asked for an init function to be called,
  // call it
  if (ops->init != NULL) {
    ops->init(state, ops);
  }
}

static PARCList *parseStringIntoTokens(const char *originalString) {
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

/**
 * Matches the user arguments to available commands, returning the command or
 * NULL if not found
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * @return <#value#> <#explanation#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
static CommandOps *commandParser_MatchCommand(CommandParser *state,
                                              PARCList *args) {
  // Find the longest matching prefix command.
  // Pretty wildly inefficient

  size_t longest_token_count = 0;
  char *longest_command = NULL;

  PARCArrayList *commands = parcTreeRedBlack_Keys(state->commandTree);
  for (int i = 0; i < parcArrayList_Size(commands); i++) {
    char *command = parcArrayList_Get(commands, i);
    PARCList *command_tokens = parseStringIntoTokens(command);

    // is it a prefix match?
    if (parcList_Size(args) >= parcList_Size(command_tokens)) {
      bool possible_match = true;
      for (int i = 0; i < parcList_Size(command_tokens) && possible_match;
           i++) {
        const char *a = parcList_GetAtIndex(command_tokens, i);
        const char *b = parcList_GetAtIndex(args, i);
        if (strncasecmp(a, b, strlen(a) + 1) != 0) {
          possible_match = false;
        }
      }

      if (possible_match &&
          parcList_Size(command_tokens) > longest_token_count) {
        longest_token_count = parcList_Size(command_tokens);
        longest_command = command;
      }
    }

    parcList_Release(&command_tokens);
  }

  parcArrayList_Destroy(&commands);

  if (longest_token_count == 0) {
    return NULL;
  } else {
    CommandOps *ops = parcTreeRedBlack_Get(state->commandTree, longest_command);
    parcAssertNotNull(ops, "Got null operations for command '%s'\n",
                      longest_command);
    return ops;
  }
}

CommandReturn commandParser_DispatchCommand(CommandParser *state,
                                            PARCList *args,
                                            char *output,
                                            size_t output_size) {
  parcAssertNotNull(output, "output buffer is null\n");
  CommandOps *ops = commandParser_MatchCommand(state, args);

  if (ops == NULL) {
    snprintf(output, output_size, "Command not found.\n");
    return CommandReturn_Failure;
  } else {
    return ops->execute(state, ops, args, output, output_size);
  }
}

bool commandParser_ContainsCommand(CommandParser *parser, const char *command) {
  CommandOps *ops = parcTreeRedBlack_Get(parser->commandTree, command);
  return (ops != NULL);
}
