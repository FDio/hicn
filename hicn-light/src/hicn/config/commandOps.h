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

/**
 * @file command_Ops.h
 * @brief The function structure defining a CLI command
 *
 * The function structure that defines a CLI command.  Each command will return
 * one of these which defines how to run the command.
 *
 */

#ifndef command_Ops_h
#define command_Ops_h

#include <parc/algol/parc_List.h>

#include <hicn/config/commandReturn.h>

// forward reference
struct command_parser;

struct command_ops;
typedef struct command_ops CommandOps;

/**
 * @typedef CommandOps
 * @abstract Each command implements a CommandOps
 * @constant closure is a user-specified pointer for any state the user needs
 * @constant command The text string of the command, must be the spelled out
 * string, e.g. "help list routes"
 * @constant init A function to call to initialize the command at program
 * startup
 * @constant execute A function to call to execute the command
 * @constant destroyer A function to call to release the command
 * @discussion
 *     Typically, the root of the thee has an Init function that then initilizes
 * the rest of the tree.  For example:
 *
 * @code
 *    const CommandOps control_Root = {
 *      .closure = NULL,
 *      .command = "", // empty string for root
 *      .init    = control_Root_Init,
 *      .execute = control_Root_Execute
 *      .destroyer = NULL
 *    };
 * @endcode
 *
 * The control_Root_Init function will then begin adding the subtree under root.
 * For example:
 *
 * @code
 *  const CommandOps control_Add = {
 *      .closure = NULL,
 *      .command = "add",
 *      .init    = control_Add_Init,
 *      .execute = control_Add_Execute,
 *      .destroyer = NULL
 *  };
 *
 *  static void
 *  control_Root_Init(ControlState *state, CommandOps *ops)
 *  {
 *      controlState_RegisterCommand(state, &control_Add);
 *  }
 * @endcode
 */
struct command_ops {
  void *closure;
  char *command;
  void (*init)(struct command_parser *parser, CommandOps *ops);
  CommandReturn (*execute)(struct command_parser *parser, CommandOps *ops,
                           PARCList *args);
  void (*destroyer)(CommandOps **opsPtr);
};

/**
 * A helper function to create the pubically defined CommandOps.
 *
 * Retruns allocated memory of the command
 *
 * @param [in] command The string is copied
 *
 * @retval <#value#> <#explanation#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
CommandOps *commandOps_Create(
    void *closure, const char *command,
    void (*init)(struct command_parser *parser, CommandOps *ops),
    CommandReturn (*execute)(struct command_parser *parser, CommandOps *ops,
                             PARCList *args),
    void (*destroyer)(CommandOps **opsPtr));

/**
 * De-allocates the memory of the CommandOps and the copied command string
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * @retval <#value#> <#explanation#>
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
void commandOps_Destroy(CommandOps **opsPtr);
#endif  // command_Ops_h
