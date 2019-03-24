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
 * @file command_Parser.h
 * @brief Creates a dictionary of commands and parses a command_line to match
 * against them
 *
 * A user creates individual CommandParserEntry that map a command_line to a
 * function to execute.  The CommandParser then does a longest-matching prefix
 * match of a command_line to the dictionary of commands and executes the
 * appropriate command.
 *
 */

#ifndef command_parser_h
#define command_parser_h

#include <hicn/config/commandOps.h>
#include <hicn/config/commandReturn.h>

struct command_parser;
typedef struct command_parser CommandParser;

/**
 * controlState_Create
 *
 * Creates the global state for the Control program
 *
 * @return non-null A command parser
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
CommandParser *commandParser_Create(void);

/**
 * Destroys the control state, closing all network connections
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
void commandParser_Destroy(CommandParser **statePtr);

/**
 * Registers a CommandOps with the system.
 *
 * Each command has its complete command prefix in the "command" field.
 * RegisterCommand will put these command prefixes in to a tree and then match
 * what a user types against the longest-matching prefix in the tree.  If
 * there's a match, it will call the "execute" function.
 *
 * When the parser is destroyed, each command's destroyer function will be
 * called.
 *
 * @param [in] state An allocated ControlState
 * @param [in] command The command to register with the system
 *
 * Example:
 * @code
 *      static ControlReturn
 *      control_Root_Execute(CommandParser *parser, CommandOps *ops, PARCList
 * *args)
 *      {
 *          printf("Root Command\n");
 *          return CommandReturn_Success;
 *      }
 *
 *      static ControlReturn
 *      control_FooBar_Execute(CommandParser *parser, CommandOps *ops, PARCList
 * *args)
 *      {
 *          printf("Foo Bar Command\n");
 *          return CommandReturn_Success;
 *      }
 *
 *      const CommandOps control_Root = {
 *      .closure = NULL,
 *      .command = "", // empty string for root
 *      .init    = NULL,
 *      .execute = control_Root_Execute
 *      };
 *
 *      const CommandOps control_FooBar = {
 *      .closure = NULL,
 *      .command = "foo bar", // empty string for root
 *      .init    = NULL,
 *      .execute = control_FooBar_Execute
 *      };
 *
 *   void startup(void)
 *   {
 *      ControlState *state = controlState_Create("happy", "day");
 *      controlState_RegisterCommand(state, control_FooBar);
 *      controlState_RegisterCommand(state, control_Root);
 *
 *      // this executes "root"
 *      controlState_DispatchCommand(state, "foo");
 *      controlState_Destroy(&state);
 *  }
 * @endcode
 */
void commandParser_RegisterCommand(CommandParser *state, CommandOps *command);

/**
 * Performs a longest-matching prefix of the args to the command tree
 *
 * The command tree is created with controlState_RegisterCommand.
 *
 * @param [in] state The allocated ControlState
 * @param [in] args  Each command_line word parsed to the ordered list
 *
 * @return CommandReturn_Success the command was successful
 * @return CommandReturn_Failure the command failed or was not found
 * @return CommandReturn_Exit the command indicates that the interactive mode
 * should exit
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
CommandReturn commandParser_DispatchCommand(CommandParser *state,
                                            PARCList *args);

/**
 * Sets the Debug mode, which will print out much more information.
 *
 * Prints out much more diagnostic information about what hicn-light controller
 * is doing. yes, you would make a CommandOps to set and unset this :)
 *
 * @param [in] debugFlag true means to print debug info, false means to turn it
 * off
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
void commandParser_SetDebug(CommandParser *state, bool debugFlag);

/**
 * Returns the debug state of ControlState
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
bool commandParser_GetDebug(CommandParser *state);

/**
 * Checks if the command is registered
 *
 * Checks if the exact command given is registered.  This is not a prefix match.
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * @return true The command is registered
 * @return false The command is not registered
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
bool commandParser_ContainsCommand(CommandParser *parser, const char *command);
#endif  // command_parser_h
