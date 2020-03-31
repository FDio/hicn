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
 * @file controlState.h
 * @brief A control program for hicn-light using CLI commands
 *
 * Implements the state machine for the control program.  It takes a "writeRead"
 * function as part of the constructor.  This abstracts out the backend.  It
 * could be a Portal from hicnLightControl program down to the forwarder or it
 * could be an internal function within hicn-light.
 *
 */

#ifndef control_h
#define control_h

#include <parc/algol/parc_List.h>
#include <hicn/config/commandParser.h>

#include <hicn/utils/commands.h>

#define SRV_CTRL_IP "127.0.0.1"
#define SRV_CTRL_PORT 9695

struct controller_state;
typedef struct controller_state ControlState;

/**
 * controlState_Create
 *
 * Creates the global state for the Control program.  The user provides the
 * writeRead function for sending and receiving the message wrapping command
 * arguments.  For configuration file inside hicn-light, it would make direct
 * calls to Configuration -> Dispatcher.
 *
 * @param [in] userdata A closure passed back to the user when calling
 * writeRead.
 * @param [in] writeRead The function to write then read configuration messages
 * to hicn-light
 *
 * @return non-null The control state
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */

ControlState *controlState_Create(
    void *userdata,
    uint8_t *(*writeRead)(ControlState *state, uint8_t * msg),
    bool openControllerConnetion,
    char * server_ip, uint16_t port);

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
void controlState_Destroy(ControlState **statePtr);

/**
 * Registers a CommandOps with the system.
 *
 * Each command has its complete command prefix in the "command" field.
 * RegisterCommand will put these command prefixes in to a tree and then match
 * what a user types against the longest-matching prefix in the tree.  If
 * there's a match, it will call the "execute" function.
 *
 * @param [in] state An allocated ControlState
 * @param [in] command The command to register with the system
 *
 * Example:
 * @code
 *      static CommandReturn
 *      control_Root_Execute(CommandParser *parser, CommandOps *ops, PARCList
 * *args)
 *      {
 *          printf("Root Command\n");
 *          return CommandReturn_Success;
 *      }
 *
 *      static CommandReturn
 *      control_FooBar_Execute(CommandParser *parser, CommandOps *ops, PARCList
 * *args)
 *      {
 *          printf("Foo Bar Command\n");
 *          return CommandReturn_Success;
 *      }
 *
 *      const CommandOps control_Root = {
 *      .command = "", // empty string for root
 *      .init    = NULL,
 *      .execute = control_Root_Execute
 *      };
 *
 *      const CommandOps control_FooBar = {
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
void controlState_RegisterCommand(ControlState *state, CommandOps *command);

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
CommandReturn controlState_DispatchCommand(ControlState *state, PARCList *args);

/**
 * Begin an interactive shell
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
int controlState_Interactive(ControlState *state);

/**
 * Write then Read a command
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
struct iovec *controlState_WriteRead(ControlState *state, struct iovec *msg);

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
void controlState_SetDebug(ControlState *state, bool debugFlag);

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
bool controlState_GetDebug(ControlState *state);
#endif  // control_h

void controlState_SetCommandOutput(ControlState *state, char **commandData);

void controlState_ReleaseCommandOutput(ControlState *state, char **commandData,
                                       size_t commandLenght);

char **controlState_GetCommandOutput(ControlState *state);

void controlState_SetInteractiveFlag(ControlState *state, bool interactive);

bool controlState_IsInteractive(ControlState *state);

void *controlState_GetUserdata(ControlState *state);

bool controlState_isConfigFile(ControlState *state);

int controlState_GetSockfd(ControlState *state);
