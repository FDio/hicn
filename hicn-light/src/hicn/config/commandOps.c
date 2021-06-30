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
#include <string.h>

#ifndef __ANDROID__
#ifdef HAVE_ERRNO_H
#include <errno.h>
#else
#ifndef _WIN32
extern int errno;
#endif
#endif
#endif

#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/config/commandOps.h>
#include <hicn/config/commandParser.h>

CommandOps *commandOps_Create(void *closure, const char *command,
                              void (*init)(CommandParser *parser,
                                           CommandOps *ops),
                              CommandReturn (*execute)(CommandParser *parser,
                                                       CommandOps *ops,
                                                       PARCList *args,
                                                       char *output,
                                                       size_t output_size),
                              void (*destroyer)(CommandOps **opsPtr)) {
  parcAssertNotNull(command, "Parameter command must be non-null");
  parcAssertNotNull(execute, "Parameter execute must be non-null");
  CommandOps *ops = parcMemory_AllocateAndClear(sizeof(CommandOps));
  parcAssertNotNull(ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(CommandOps));

  ops->closure = closure;
  ops->command = parcMemory_StringDuplicate(command, strlen(command) + 1);
  ops->init = init;
  ops->execute = execute;
  ops->destroyer = destroyer;
  return ops;
}

void commandOps_Destroy(CommandOps **opsPtr) {
  parcAssertNotNull(opsPtr, "Parameter opsPtr must be non-null");
  parcAssertNotNull(*opsPtr,
                    "Parameter opsPtr must dereference to non-null pointer");

  CommandOps *ops = *opsPtr;
  parcMemory_Deallocate((void **)&(ops->command));
  // DO NOT call ops->destroyer, we are one!
  parcMemory_Deallocate((void **)&ops);

  *opsPtr = NULL;
}
