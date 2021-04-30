/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#pragma once
#include <hicn/util/windows/windows_Utils.h>
#include <afunix.h>
#include <io.h>
#include <iphlpapi.h>
#include <process.h>
#include <stdio.h>
#pragma comment(lib, "IPHLPAPI.lib")

#ifndef in_port_t
#define in_port_t uint16_t
#endif

#ifndef in_addr_t
#define in_addr_t uint32_t
#endif

#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif

#define HAVE_STRUCT_TIMESPEC

#ifndef getline
int getline(char **lineptr, size_t *n, FILE *stream);
#endif