/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
 * @file cli.h
 * @brief Command line helpers
 */

#ifndef HICNCTRL_CLI
#define HICNCTRL_CLI

#include "api.h"

#define MAXSZ_OBJECT 255 // XXX

int hc_object_type_snprintf(char * buf, size_t size, hc_object_type_t type, uint8_t * data);
int hc_object_snprintf(char * buf, size_t size, hc_object_t * object);

#endif /* HICNCTRL_CLI */
