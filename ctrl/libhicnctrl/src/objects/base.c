/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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
 * \file base.c
 * \brief Implementation of base functions for object APIs.
 */

#include <stdbool.h>

#include "base.h"

#include <hicn/util/log.h>

bool iszero(const void *ptr, int bytes) {
  char *bptr = (char *)ptr;
  while (bytes--)
    if (*bptr++) return false;
  return true;
}

bool isempty(const char *str) { return str[0] == '\0'; }
