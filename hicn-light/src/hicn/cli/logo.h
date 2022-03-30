/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef HICNLIGHT_LOGO
#define HICNLIGHT_LOGO

#include "color.h"

static void logo(void) {
  printfc(COLOR_RED, "   ____ ___      _       ");
  printfc(COLOR_WHITE, "  __    _               __ _        __   __\n");
  printfc(COLOR_RED, "  / __// _ \\    (_)___  ");
  printfc(COLOR_WHITE, "  / /   (_)____ ___ ____/ /(_)___ _ / /  / /_\n");
  printfc(COLOR_RED, " / _/ / // /_  / // _ \\ ");
  printfc(COLOR_WHITE, " / _ \\ / // __// _ \\___/ // // _ `// _ \\/ __/\n");
  printfc(COLOR_RED, "/_/  /____/(_)/_/ \\___/ ");
  printfc(COLOR_WHITE, "/_//_//_/ \\__//_//_/  /_//_/ \\_, //_//_/\\__/\n");
  printfc(
      COLOR_WHITE,
      "                                                    /___/            "
      "\n");
  printf("\n");
}

#endif /* HICNLIGHT_LOGO */
