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

#ifndef HICNLIGHT_COLOR
#define HICNLIGHT_COLOR

#include <stdarg.h>

/*
 * Format : color_name, escape sequence, windows id
 */
#define foreach_color     \
  _(RED, "\033[0;31m", 4) \
  _(WHITE, "\033[0m", 7)

typedef enum {
  COLOR_UNDEFINED,
#define _(x, y, z) COLOR_##x,
  foreach_color
#undef _
      COLOR_N,
} color_t;

#define IS_VALID_COLOR(color) ((color != COLOR_UNDEFINED) && (color != COLOR_N))

void vprintfc(color_t color, const char* fmt, va_list ap);

void printfc(color_t color, const char* fmt, ...);

#endif /* HICNLIGHT_COLOR */
