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

#include <stdio.h>
#include "color.h"

#ifndef _WIN32

void
vprintfc(color_t color, const char * fmt, va_list ap)
{
    char * color_s;
    switch(color) {
#define _(x, y, z)              \
        case COLOR_ ## x:       \
            color_s = y;          \
            break;
    foreach_color
#undef _

        case COLOR_UNDEFINED:
        case COLOR_N:
            color_s = "";
            break;
    }
    printf("%s", color_s);
    vprintf(fmt, ap);
}
#else
void
vprintfc(color_t color, const char * fmt, va_list ap)
{
    int color_id;
    switch(color) {
#define _(x, y, z)              \
        case COLOR_ ## x:       \
            color_id = z;          \
            break;
    foreach_color
#undef _

        case COLOR_UNDEFINED:
        case COLOR_N:
            color_id = 0;
            break;
    }
    HANDLE hConsole = NULL;
    WORD currentConsoleAttr;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleScreenBufferInfo(hConsole, &csbi))
        currentConsoleAttr = csbi.wAttributes;
    if (color_id != 0)
        SetConsoleTextAttribute(hConsole, color_id);
    fprintf("%s", color);
    vfprintf(fmt, ap);
    SetConsoleTextAttribute(hConsole, currentConsoleAttr);
}
#endif

void
printfc(color_t color, const char * fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintfc(color, fmt, ap);
    va_end(ap);
}
