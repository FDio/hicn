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

#ifndef UTIL_LOG_H
#define UTIL_LOG_H

#include <stdarg.h> // va_*
#include <stdio.h>  // FILE
#include <time.h>   // time, localtime

typedef enum
{
  LOG_FATAL,
  LOG_ERROR,
  LOG_WARN,
  LOG_INFO,
  LOG_DEBUG,
  LOG_TRACE
} log_level_t;

typedef struct
{
  int log_level;
  int debug;
  FILE *log_file;
} log_conf_t;

#define DEFAULT_LOG_CONF                                                      \
  {                                                                           \
    .log_level = LOG_INFO,                                                    \
    .debug = 0,                                                               \
    .log_file = NULL,                                                         \
  };

extern log_conf_t log_conf;

#define WITH_ERROR(BLOCK)                                                     \
  if (log_conf.log_level >= LOG_ERROR)                                        \
  BLOCK
#define WITH_WARN(BLOCK)                                                      \
  if (log_conf.log_level >= LOG_WARN)                                         \
  BLOCK
#define WITH_INFO(BLOCK)                                                      \
  if (log_conf.log_level >= LOG_INFO)                                         \
  BLOCK
#define WITH_DEBUG(BLOCK)                                                     \
  if (log_conf.log_level >= LOG_DEBUG)                                        \
  BLOCK
#define WITH_TRACE(BLOCK)                                                     \
  if (log_conf.log_level >= LOG_TRACE)                                        \
  BLOCK

#define FATAL(fmt, ...) (_log (LOG_FATAL, fmt, ##__VA_ARGS__))
#ifdef ERROR
#undef ERROR
#endif
#define ERROR(fmt, ...) (_log (LOG_ERROR, fmt, ##__VA_ARGS__))
#define WARN(fmt, ...)	(_log (LOG_WARN, fmt, ##__VA_ARGS__))
#define INFO(fmt, ...)	(_log (LOG_INFO, fmt, ##__VA_ARGS__))
#define DEBUG(fmt, ...) (_log (LOG_DEBUG, fmt, ##__VA_ARGS__))
#define TRACE(fmt, ...) (_log (LOG_TRACE, fmt, ##__VA_ARGS__))

void _log_va (int level, const char *fmt, va_list ap);

void _log (int level, const char *fmt, ...);

void fatal (char *fmt, ...);

int loglevel_from_str (const char *loglevel);

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
void print_trace (void);
#endif

#endif // UTIL_LOG_H
