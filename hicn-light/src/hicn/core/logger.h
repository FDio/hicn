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
 * @file logger.h
 * @brief Logger for the hicn-light forwarder
 *
 * A facility based logger to allow selective logging from different parts of
 * hicn-light
 *
 */

#ifndef logger_h
#define logger_h

#ifndef _WIN32
#include <sys/time.h>
#endif
#include <parc/algol/parc_Buffer.h>
#include <parc/algol/parc_Clock.h>
#include <parc/logging/parc_LogLevel.h>
#include <parc/logging/parc_LogReporter.h>
#include <stdarg.h>

struct logger;
typedef struct logger Logger;

/**
 * CONFIG faciilty concerns anything in the /config directory
 * CORE concerns anything in the /core directory
 * IO concerns anything in the /io directory (listeners, connectors, tcp,
 * ethernet, etc.) PROCESSOR concerns FIB, PIT, CS MESSAGE concerns message
 * events, like parsing
 */
typedef enum {
  LoggerFacility_Config,
  LoggerFacility_Core,
  LoggerFacility_IO,
  LoggerFacility_Processor,
  LoggerFacility_Message,
  LoggerFacility_Strategy,
  LoggerFacility_END  // sentinel value
} LoggerFacility;

/**
 * Returns a string representation of a facility
 *
 * Do not free the returned value.
 *
 * @param [in] facility The facility to change to a string
 *
 * @retval string A string representation of the facility
 */
const char *logger_FacilityString(LoggerFacility facility);

/**
 * Returns a string representation of a log level
 *
 * Do not free the returned value.
 *
 * @param [in] level The level to change to a string
 *
 * @retval string A string representation of the level
 */
const char *logger_LevelString(PARCLogLevel level);

/**
 * Create a logger that uses a given writer and clock
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] writer The output writer
 * @param [in] clock The clock to use for log messages
 *
 * @retval non-null An allocated logger
 * @retval null An error
 */
Logger *logger_Create(PARCLogReporter *reporter, const PARCClock *clock);

/**
 * Release logger
 */
void logger_Release(Logger **loggerPtr);

/**
 * Acquire logger
 */
Logger *logger_Acquire(const Logger *logger);

/**
 * Sets the minimum log level for a facility
 *
 * The default log level is ERROR.  For a message to be logged, it must be of
 * equal or higher log level.
 *
 * @param [in] logger An allocated logger
 * @param [in] facility The facility to set the log level for
 * @param [in] The minimum level to log
 *
 */
void logger_SetLogLevel(Logger *logger, LoggerFacility facility,
                        PARCLogLevel minimumLevel);

/**
 * Tests if the log level would be logged
 *
 * If the facility would log the given level, returns true.  May be used as a
 * guard around expensive logging functions.
 *
 * @param [in] logger An allocated logger
 * @param [in] facility The facility to test
 * @param [in] The level to test
 *
 * @retval true The given facility would log the given level
 * @retval false A message of the given level would not be logged
 *
 */
bool logger_IsLoggable(const Logger *logger, LoggerFacility facility,
                       PARCLogLevel level);

/**
 * Log a message
 *
 * The message will only be logged if it is loggable (logger_IsLoggable returns
 * true).
 *
 * @param [in] logger An allocated Logger
 * @param [in] facility The facility to log under
 * @param [in] level The log level of the message
 * @param [in] module The specific module logging the message
 * @param [in] format The message with varargs
 *
 */
void logger_Log(Logger *logger, LoggerFacility facility, PARCLogLevel level,
                const char *module, const char *format, ...);

/**
 * Switch the logger to a new reporter
 *
 * Will close the old reporter and re-setup the internal loggers to use the new
 * reporter. All current log level settings are preserved.
 *
 * @param [in] logger An allocated Logger
 * @param [in] reporter An allocated PARCLogReporter
 */
void logger_SetReporter(Logger *logger, PARCLogReporter *reporter);

/**
 * Set a new clock to use with the logger
 *
 * The logger will start getting the time (logged as the messageid) from the
 * specified clock
 *
 * @param [in] logger An allocated Logger
 * @param [in] clock An allocated PARCClock
 */
void logger_SetClock(Logger *logger, PARCClock *clock);
#endif  // logger_h
