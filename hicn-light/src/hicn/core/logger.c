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

#ifndef _WIN32
#include <unistd.h>
#endif

#include <errno.h>
#include <hicn/hicn-light/config.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>

#include <parc/logging/parc_Log.h>

#include <hicn/core/forwarder.h>
#include <hicn/core/logger.h>

struct logger {
  PARCClock *clock;

  PARCLogReporter *reporter;
  PARCLog *loggerArray[LoggerFacility_END];
};

static const struct facility_to_string {
  LoggerFacility facility;
  const char *string;
} _facilityToString[] = {
    {.facility = LoggerFacility_Config, .string = "Config"},
    {.facility = LoggerFacility_Core, .string = "Core"},
    {.facility = LoggerFacility_IO, .string = "IO"},
    {.facility = LoggerFacility_Message, .string = "Message"},
    {.facility = LoggerFacility_Processor, .string = "Processor"},
    {.facility = LoggerFacility_Strategy, .string = "Strategy"},
    {.facility = 0, .string = NULL}};

const char *logger_FacilityString(LoggerFacility facility) {
  for (int i = 0; _facilityToString[i].string != NULL; i++) {
    if (_facilityToString[i].facility == facility) {
      return _facilityToString[i].string;
    }
  }
  return "Unknown";
}

static void _allocateLoggers(Logger *logger, PARCLogReporter *reporter) {
  parcTrapUnexpectedStateIf(
      logger->reporter != NULL,
      "Trying to allocate a reporter when the previous one is not null");
  logger->reporter = parcLogReporter_Acquire(reporter);

  char hostname[255];
  int gotHostName = gethostname(hostname, 255);
  if (gotHostName < 0) {
    snprintf(hostname, 255, "unknown");
  }

  for (int i = 0; i < LoggerFacility_END; i++) {
    logger->loggerArray[i] = parcLog_Create(hostname, logger_FacilityString(i),
                                            "forwarder", logger->reporter);
    parcLog_SetLevel(logger->loggerArray[i], PARCLogLevel_Error);
  }
}

static void _releaseLoggers(Logger *logger) {
  for (int i = 0; i < LoggerFacility_END; i++) {
    parcLog_Release(&logger->loggerArray[i]);
  }
  parcLogReporter_Release(&logger->reporter);
}

static void _destroyer(Logger **loggerPtr) {
  Logger *logger = *loggerPtr;
  _releaseLoggers(logger);
  parcClock_Release(&(*loggerPtr)->clock);
}

parcObject_ExtendPARCObject(Logger, _destroyer, NULL, NULL, NULL, NULL, NULL,
                            NULL);

parcObject_ImplementAcquire(logger, Logger);

parcObject_ImplementRelease(logger, Logger);

Logger *logger_Create(PARCLogReporter *reporter, const PARCClock *clock) {
  parcAssertNotNull(reporter, "Parameter reporter must be non-null");
  parcAssertNotNull(clock, "Parameter clock must be non-null");

  Logger *logger = parcObject_CreateAndClearInstance(Logger);
  if (logger) {
    logger->clock = parcClock_Acquire(clock);
    _allocateLoggers(logger, reporter);
  }

  return logger;
}

void logger_SetReporter(Logger *logger, PARCLogReporter *reporter) {
  parcAssertNotNull(logger, "Parameter logger must be non-null");

  // save the log level state
  PARCLogLevel savedLevels[LoggerFacility_END];
  for (int i = 0; i < LoggerFacility_END; i++) {
    savedLevels[i] = parcLog_GetLevel(logger->loggerArray[i]);
  }

  _releaseLoggers(logger);

  _allocateLoggers(logger, reporter);

  // restore log level state
  for (int i = 0; i < LoggerFacility_END; i++) {
    parcLog_SetLevel(logger->loggerArray[i], savedLevels[i]);
  }
}

void logger_SetClock(Logger *logger, PARCClock *clock) {
  parcAssertNotNull(logger, "Parameter logger must be non-null");
  parcClock_Release(&logger->clock);
  logger->clock = parcClock_Acquire(clock);
}

static void _assertInvariants(const Logger *logger, LoggerFacility facility) {
  parcAssertNotNull(logger, "Parameter logger must be non-null");
  parcTrapOutOfBoundsIf(facility >= LoggerFacility_END, "Invalid facility %d",
                        facility);
}

void logger_SetLogLevel(Logger *logger, LoggerFacility facility,
                        PARCLogLevel minimumLevel) {
  _assertInvariants(logger, facility);
  PARCLog *log = logger->loggerArray[facility];
  parcLog_SetLevel(log, minimumLevel);
}

bool logger_IsLoggable(const Logger *logger, LoggerFacility facility,
                       PARCLogLevel level) {
  _assertInvariants(logger, facility);
  PARCLog *log = logger->loggerArray[facility];
  return parcLog_IsLoggable(log, level);
}

void logger_Log(Logger *logger, LoggerFacility facility, PARCLogLevel level,
                const char *module, const char *format, ...) {
  if (logger_IsLoggable(logger, facility, level)) {
    // this is logged as the messageid
    uint64_t logtime = parcClock_GetTime(logger->clock);

    // logger_IsLoggable asserted invariants so we know facility is in bounds
    PARCLog *log = logger->loggerArray[facility];

    va_list va;
    va_start(va, format);

    parcLog_MessageVaList(log, level, logtime, format, va);

    va_end(va);
  }
}
