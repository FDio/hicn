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

#include <errno.h>
#include <fcntl.h>
#include <src/config.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include <parc/algol/parc_FileOutputStream.h>
#include <parc/logging/parc_LogLevel.h>
#include <parc/logging/parc_LogReporterFile.h>
#include <parc/logging/parc_LogReporterTextStdout.h>

#include <parc/assert/parc_Assert.h>

#include <src/core/dispatcher.h>
#include <src/core/forwarder.h>

static void _displayForwarderLogo(void){
  const char cli_banner [] =
  "\033[0;31m   ____ ___      _       \033[0m  __    _               __ _        __   __\n"
  "\033[0;31m  / __// _ \\    (_)___  \033[0m  / /   (_)____ ___ ____/ /(_)___ _ / /  / /_\n"
  "\033[0;31m / _/ / // /_  / // _ \\ \033[0m / _ \\ / // __// _ \\___/ // // _ `// _ \\/ __/\n"
  "\033[0;31m/_/  /____/(_)/_/ \\___/ \033[0m/_//_//_/ \\__//_//_/  /_//_/ \\_, //_//_/\\__/\n"
  "                                                    /___/            \n";
  printf("%s", cli_banner);
  printf("\n");
}

static void _usage(int exitCode) {
  printf(
      "Usage: daemon [--port port] [--daemon] [--capacity objectStoreSize] "
      "[--log facility=level] [--log-file filename] [--config file]\n");
  printf("\n");
  printf(
      "hicn-light run as a daemon is the program to launch the forwarder, "
      "either as a console program\n");
  printf(
      "or a background daemon (detatched from console).  Once running, use the "
      "program controller to\n");
  printf("configure hicn-light.\n");
  printf("\n");
  printf(
      "The configuration file contains configuration lines as per "
      "controller\n");
  printf(
      "If logging level or content store capacity is set in the configuraiton "
      "file, it overrides the command_line\n");
  printf(
      "When a configuration file is specified, no default listeners on 'port' "
      "are setup.  Only 'add listener' lines\n");
  printf("in the configuration file matter.\n");
  printf("\n");
  printf(
      "If no configuration file is specified, daemon will listen on TCP and "
      "UDP ports specified by\n");
  printf(
      "the --port flag (or default port).  It will listen on both IPv4 and "
      "IPv6 if available.\n");
  printf("\n");
  printf("Options:\n");
  printf("--port            = tcp port for in-bound connections\n");
  printf("--daemon          = start as daemon process\n");
  printf("--objectStoreSize = maximum number of content objects to cache\n");
  printf(
      "--log             = sets a facility to a given log level.  You can have "
      "multiple of these.\n");
  printf(
      "                    facilities: all, config, core, io, message, "
      "processor\n");
  printf(
      "                    levels: debug, info, notice, warning, error, "
      "critical, alert, off\n");
  printf("                    example: daemon --log io=debug --log core=off\n");
  printf(
      "--log-file        = file to write log messages to (required in daemon "
      "mode)\n");
  printf("--config           = configuration filename\n");
  printf("\n");
  exit(exitCode);
}

static void _setLogLevelToLevel(int logLevelArray[LoggerFacility_END],
                                LoggerFacility facility,
                                const char *levelString) {
  PARCLogLevel level = parcLogLevel_FromString(levelString);

  if (level < PARCLogLevel_All) {
    // we have a good facility and level
    logLevelArray[facility] = level;
  } else {
    printf("Invalid log level string %s\n", levelString);
    _usage(EXIT_FAILURE);
  }
}

/**
 * string: "facility=level"
 * Set the right thing in the logger
 */
static void _setLogLevel(int logLevelArray[LoggerFacility_END],
                         const char *string) {
  char *tofree = parcMemory_StringDuplicate(string, strlen(string));
  char *p = tofree;

  char *facilityString = strsep(&p, "=");
  if (facilityString) {
    char *levelString = p;

    if (strcasecmp(facilityString, "all") == 0) {
      for (LoggerFacility facility = 0; facility < LoggerFacility_END;
           facility++) {
        _setLogLevelToLevel(logLevelArray, facility, levelString);
      }
    } else {
      LoggerFacility facility;
      for (facility = 0; facility < LoggerFacility_END; facility++) {
        if (strcasecmp(facilityString, logger_FacilityString(facility)) == 0) {
          break;
        }
      }

      if (facility < LoggerFacility_END) {
        _setLogLevelToLevel(logLevelArray, facility, levelString);
      } else {
        printf("Invalid facility string %s\n", facilityString);
        _usage(EXIT_FAILURE);
      }
    }
  }

  parcMemory_Deallocate((void **)&tofree);
}

static void _daemonize(void) {
  if (getppid() == 1) {
    // already a daemon
    return;
  }

  int forkReturn = fork();
  parcTrapUnexpectedStateIf(forkReturn < 0, "Fork error");

  if (forkReturn > 0) {
    // parent exits
    exit(EXIT_SUCCESS);
  }

  // Child daemon detaches
  printf("child continuing, pid = %u\n", getpid());

  // get a new process group independent from old parent
  setsid();

  /* close all descriptors */
  for (int i = getdtablesize(); i >= 0; --i) {
    close(i);
  }

  // reset errno because it might be seg to EBADF from the close calls above
  errno = 0;

  // Redirect stdin and stdout and stderr to /dev/null
  const char *devnull = "/dev/null";
  int nullfile = open(devnull, O_RDWR);
  parcAssertTrue(nullfile >= 0, "Error opening file '%s': (%d) %s", devnull,
                 errno, strerror(errno));

  int ret;
  ret = dup(nullfile);
  parcAssertTrue(ret == 1, "Error duping fd 1 got %d file: (%d) %s", ret, errno,
                 strerror(errno));
  ret = dup(nullfile);
  parcAssertTrue(ret == 2, "Error duping fd 2, got %d file: (%d) %s", ret,
                 errno, strerror(errno));

  // forwarder will capture signals
}

static Logger *_createLogfile(const char *logfile) {
  int logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT, S_IWUSR | S_IRUSR);
  if (logfd < 0) {
    fprintf(stderr, "Error opening %s for writing: (%d) %s\n", logfile, errno,
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  chmod(logfile, S_IRWXU);

  PARCFileOutputStream *fos = parcFileOutputStream_Create(logfd);
  PARCOutputStream *pos = parcFileOutputStream_AsOutputStream(fos);
  PARCLogReporter *reporter = parcLogReporterFile_Create(pos);

  Logger *logger = logger_Create(reporter, parcClock_Wallclock());

  parcOutputStream_Release(&pos);
  parcLogReporter_Release(&reporter);

  return logger;
}

int main(int argc, const char *argv[]) {
  _displayForwarderLogo();

  uint16_t port = PORT_NUMBER;
  uint16_t configurationPort = 2001;
  bool daemon = false;
  int capacity = -1;
  const char *configFileName = NULL;

  char *logfile = NULL;

  if (argc == 2 && strcasecmp(argv[1], "-h") == 0) {
    _usage(EXIT_SUCCESS);
  }

  int logLevelArray[LoggerFacility_END];
  for (int i = 0; i < LoggerFacility_END; i++) {
    logLevelArray[i] = -1;
  }

  for (int i = 0; i < argc; i++) {
    if (argv[i][0] == '-') {
      if (strcmp(argv[i], "--config") == 0) {
        configFileName = argv[i + 1];
        i++;
      } else if (strcmp(argv[i], "--port") == 0) {
        port = atoi(argv[i + 1]);
        i++;
      } else if (strcmp(argv[i], "--daemon") == 0) {
        daemon = true;
      } else if (strcmp(argv[i], "--capacity") == 0 ||
                 strcmp(argv[i], "-c") == 0) {
        capacity = atoi(argv[i + 1]);
        i++;
      } else if (strcmp(argv[i], "--log") == 0) {
        _setLogLevel(logLevelArray, argv[i + 1]);
        i++;
      } else if (strcmp(argv[i], "--log-file") == 0) {
        if (logfile) {
          // error cannot repeat
          fprintf(stderr, "Cannot specify --log-file more than once\n");
          _usage(EXIT_FAILURE);
        }

        logfile = parcMemory_StringDuplicate(argv[i + 1], strlen(argv[i + 1]));
        i++;
      } else {
        _usage(EXIT_FAILURE);
      }
    }
  }

  // set restrictive umask, in case we create any files
  umask(027);

  if (daemon && (logfile == NULL)) {
    fprintf(stderr, "Must specify a logfile when running in daemon mode\n");
    _usage(EXIT_FAILURE);
  }

  if (daemon) {
    // inside this call, parent will EXIT_SUCCESS and child will continue
    _daemonize();
  }

  Logger *logger = NULL;
  if (logfile) {
    logger = _createLogfile(logfile);
    parcMemory_Deallocate((void **)&logfile);
  } else {
    PARCLogReporter *stdoutReporter = parcLogReporterTextStdout_Create();
    logger = logger_Create(stdoutReporter, parcClock_Wallclock());
    parcLogReporter_Release(&stdoutReporter);
  }

  for (int i = 0; i < LoggerFacility_END; i++) {
    if (logLevelArray[i] > -1) {
      logger_SetLogLevel(logger, i, logLevelArray[i]);
    }
  }

  // this will update the clock to the tick clock
  Forwarder *forwarder = forwarder_Create(logger);

  Configuration *configuration = forwarder_GetConfiguration(forwarder);

  if (capacity > -1) {
    configuration_SetObjectStoreSize(configuration, capacity);
  }

  if (configFileName) {
    forwarder_SetupAllListeners(forwarder, port, NULL);
    forwarder_SetupFromConfigFile(forwarder, configFileName);
  } else {
    // NULL to not setup AF_UNIX
    forwarder_SetupAllListeners(forwarder, port, NULL);
  }

  Dispatcher *dispatcher = forwarder_GetDispatcher(forwarder);

  logger_Log(logger, LoggerFacility_Core, PARCLogLevel_Alert, "daemon",
             "hicn-light running port %d configuration-port %d", port,
             configurationPort);

  dispatcher_Run(dispatcher);

  logger_Log(logger, LoggerFacility_Core, PARCLogLevel_Alert, "daemon",
             "hicn-light exiting port %d", port);

  forwarder_Destroy(&forwarder);

  sleep(2);

  logger_Release(&logger);
  return 0;
}
