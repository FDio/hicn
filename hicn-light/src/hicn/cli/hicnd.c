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
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

//#include <hicn/hicn-light/config.h>
#include <hicn/util/log.h>

#include "logo.h"
#include "../base/loop.h"
#include "../core/forwarder.h"

static
void
usage(const char * prog)
{
  printf("Usage: %s [--port port]"
#ifndef _WIN32
         " [--daemon]"
#endif
         " [--capacity objectStoreSize] [--log facility=level]"
         "[--log-file filename] [--config file]\n", prog);
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
#ifndef _WIN32
  printf("--daemon          = start as daemon process\n");
#endif
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
}

#if 0
static void _setLogLevelToLevel(int logLevelArray[LoggerFacility_END],
                                LoggerFacility facility,
                                const char *levelString) {
  PARCLogLevel level = parcLogLevel_FromString(levelString);

  if (level < PARCLogLevel_All) {
    // we have a good facility and level
    logLevelArray[facility] = level;
  } else {
    printf("Invalid log level string %s\n", levelString);
    usage(""); // XXX
    exit(EXIT_FAILURE);
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

  char *facilityString = strtok(p, "=");
  if (facilityString) {
    char *levelString = strtok(NULL, "=");

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
        usage(""); // XXX
        exit(EXIT_FAILURE);
      }
    }
  }

  parcMemory_Deallocate((void **)&tofree);
}
#endif

#ifndef _WIN32
static
int daemonize(void)
{
    /* Check whether we already are a daemon */
    if (getppid() == 1)
        return 0;

    int rc = fork();
    if (rc < 0) {
        ERROR("Fork error");
        goto ERR_FORK;
    } else if (rc > 0) {
        /* Parent exits successfully */
        exit(EXIT_SUCCESS);
    }

    /* Child daemon detaches */
    DEBUG("child continuing, pid = %u\n", getpid());

    /* get a new process group independent from old parent */
    setsid();

    /* close all descriptors */
#ifdef __ANDROID__
    for (int i = sysconf(_SC_OPEN_MAX); i >= 0; --i)
        close(i);
#else
    for (int i = getdtablesize(); i >= 0; --i)
        close(i);
#endif

    /*
     * Reset errno because it might be seg to EBADF from the close calls above
     */
    errno = 0;

    /* Redirect stdin and stdout and stderr to /dev/null */
    const char *devnull = "/dev/null";
    int nullfile = open(devnull, O_RDWR);
    if (nullfile < 0) {
        ERROR("Error opening file '%s': (%d) %s", devnull, errno, strerror(errno));
        goto ERR_DEVNULL;
    }


    rc = dup(nullfile);
    if (rc != 1) {
        ERROR("Error duping fd 1 got %d file: (%d) %s", rc, errno, strerror(errno));
        goto ERR_DUP1;
    }
    rc = dup(nullfile);
    if (rc != 2) {
        ERROR("Error duping fd 2 got %d file: (%d) %s", rc, errno, strerror(errno));
        goto ERR_DUP2;
    }

    /* Forwarder will capture signals */
    return 0;

ERR_DUP2:
ERR_DUP1:
ERR_DEVNULL:
ERR_FORK:
    return -1;
}
#endif

#if 0
static Logger *_createLogfile(const char *logfile) {
#ifndef _WIN32
    int logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT, S_IWUSR | S_IRUSR);
#else
    int logfd =
        _open(logfile, _O_WRONLY | _O_APPEND | _O_CREAT, _S_IWRITE | _S_IREAD);
#endif
    if (logfd < 0) {
        fprintf(stderr, "Error opening %s for writing: (%d) %s\n", logfile, errno,
                strerror(errno));
        exit(EXIT_FAILURE);
    }

#ifndef _WIN32
    chmod(logfile, S_IRWXU);
#endif

    PARCFileOutputStream *fos = parcFileOutputStream_Create(logfd);
    PARCOutputStream *pos = parcFileOutputStream_AsOutputStream(fos);
    PARCLogReporter *reporter = parcLogReporterFile_Create(pos);

    Logger *logger = logger_Create(reporter, parcClock_Wallclock());

    parcOutputStream_Release(&pos);
    parcLogReporter_Release(&reporter);

    return logger;
}
#endif

int
main(int argc, const char * argv[])
{
    logo();

#ifndef _WIN32
    bool daemon = false;
#else
    WSADATA wsaData = {0};
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    uint16_t port = PORT_NUMBER;
    uint16_t configurationPort = 2001;
    int capacity = -1;
    const char *fn_config = NULL;

    char *logfile = NULL;

    if (argc == 2 && strcasecmp(argv[1], "-h") == 0) {
        usage(argv[0]);
        exit(EXIT_SUCCESS); // XXX redundant
    }

#if 0
    int logLevelArray[LoggerFacility_END];
    for (int i = 0; i < LoggerFacility_END; i++)
        logLevelArray[i] = -1;
#endif

    // XXX use getoptlong ????
    for (int i = 0; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "--config") == 0) {
                fn_config = argv[i + 1];
                i++;
            } else if (strcmp(argv[i], "--port") == 0) {
                port = atoi(argv[i + 1]);
                i++;
#ifndef _WIN32
            } else if (strcmp(argv[i], "--daemon") == 0) {
                daemon = true;
#endif
            } else if (strcmp(argv[i], "--capacity") == 0 ||
                    strcmp(argv[i], "-c") == 0) {
                capacity = atoi(argv[i + 1]);
                i++;
            } else if (strcmp(argv[i], "--log") == 0) {
                // XXX _setLogLevel(logLevelArray, argv[i + 1]);
                i++;
            } else if (strcmp(argv[i], "--log-file") == 0) {
                if (logfile) {
                    // error cannot repeat
                    fprintf(stderr, "Cannot specify --log-file more than once\n");
                    usage(argv[0]);
                    exit(EXIT_FAILURE);
                }

                logfile = strndup(argv[i + 1], strlen(argv[i + 1]));
                i++;
            } else {
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
        }
    }

    // set restrictive umask, in case we create any files
    umask(027);

#ifndef _WIN32
    if (daemon && (logfile == NULL)) {
        fprintf(stderr, "Must specify a logfile when running in daemon mode\n");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* In daemon mode, parent will exit and child will continue */
    if (daemon && daemonize() < 0) {
        ERROR("Could not daemonize process");
        exit(EXIT_FAILURE);
    }
#endif

#if 0 // XXX use hicn own logging
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
#endif

    /*
     * The loop should be created before the forwarder instance as it is needed
     * for timers
     */
    MAIN_LOOP = loop_create();

    forwarder_t * forwarder = forwarder_create();
    if (!forwarder) {
        ERROR("Forwarder initialization failed. Are you running it with sudo privileges?");
        return -1;
    }

    configuration_t * configuration = forwarder_get_configuration(forwarder);
    if (capacity > -1) {
        configuration_cs_set_size(configuration, capacity);
    }

    forwarder_setup_local_listeners(forwarder, port);
    if (fn_config) {
        forwarder_read_config(forwarder, fn_config);
    }

    INFO("%s running port %d configuration-port %d", argv[0], port,
            configurationPort);

    /* Main loop */
    if (loop_dispatch(MAIN_LOOP) < 0) {
        ERROR("Failed to run main loop");
        return EXIT_FAILURE;
    }

    INFO("%s exiting port %d", argv[0], port);

    if (loop_undispatch(MAIN_LOOP) < 0) {
        ERROR("Failed to terminate main loop");
        return EXIT_FAILURE;
    }

    forwarder_free(forwarder);

    loop_free(MAIN_LOOP);
    MAIN_LOOP = NULL;

#ifdef _WIN32
    WSACleanup(); // XXX why is this needed here ?
#endif

    return 0;
}
