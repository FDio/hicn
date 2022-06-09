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

#include <hicn/util/log.h>
#include <hicn/base/loop.h>

#include "logo.h"
#include "../core/forwarder.h"
#include "../config/configuration.h"  // XXX needed ?
#include "../config/configuration_file.h"

static void usage(const char *prog) {
  printf(
      "Usage: %s [--port port]"
#ifndef _WIN32
      " [--daemon]"
#endif
      " [--capacity objectStoreSize] [--log level]"
      "[--log-file filename] [--config file]\n",
      prog);
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
  printf("%-30s = tcp port for in-bound connections\n", "--port <tcp_port>");
#ifndef _WIN32
  printf("%-30s = start as daemon process\n", "--daemon");
#endif
  printf(
      "%-30s = maximum number of content objects to cache. To disable the "
      "cache objectStoreSize must be 0.\n",
      "--capacity <objectStoreSize>");
  printf("%-30s   Default vaule for objectStoreSize is  100000\n", "");
  printf(
      "%-30s = sets the log level. Available levels: trace, debug, info, warn, "
      "error, fatal\n",
      "--log <level>");
  printf("%-30s = file to write log messages to  (required in daemon mode)\n",
         "--log-file <output_logfile>");
  printf("%-30s = configuration filename\n", "--config <config_path>");
  printf("\n");
}

#ifndef _WIN32
static int daemonize(int logfile_fd) {
  /* Check whether we already are a daemon */
  if (getppid() == 1) return 0;

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

  /* close all descriptors (apart from the logfile) */
#ifdef __ANDROID__
  for (int i = sysconf(_SC_OPEN_MAX); i >= 0; --i) close(i);
#else
  for (int i = getdtablesize(); i >= 0; --i) {
    if (i != logfile_fd) close(i);
  }
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

  /* Redirect stdout and stderr to the logfile */
  rc = dup2(logfile_fd, STDOUT_FILENO);
  if (rc != STDOUT_FILENO) {
    ERROR("Error duping fd 1 got %d file: (%d) %s", rc, errno, strerror(errno));
    goto ERR_DUP1;
  }
  rc = dup2(logfile_fd, STDERR_FILENO);
  if (rc != STDERR_FILENO) {
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

static void signal_cb(int sig) {
  switch (sig) {
    case SIGTERM:
    case SIGINT:
      INFO("caught an interrupt signal, exiting cleanly");
      break;
#ifndef _WIN32
    case SIGUSR1:
      // dump stats
      break;
#endif
    default:
      break;
  }

  if (loop_break(MAIN_LOOP) < 0) {
    ERROR("Failed to terminate main loop");
    _exit(1);
  }
}

static void signal_setup() {
#ifndef _WIN32
  signal(SIGUSR1, signal_cb);

  /* ignore child */
  signal(SIGCHLD, SIG_IGN);

  /* ignore tty signals */
  signal(SIGTSTP, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
#endif
  signal(SIGINT, signal_cb);
  signal(SIGTERM, signal_cb);
}

configuration_t *parse_commandline(int argc, const char *argv[]) {
  if (argc == 2 && strcasecmp(argv[1], "-h") == 0) {
    usage(argv[0]);
    exit(EXIT_SUCCESS);  // XXX redundant
  }

  configuration_t *configuration = configuration_create();

  // XXX use getoptlong ????
  for (int i = 0; i < argc; i++) {
    if (argv[i][0] == '-') {
      if (strcmp(argv[i], "--config") == 0) {
        const char *fn_config = argv[i + 1];
        configuration_set_fn_config(configuration, fn_config);
        i++;
      } else if (strcmp(argv[i], "--port") == 0) {
        uint16_t port = atoi(argv[i + 1]);
        configuration_set_port(configuration, port);
        i++;
#ifndef _WIN32
      } else if (strcmp(argv[i], "--daemon") == 0) {
        configuration_set_daemon(configuration, true);
#endif
      } else if (strcmp(argv[i], "--capacity") == 0 ||
                 strcmp(argv[i], "-c") == 0) {
        int capacity = atoi(argv[i + 1]);
        configuration_set_cs_size(configuration, capacity);
        i++;
      } else if (strcmp(argv[i], "--log") == 0) {
        int loglevel = loglevel_from_str(argv[i + 1]);
        configuration_set_loglevel(configuration, loglevel);
        i++;
      } else if (strcmp(argv[i], "--log-file") == 0) {
        if (configuration_get_logfile(configuration)) {
          fprintf(stderr, "Cannot specify --log-file more than once\n");
          usage(argv[0]);
          exit(EXIT_FAILURE);
        }

        const char *logfile = argv[i + 1];
        configuration_set_logfile(configuration, logfile);
        i++;
      } else {
        usage(argv[0]);
        exit(EXIT_FAILURE);
      }
    }
  }

  return configuration;
}

int main(int argc, const char *argv[]) {
  signal_setup();
  logo();

  configuration_t *configuration = parse_commandline(argc, argv);
  const char *logfile = configuration_get_logfile(configuration);
  bool daemon = configuration_get_daemon(configuration);

  // set restrictive umask, in case we create any files
  umask(027);

#ifndef _WIN32
  if (daemon && (logfile == NULL)) {
    fprintf(stderr, "Must specify a logfile when running in daemon mode\n");
    usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  /* In daemon mode, parent will exit and child will continue */
  if (daemon && daemonize(configuration_get_logfile_fd(configuration)) < 0) {
    ERROR("Could not daemonize process");
    exit(EXIT_FAILURE);
  }
#endif

  /*
   * The loop should be created before the forwarder instance as it is needed
   * for timers
   */
  MAIN_LOOP = loop_create();

  forwarder_t *forwarder = forwarder_create(configuration);
  if (!forwarder) {
    ERROR(
        "Forwarder initialization failed. Are you running it with sudo "
        "privileges?");
    return -1;
  }

  forwarder_setup_local_listeners(forwarder,
                                  configuration_get_port(configuration));

  /* If specified, process the configuration file */
  const char *fn_config = configuration_get_fn_config(configuration);
  if (fn_config) configuration_file_process(forwarder, fn_config);
  INFO("%s running port %d configuration-port %d", argv[0],
       configuration_get_port(configuration),
       configuration_get_configuration_port(configuration));

  /* Main loop */
  if (loop_dispatch(MAIN_LOOP) < 0) {
    ERROR("Failed to run main loop");
    return EXIT_FAILURE;
  }

  INFO("loop stopped");
  forwarder_free(forwarder);
  loop_free(MAIN_LOOP);
  MAIN_LOOP = NULL;

#ifdef _WIN32
  WSACleanup();  // XXX why is this needed here ?
#endif

  configuration_flush_log();
  return 0;
}
