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

#include <limits.h>  // LONG_MAX, LONG_MIN
#include <signal.h>
#include <hicn/ctrl.h>

#ifndef _WIN32
#include <getopt.h>
#endif

#include "color.h"
#include <hicn/ctrl/parse.h>
#include <hicn/ctrl/hicn-light.h>
#include <hicn/util/log.h>
#include <hicn/util/sstrncpy.h>

#define PORT 9695

/*
 * Duplicated from hicn_light_ng_api.c while is only available as a module in
 * libhicnctrl
 */
const char *command_type_str[] = {
#define _(l, u) [COMMAND_TYPE_##u] = STRINGIZE(u),
    foreach_command_type
#undef _
};

static struct option longFormOptions[] = {{"help", no_argument, 0, 'h'},
                                          {"server", required_argument, 0, 'S'},
                                          {"port", required_argument, 0, 'P'},
                                          {0, 0, 0, 0}};

static void usage(char *prog) {
  printf("%s: portable hICN forwarder\n", prog);
  printf("\n");
  printf("Usage: %s COMMAND [PARAMETERS]\n", prog);
  printf("\n");
  printf("       %s -h        This help screen.\n", prog);
  printf("       %s help      Obtain a list of available commands.\n", prog);
  printf("\n");
}

static bool stop = false;
void signal_handler(int sig) {
  fprintf(stderr, "Received ^C... quitting !\n");
  stop = true;
}

#if 0
int hc_active_interface_snprintf(char *buf, size_t size,
                                 hc_event_active_interface_update_t *event) {
  int rc;
  char *pos = buf;

  rc = ip_prefix_snprintf(pos, size, &event->prefix);
  if ((rc < 0) || (rc >= size)) return rc;
  pos += rc;
  size -= rc;

  for (netdevice_type_t type = NETDEVICE_TYPE_UNDEFINED + 1;
       type < NETDEVICE_TYPE_N; type++) {
    if (!netdevice_flags_has(event->interface_type, type)) continue;
    rc = snprintf(pos, size, " %s", netdevice_type_str(type));
    if ((rc < 0) || (rc >= size)) return pos - buf + rc;

    pos += rc;
    size -= rc;
  }
  return pos - buf;
}

// XXX hc_object_snprintf
void hc_subscription_display(command_type_t command_type,
                             const uint8_t *buffer) {
  char buf[65535];

  switch (command_type) {
    case COMMAND_TYPE_CONNECTION_ADD:
    case COMMAND_TYPE_CONNECTION_REMOVE:
    case COMMAND_TYPE_CONNECTION_UPDATE:
      hc_connection_snprintf(buf, sizeof(buf), (hc_connection_t *)buffer);
      break;
    case COMMAND_TYPE_ACTIVE_INTERFACE_UPDATE:
      hc_active_interface_snprintf(
          buf, sizeof(buf), (hc_event_active_interface_update_t *)buffer);
      break;
    case COMMAND_TYPE_ROUTE_LIST:
      hc_route_snprintf(buf, sizeof(buf), (hc_route_t *)buffer);
      break;
    default:
      INFO("Unknown event received");
      return;
  }
  INFO("%s %s", command_type_str(command_type), buf);
}
#endif

int main(int argc, char *const *argv) {
  log_conf.log_level = LOG_INFO;

  // Handle termination signal
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  sigaction(SIGINT, &sa, NULL);

  /* Parse commandline */
  char *server_ip = NULL;
  uint16_t server_port = 0;

  for (;;) {
    // getopt_long stores the option index here.
    int optind = 0;

    int c = getopt_long(argc, argv, "hS:P:", longFormOptions, &optind);
    if (c == -1) break;

    switch (c) {
      case 'S':
        server_ip = optarg;
        break;

      case 'P': {
        char *endptr;
        long val = strtol(optarg, &endptr, 10);

        errno = 0; /* To distinguish success/failure after call */

        if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
            (errno != 0 && val == 0)) {
          perror("strtol");
          exit(EXIT_FAILURE);
        }

        if (endptr == optarg) {
          fprintf(stderr, "No digits were found.\n");
          exit(EXIT_FAILURE);
        }

        if (*endptr != '\0') {
          fprintf(stderr, "Spurious characters after number: %s.\n", endptr);
          exit(EXIT_FAILURE);
        }

        if ((val < 1) || (val > 65535)) {
          fprintf(stderr, "Invalid port number: %ld.\n", val);
          exit(EXIT_FAILURE);
        }

        server_port = val;
        break;
      }

      case 'h':
        usage(argv[0]);
        exit(EXIT_SUCCESS);

      default:
        fprintf(stderr, "Invalid argument.\n");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
  }

  /* Parse */
  char *param = argv[optind];
  for (; optind < argc - 1; optind++) {
    char *arg = argv[optind];
    arg[strlen(arg)] = ' ';
  }

  if (!param) {
    usage(argv[0]);
    goto ERR_PARAM;
  }

  if (strncmp(param, "help", 4) == 0) {
    if (help(param) < 0) {
      usage(argv[0]);
      exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
  }

  hc_command_t command = {};
  if (parse(param, &command) < 0) {
    fprintf(stderr, "Error parsing command : '%s'\n", param);
    goto ERR_PARSE;
  }

  hc_sock_t *s;
  if (server_ip) {
    if (server_port == 0) server_port = PORT;
#define BUFSIZE 255
    char url[BUFSIZE];
    snprintf(url, BUFSIZE, "tcp://%s:%d/", server_ip, server_port);
    s = hc_sock_create(FORWARDER_TYPE_HICNLIGHT, url);
  } else {
    s = hc_sock_create(FORWARDER_TYPE_HICNLIGHT, NULL);
  }
  if (!s) {
    fprintf(stderr, "Could not create socket.\n");
    goto ERR_SOCKET;
  }

  if (hc_sock_connect(s) < 0) {
    fprintf(stderr, "Could not establish connection to forwarder.\n");
    goto ERR_CONNECT;
  }

  if (!IS_VALID_OBJECT_TYPE(command.object_type) ||
      !IS_VALID_ACTION(command.action)) {
    fprintf(stderr, "Unsupported command");
    goto ERR_PARAM;
  }

  int rc = UNSUPPORTED_CMD_ERROR;
  hc_data_t *data = NULL;

  rc = hc_execute(s, command.action, command.object_type, &command.object,
                  &data);

  if (rc < 0) {
    switch (rc) {
      case INPUT_ERROR:
        ERROR("Wrong input parameters");
        break;
      case UNSUPPORTED_CMD_ERROR:
        ERROR("Unsupported command");
        break;
      default:
        ERROR("Error executing command");
        break;
    }
    goto ERR_COMMAND;
  }

  if (!data) goto ERR_QUERY;
  if (!hc_data_get_result(data)) goto ERR_DATA;

  if (command.action == ACTION_LIST) {
    char buf[MAXSZ_HC_OBJECT];
    hc_data_foreach(data, obj, {
      rc = hc_object_snprintf(buf, MAXSZ_HC_OBJECT, command.object_type, obj);
      if (rc < 0)
        WARN("Display error");
      else if (rc >= MAXSZ_HC_OBJECT)
        WARN("Output truncated");
      else
        printf("%s\n", buf);
    });
  }

  hc_data_free(data);
  hc_sock_free(s);
  return EXIT_SUCCESS;

ERR_DATA:
  hc_data_free(data);
ERR_QUERY:
ERR_COMMAND:
ERR_CONNECT:
  hc_sock_free(s);
ERR_SOCKET:
ERR_PARSE:
ERR_PARAM:
  ERROR("Error");
  return EXIT_FAILURE;
}
