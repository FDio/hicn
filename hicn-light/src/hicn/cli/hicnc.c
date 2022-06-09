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
#include "../config/parse.h"
#include <hicn/util/log.h>
#include <hicn/util/sstrncpy.h>

#define PORT 9695

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
    s = hc_sock_create_forwarder_url(HICNLIGHT_NG, url);
  } else {
    s = hc_sock_create_forwarder(HICNLIGHT_NG);
  }
  if (!s) {
    fprintf(stderr, "Could not create socket.\n");
    goto ERR_SOCK;
  }

  if (hc_sock_connect(s) < 0) {
    fprintf(stderr, "Could not establish connection to forwarder.\n");
    goto ERR_CONNECT;
  }

  if (!IS_VALID_OBJECT_TYPE(command.object.type) ||
      !IS_VALID_ACTION(command.action)) {
    fprintf(stderr, "Unsupported command");
    goto ERR_PARAM;
  }

  int rc = UNSUPPORTED_CMD_ERROR;
  hc_data_t *data = NULL;
  char buf_listener[MAXSZ_HC_LISTENER];
  char buf_connection[MAXSZ_HC_CONNECTION];
  char buf_route[MAXSZ_HC_ROUTE];
  char buf[MAX_LEN];
  switch (command.object.type) {
    case OBJECT_ROUTE:
      switch (command.action) {
        case ACTION_CREATE:
          rc = hc_route_create(s, &command.object.route);
          break;

        case ACTION_DELETE:
          rc = hc_route_delete(s, &command.object.route);
          break;

        case ACTION_LIST:
          rc = hc_route_list(s, &data);
          if (rc < 0) break;

          INFO("Routes:");
          foreach_route(r, data) {
            if (hc_route_snprintf(buf_route, MAXSZ_HC_ROUTE, r) >=
                MAXSZ_HC_ROUTE)
              ERROR("Display error");
            INFO("%s", buf_route);
          }
          break;

        default:
          break;
      }
      break;

    case OBJECT_LISTENER:
      switch (command.action) {
        case ACTION_CREATE:
          rc = hc_listener_create(s, &command.object.listener);
          break;

        case ACTION_DELETE:
          rc = hc_listener_delete(s, &command.object.listener);
          break;

        case ACTION_LIST:
          rc = hc_listener_list(s, &data);
          if (rc < 0) break;

          INFO("Listeners:");
          foreach_listener(l, data) {
            if (hc_listener_snprintf(buf_listener, MAXSZ_HC_LISTENER + 17, l) >=
                MAXSZ_HC_LISTENER)
              ERROR("Display error");
            INFO("[%d] %s", l->id, buf_listener);
          }
          break;

        default:
          break;
      }
      break;

    case OBJECT_CONNECTION:
      switch (command.action) {
        case ACTION_CREATE:
          rc = hc_connection_create(s, &command.object.connection);
          break;

        case ACTION_DELETE:
          rc = hc_connection_delete(s, &command.object.connection);
          break;

        case ACTION_LIST:
          rc = hc_connection_list(s, &data);
          if (rc < 0) break;

          INFO("Connections:");
          foreach_connection(c, data) {
            if (hc_connection_snprintf(buf_connection, MAXSZ_HC_CONNECTION,
                                       c) >= MAXSZ_HC_CONNECTION)
              ERROR("Display error");
            INFO("[%d] %s", c->id, buf_connection);
          }
          break;

        default:
          break;
      }
      break;

    case OBJECT_CACHE:
      switch (command.action) {
        case ACTION_SERVE:
          rc = hc_cache_set_serve(s, &command.object.cache);
          break;

        case ACTION_STORE:
          rc = hc_cache_set_store(s, &command.object.cache);
          break;

        case ACTION_CLEAR:
          rc = hc_cache_clear(s, &command.object.cache);
          break;

        case ACTION_LIST:
          rc = hc_cache_list(s, &data);
          if (rc < 0) break;

          hc_cache_snprintf(buf, MAX_LEN, (hc_cache_info_t *)data->buffer);
          printf("%s\n", buf);
          break;

        default:
          break;
      }
      break;

    case OBJECT_STRATEGY:
      switch (command.action) {
        case ACTION_SET:
          rc = hc_strategy_set(s, &command.object.strategy);
          break;

        default:
          break;
      }
      break;

    case OBJECT_MAPME:
      switch (command.action) {
        case ACTION_UPDATE:
          rc = hc_mapme_send_update(s, &command.object.mapme);
          break;
        case ACTION_SET:
          if (command.object.mapme.target == MAPME_TARGET_ENABLE) {
            rc = hc_mapme_set(s, &command.object.mapme);
          } else if (command.object.mapme.target == MAPME_TARGET_DISCOVERY) {
            rc = hc_mapme_set_discovery(s, &command.object.mapme);
          } else if (command.object.mapme.target == MAPME_TARGET_TIMESCALE) {
            rc = hc_mapme_set_timescale(s, &command.object.mapme);
          } else if (command.object.mapme.target == MAPME_TARGET_RETX) {
            rc = hc_mapme_set_retx(s, &command.object.mapme);
          }
          break;

        default:
          break;
      }
      break;

    case OBJECT_LOCAL_PREFIX:
      switch (command.action) {
        case ACTION_CREATE:
          rc = hc_strategy_add_local_prefix(s, &command.object.strategy);
          break;

        default:
          break;
      }
      break;

    case OBJECT_SUBSCRIPTION:
      // Disable socket recv timeout
      hc_sock_set_recv_timeout_ms(s, 0);

      rc = hc_subscription_create(s, &command.object.subscription);
      if (rc < 0) break;
      INFO("Subscription sent");

      while (!stop) {
        int rc = hc_sock_callback(s, &data);
        if (rc < 0 && !stop) ERROR("Notification error");

        if (!stop) {
          event_type_t event_type = rc;
          INFO("Notification recevied %s [%d]", event_str(event_type),
               event_type);

          if (event_type == EVENT_INTERFACE_UPDATE) {
            hc_event_interface_update_t *event =
                (hc_event_interface_update_t *)(data->buffer);
            INFO("Interface update event received: %u", event->interface_type);
          }
        }
      }

      INFO("Unsubscribing...");
      rc = hc_subscription_delete(s, &command.object.subscription);
      break;

#ifdef TEST_FACE_CREATION
    case OBJECT_FACE:
      switch (command.action) {
        case ACTION_CREATE: {
          hc_face_t face = {0};
          face.face.type = FACE_TYPE_UDP;
          face.face.family = AF_INET;
          face.face.local_addr = IPV4_LOOPBACK;
          face.face.remote_addr = IPV4_LOOPBACK;
          face.face.local_port = 9696;
          face.face.remote_port = 9696;

          rc = hc_face_create(s, &face);
          break;
        }
        default:
          break;
      }
      break;
#endif

    default:
      break;
  }
  hc_data_free(data);

  if (rc < -1) {
    if (rc == INPUT_ERROR) ERROR("Wrong input parameters");
    if (rc == UNSUPPORTED_CMD_ERROR) ERROR("Unsupported command");
    goto ERR_CMD;
  }
  if (rc < 0) ERROR("Error executing command");

  // Remove the connection created to send the command
  command.object.connection.id = 0;
  rc = strcpy_s(command.object.connection.name,
                sizeof(command.object.connection.name), "SELF");
  if (rc != EOK || hc_connection_delete(s, &command.object.connection) < 0)
    fprintf(stderr, "Error removing local connection to forwarder\n");

  exit(EXIT_SUCCESS);

ERR_CMD:
ERR_CONNECT:
  hc_sock_free(s);
ERR_SOCK:
ERR_PARSE:
ERR_PARAM:
  exit(EXIT_FAILURE);
}
