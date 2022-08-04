/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
 * \file cli.c
 * \brief Command line interface
 */
#include <ctype.h>  // isalpha isalnum
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>  // getopt

#include <hicn/ctrl.h>
#include <hicn/util/ip_address.h>
#include <hicn/util/log.h>
#include <hicn/util/token.h>
#include <hicn/validation.h>

#include <hicn/ctrl/parse.h>

#define die(LABEL, MESSAGE) \
  do {                      \
    printf(MESSAGE "\n");   \
    goto ERR_##LABEL;       \
  } while (0)

void usage_header() { fprintf(stderr, "Usage:\n"); }

void usage_face_create(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr,
          "%s -f TYPE LOCAL_ADDRESS LOCAL_PORT REMOTE_ADDRESS REMOTE_PORT "
          "[INTERFACE_NAME]\n",
          prog);
  if (verbose)
    fprintf(stderr, "    Create a face on specified address and port.\n");
}

void usage_face_delete(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr, "%s -df ID\n", prog);
  // fprintf(stderr, "%s -df NAME\n", prog);
  fprintf(stderr,
          "%s -df TYPE LOCAL_ADDRESS LOCAL_PORT REMOTE_ADDRESS REMOTE_PORT "
          "[INTERFACE_NAME]\n",
          prog);
  if (verbose) fprintf(stderr, "    Delete a face...\n");
}

void usage_face_list(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr, "%s -F\n", prog);
  if (verbose) fprintf(stderr, "    List all faces.\n");
}

void usage_face(const char *prog, bool header, bool verbose) {
  usage_face_create(prog, header, verbose);
  usage_face_delete(prog, header, verbose);
  usage_face_list(prog, header, verbose);
}

void usage_route_create(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr, "%s -r FACE_ID PREFIX [COST]\n", prog);
  // fprintf(stderr, "%s -r [FACE_ID|NAME] PREFIX [COST]\n", prog);
  if (verbose) fprintf(stderr, "    Create a route...\n");
}

void usage_route_delete(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr, "%s -dr FACE_ID PREFIX\n", prog);
  // fprintf(stderr, "%s -dr [FACE_ID|NAME] PREFIX\n", prog);
  if (verbose) fprintf(stderr, "    Delete a route...\n");
}

void usage_route_list(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr, "%s -R\n", prog);
  if (verbose) fprintf(stderr, "    List all routes.\n");
}

void usage_route(const char *prog, bool header, bool verbose) {
  usage_route_create(prog, header, verbose);
  usage_route_delete(prog, header, verbose);
  usage_route_list(prog, header, verbose);
}

void usage_forwarding_strategy_create(const char *prog, bool header,
                                      bool verbose) {
  if (header) usage_header();
}
void usage_forwarding_strategy_delete(const char *prog, bool header,
                                      bool verbose) {
  if (header) usage_header();
}

void usage_forwarding_strategy_list(const char *prog, bool header,
                                    bool verbose) {
  if (header) usage_header();
  fprintf(stderr, "%s -S\n", prog);
  if (verbose)
    fprintf(stderr, "    List all availble forwarding strategies.\n");
}

void usage_forwarding_strategy(const char *prog, bool header, bool verbose) {
  usage_forwarding_strategy_create(prog, header, verbose);
  usage_forwarding_strategy_delete(prog, header, verbose);
  usage_forwarding_strategy_list(prog, header, verbose);
}

void usage_listener_create(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr, "%s -l NAME TYPE LOCAL_ADDRESS LOCAL_PORT [INTERFACE_NAME]\n",
          prog);
  if (verbose)
    fprintf(stderr, "    Create a listener on specified address and port.\n");
}

void usage_listener_delete(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr, "%s -dl ID\n", prog);
  fprintf(stderr, "%s -dl NAME\n", prog);
  fprintf(stderr, "%s -dl TYPE LOCAL_ADDRESS LOCAL_PORT [INTERFACE_NAME]\n",
          prog);
  if (verbose) fprintf(stderr, "    Delete a listener...\n");
}

void usage_listener_list(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr, "%s -L\n", prog);
  if (verbose) fprintf(stderr, "    List all listeners.\n");
}

void usage_listener(const char *prog, bool header, bool verbose) {
  usage_listener_create(prog, header, verbose);
  usage_listener_delete(prog, header, verbose);
  usage_listener_list(prog, header, verbose);
}
void usage_connection_create(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr,
          "%s -c NAME TYPE LOCAL_ADDRESS LOCAL_PORT REMOTE_ADDRESS REMOTE_PORT "
          "[INTERFACE_NAME]\n",
          prog);
  if (verbose)
    fprintf(stderr, "    Create a connection on specified address and port.\n");
}

void usage_connection_delete(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr, "%s -dc ID\n", prog);
  fprintf(stderr, "%s -dc NAME\n", prog);
  fprintf(stderr,
          "%s -dc TYPE LOCAL_ADDRESS LOCAL_PORT REMOTE_ADDRESS REMOTE_PORT "
          "[INTERFACE_NAME]\n",
          prog);
  if (verbose) fprintf(stderr, "    Delete a connection...\n");
}

void usage_connection_list(const char *prog, bool header, bool verbose) {
  if (header) usage_header();
  fprintf(stderr, "%s -C\n", prog);
  if (verbose) fprintf(stderr, "    List all connections.\n");
}

void usage_connection(const char *prog, bool header, bool verbose) {
  usage_connection_create(prog, header, verbose);
  usage_connection_delete(prog, header, verbose);
  usage_connection_list(prog, header, verbose);
}

void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [ -z forwarder (hicnlight | vpp) ] [ [-d] [-f|-l|-c|-r] "
          "PARAMETERS | [-F|-L|-C|-R] ]\n",
          prog);
  fprintf(stderr, "\n");
  fprintf(stderr, "High-level commands\n");
  fprintf(stderr, "\n");
  usage_face(prog, false, true);
  usage_route(prog, false, true);
  usage_forwarding_strategy(prog, false, true);
  fprintf(stderr, "\n");
  fprintf(stderr, "Low level commands (hicn-light specific)\n");
  fprintf(stderr, "\n");
  usage_listener(prog, false, true);
  usage_connection(prog, false, true);
}

/*
 * We only allow settings commands and object types once, with the default
 * action being set to CREATE
 */
#define set_command(ACTION, OBJECT_TYPE)                             \
  do {                                                               \
    if ((ACTION) != ACTION_UNDEFINED) {                              \
      if (command->action != ACTION_CREATE) goto USAGE;              \
      command->action = (ACTION);                                    \
    }                                                                \
    if ((OBJECT_TYPE) != OBJECT_TYPE_UNDEFINED) {                    \
      if (command->object_type != OBJECT_TYPE_UNDEFINED) goto USAGE; \
      command->object_type = (OBJECT_TYPE);                          \
    }                                                                \
  } while (0)

int parse_options(int argc, char *argv[], hc_command_t *command,
                  forwarder_type_t *forwarder) {
  command->object_type = OBJECT_TYPE_UNDEFINED;
  command->action = ACTION_CREATE;
  int opt;

  while ((opt = getopt(argc, argv, "cCdfFlLrRsShz:")) != -1) {
    switch (opt) {
      case 'z':
        *forwarder = forwarder_type_from_str(optarg);
        if (*forwarder == FORWARDER_TYPE_UNDEFINED) goto USAGE;
        break;
      case 'd':
        set_command(ACTION_DELETE, OBJECT_TYPE_UNDEFINED);
        break;
      case 's':
        set_command(ACTION_SUBSCRIBE, OBJECT_TYPE_UNDEFINED);
        break;
      case 'f':
        set_command(ACTION_UNDEFINED, OBJECT_TYPE_FACE);
        break;
      case 'c':
        set_command(ACTION_UNDEFINED, OBJECT_TYPE_CONNECTION);
        break;
      case 'l':
        set_command(ACTION_UNDEFINED, OBJECT_TYPE_LISTENER);
        break;
      case 'r':
        set_command(ACTION_UNDEFINED, OBJECT_TYPE_ROUTE);
        break;
      case 'F':
        set_command(ACTION_LIST, OBJECT_TYPE_FACE);
        break;
      case 'L':
        set_command(ACTION_LIST, OBJECT_TYPE_LISTENER);
        break;
      case 'C':
        set_command(ACTION_LIST, OBJECT_TYPE_CONNECTION);
        break;
      case 'R':
        set_command(ACTION_LIST, OBJECT_TYPE_ROUTE);
        break;
      case 'S':
        set_command(ACTION_LIST, OBJECT_TYPE_STRATEGY);
        break;
      default: /* "h" */
        usage(argv[0]);
        exit(EXIT_SUCCESS);
    }
  }

  // XXX The rest could be made a single parse function

  /* A default action is always defined, let's verify we have an object type,
   * unless we are subscribing to notifications. In that case, we can monitor
   * all objects.
   * XXX handle later
   */
  if ((command->object_type == OBJECT_TYPE_UNDEFINED) &&
      (command->action != ACTION_SUBSCRIBE)) {
    ERROR("Missing object specification");
    goto USAGE;
  }

  /* Check the adequation between the number of parameters and the command */
  size_t nparams = argc - optind;
  if (nparams > 0) {
    if (command->action == ACTION_LIST) command->action = ACTION_GET;
  } else {
    if ((command->action != ACTION_LIST) &&
        (command->action != ACTION_SUBSCRIBE))
      goto USAGE;
  }

  /*
   * This checks is important even with 0 parameters as it checks whether the
   * command exists.
   */
  if (command->action != ACTION_SUBSCRIBE) {
    const command_parser_t *parser =
        command_search(command->action, command->object_type, nparams);
    if (!parser) {
      ERROR("Could not find parser for command '%s %s'",
            action_str(command->action), object_type_str(command->object_type));
      return -1;
    }

    if (nparams > 0) {
      if (parse_getopt_args(parser, argc - optind, argv + optind, command) <
          0) {
        ERROR("Error parsing command arguments");
        goto USAGE;
      }
    }
  }

  return 0;

USAGE:
  usage(argv[0]);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  int rc = 1;
  hc_command_t command = {0};
  char buf[MAXSZ_HC_OBJECT];

  forwarder_type_t forwarder = FORWARDER_TYPE_VPP;

  if (parse_options(argc, argv, &command, &forwarder) < 0)
    die(OPTIONS, "Bad arguments");

  hc_sock_t *s = hc_sock_create(forwarder, /* url= */ NULL);
  if (!s) die(SOCKET, "Error creating socket.");

  if (hc_sock_connect(s) < 0)
    die(CONNECT, "Error connecting to the forwarder.");

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

  size_t size = hc_data_get_size(data);
  if (size > 0) {
    printf("Success: got %ld %s\n", size, object_type_str(command.object_type));
  } else {
    printf("Success.\n");
  }

  if (command.action == ACTION_LIST) {
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
ERR_OPTIONS:
  printf("Error.\n");
  return EXIT_FAILURE;
}
