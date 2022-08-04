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
#include <hicn/ctrl.h>

#ifndef _WIN32
#include <getopt.h>
#endif

#include "logo.h"
#include <hicn/ctrl/parse.h>
#include <hicn/util/sstrncpy.h>

#define PORT 9695

static struct option longFormOptions[] = {{"help", no_argument, 0, 'h'},
                                          {"server", required_argument, 0, 'S'},
                                          {"port", required_argument, 0, 'P'},
                                          {0, 0, 0, 0}};

static void usage(char *prog) {
  printf("%s: interactive shell for hicn-light\n", prog);
  printf("\n");
  printf("Usage: %s", prog);
  printf("\n");
  printf("       %s -h        This help screen.\n", prog);
  printf("\n");
}

void prompt(void) {
  fputs("hicn> ", stdout);
  fflush(stdout);
}

int shell(hc_sock_t *s) {
  char *line = NULL;
  size_t len = 0;
  hc_data_t *data = NULL;
  ssize_t nread;

  hc_data_t *connections;

  prompt();
  while ((nread = getline(&line, &len, stdin)) != -1) {
    hc_command_t command = {0};

    char *pos;
    if ((pos = strchr(line, '\n')) != NULL) {
      *pos = '\0';
    } else {
      fprintf(stderr, "Error while reading command.\n");
      goto CONTINUE;
    }

    if (strlen(line) == 0) goto CONTINUE;

    if (strncmp(line, "exit", 4) == 0) break;
    if (strncmp(line, "quit", 4) == 0) break;

    if (parse(line, &command) < 0) {
      fprintf(stderr, "Unknown command '%s'\n", line);
      goto CONTINUE;
    }

    /* XXX connection list */
    if (hc_connection_list(s, &connections) < 0) {
      fprintf(stderr, "Error running command.\n");
      goto CONTINUE;
    }
    // data = command.object.data;

    char buf[MAXSZ_HC_CONNECTION];  // XXX
    foreach_connection(c, data) {
      /* XXX connection print */
      int rc = hc_connection_snprintf(buf, MAXSZ_HC_CONNECTION, c);
      if (rc < 0) {
        strcpy_s(buf, sizeof(buf), "(Error)");
      } else if (rc >= MAXSZ_HC_CONNECTION) {
        buf[MAXSZ_HC_CONNECTION - 1] = '\0';
        buf[MAXSZ_HC_CONNECTION - 2] = '.';
        buf[MAXSZ_HC_CONNECTION - 3] = '.';
        buf[MAXSZ_HC_CONNECTION - 4] = '.';
      }
      printf("%s\n", buf);
    }

    hc_data_free(data);
  CONTINUE:
    prompt();
  }

  return 0;
}

int main(int argc, char *const *argv) {
  logo();
  printf("Type 'help' for a list of available commands\n");
  printf("\n");
  printf("\n");

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

        server_port = (uint16_t)val;
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

  if (optind != argc) {
    fprintf(stderr, "Invalid parameters.\n");
    usage(argv[0]);
    exit(EXIT_FAILURE);
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
    goto ERR_SOCK;
  }

  if (hc_sock_connect(s) < 0) {
    fprintf(stderr, "Could not establish connection to forwarder.\n");
    goto ERR_CONNECT;
  }

  int rc = shell(s);

  exit((rc < 0) ? EXIT_FAILURE : EXIT_SUCCESS);

ERR_CONNECT:
  hc_sock_free(s);
ERR_SOCK:
  exit(EXIT_FAILURE);
}
