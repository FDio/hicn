/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

#include <limits.h> // LONG_MAX, LONG_MIN
#include <hicn/ctrl.h>

#ifndef _WIN32
#include <getopt.h>
#endif

#include "color.h"
#include "../config/parse.h"

#define PORT 9695

static
struct option longFormOptions[] = {
    {"help", no_argument, 0, 'h'},
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

int
main(int argc, char * const * argv)
{
    /* Parse commandline */
    char *server_ip = NULL;
    uint16_t server_port = 0;

    for(;;) {
        // getopt_long stores the option index here.
        int optind = 0;

        int c = getopt_long(argc, argv, "hS:P:", longFormOptions, &optind);
        if (c == -1)
            break;

        switch (c) {
            case 'S':
                server_ip = optarg;
                break;

            case 'P':
            {
                char *endptr;
                long val = strtol(optarg, &endptr, 10);

                errno = 0;    /* To distinguish success/failure after call */

                if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
                        || (errno != 0 && val == 0)) {
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
    char * param = argv[optind];
    for (; optind < argc - 1; optind++) {
        char * arg = argv[optind];
        arg[strlen(arg)] = ' ';
    }

    if (!param) {
        usage(argv[0]);
        goto ERR_PARAM;
    }

    hc_command_t command;
    if (parse(param, &command) < 0) {
        fprintf(stderr, "Error parsing command : '%s'\n", param);
        goto ERR_PARSE;
    }

    hc_sock_t * s;
    if (server_ip) {
        if (server_port == 0)
            server_port = PORT;
#define BUFSIZE 255
        char url[BUFSIZE];
        snprintf(url, BUFSIZE, "tcp://%s:%d/", server_ip, server_port);
        s = hc_sock_create_url(url);
    } else {
        s = hc_sock_create();
    }
    if (!s) {
        fprintf(stderr, "Could not create socket.\n");
        goto ERR_SOCK;
    }

    if (hc_sock_connect(s) < 0) {
        fprintf(stderr, "Could not establish connection to forwarder.\n");
        goto ERR_CONNECT;
    }

    // TODO: handle all commands
    if (command.action == ACTION_CREATE && command.object.type == OBJECT_LISTENER) {
        if (hc_listener_create(s, &command.object.listener) < 0) {
            fprintf(stderr, "Error running command");
            goto ERR_CMD;
        }
    }
    exit(EXIT_SUCCESS);

ERR_CMD:
ERR_CONNECT:
    hc_sock_free(s);
ERR_SOCK:
ERR_PARSE:
ERR_PARAM:
    exit(EXIT_FAILURE);
}
