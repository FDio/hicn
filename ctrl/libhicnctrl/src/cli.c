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
 * \file cli.c
 * \brief Command line interface
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // getopt

#include <hicn/ctrl.h>

#include "util/ip_address.h"
#include "util/token.h"


#define die(LABEL, MESSAGE) do {    \
        printf(MESSAGE "\n");       \
        rc = -1;                    \
        goto ERR_ ## LABEL;         \
} while(0)

#define foreach_object  \
    _(UNDEFINED)        \
    _(LISTENER)         \
    _(CONNECTION)       \
    _(ROUTE)            \
    _(STRATEGY)         \
    _(N)

typedef enum {
#define _(x) OBJECT_ ## x,
foreach_object
#undef _
} hc_object_t;

void usage(const char * prog)
{
    fprintf(stderr, "Usage: %s [ [-d] [-l|-c|-r] PARAMETERS | [-L|-C|-R] ]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "%s -l <NAME> <TYPE> <ADDRESS> <PORT> <INTERFACE_NAME>\n", prog);
    fprintf(stderr, "    Create a listener on specified address and port.\n");
    fprintf(stderr, "%s -dl ...\n", prog);
    fprintf(stderr, "    Delete a listener...\n");
    fprintf(stderr, "%s -L\n", prog);
    fprintf(stderr, "    List all listeners.\n");
    fprintf(stderr, "%s -c <TYPE> <LOCAL_ADDRESS> <LOCAL_PORT> <REMOTE_ADDRESS> <REMOTE_PORT>\n", prog);
    fprintf(stderr, "    Create a connection on specified address and port.\n");
    fprintf(stderr, "%s -dc ...\n", prog);
    fprintf(stderr, "    Delete a connection...\n");
    fprintf(stderr, "%s -C\n", prog);
    fprintf(stderr, "    List all connections.\n");
    fprintf(stderr, "%s -r ...>\n", prog);
    fprintf(stderr, "    Create a route...\n");
    fprintf(stderr, "%s -dr ...\n", prog);
    fprintf(stderr, "    Delete a route...\n");
    fprintf(stderr, "%s -R\n", prog);
    fprintf(stderr, "    List all routes.\n");
    fprintf(stderr, "%s -S\n", prog);
    fprintf(stderr, "    List all availble forwarding strategies.\n");
}

typedef struct {
    hc_action_t action;
    hc_object_t object;
    union {
        hc_connection_t connection;
        hc_listener_t listener;
        hc_route_t route;
    };
} hc_command_t;

int
parse_options(int argc, char *argv[], hc_command_t * command)
{
    command->object = OBJECT_UNDEFINED;
    command->action = ACTION_CREATE;
    int nargs = 0; /* default for list */
    int opt;
    int family;

    while ((opt = getopt(argc, argv, "dlcrLCRSh")) != -1) {
        switch (opt) {
            case 'd':
                command->action = ACTION_DELETE;
                break;
            case 'l':
                command->object = OBJECT_LISTENER;
                nargs = 5;
                break;
            case 'c':
                command->object = OBJECT_CONNECTION;
                nargs = 6;
                break;
            case 'r':
                command->object = OBJECT_ROUTE;
                nargs = 0; // XXX
                break;
            case 'L':
                command->action = ACTION_LIST;
                command->object = OBJECT_LISTENER;
                break;
            case 'C':
                command->action = ACTION_LIST;
                command->object = OBJECT_CONNECTION;
                break;
            case 'R':
                command->action = ACTION_LIST;
                command->object = OBJECT_ROUTE;
                break;
            case 'S':
                command->action = ACTION_LIST;
                command->object = OBJECT_STRATEGY;
                break;
            default: /* "h" */
                usage(argv[0]);
                exit(EXIT_SUCCESS);
        }
    }

    if (command->action == ACTION_DELETE)
        nargs = 1;

    /* Each option expects a different number of arguments */
    if ((command->object == OBJECT_UNDEFINED) || (optind != argc - nargs)) {
        //printf("Object requires %d arguments [optind=%d != args=%d - nargs=%d\n", nargs, optind, argc, nargs);
        return -1;
    }
    if (nargs == 0)
    return 0;

    /* Parse and validate parameters for add/delete */
    switch(command->object) {
        case OBJECT_LISTENER:
            switch(command->action) {
                case ACTION_CREATE:
                    /* NAME TYPE LOCAL_ADDRESS LOCAL_PORT */
                    snprintf(command->listener.name, NAME_LEN, "%s", argv[optind++]);
                    // conn type
                    command->listener.type = connection_type_from_str(argv[optind++]);
                    if (command->listener.type == CONNECTION_TYPE_UNDEFINED)
                        goto ERR_PARAM;
                    command->listener.family = ip_address_get_family(argv[optind]);
                    if (!IS_VALID_FAMILY(command->listener.family))
                        goto ERR_PARAM;
                    if (ip_address_pton(argv[optind++], &command->listener.local_addr) < 0)
                        goto ERR_PARAM;
                    command->listener.local_port = atoi(argv[optind++]);
#ifdef __linux__
                    snprintf(command->listener.interface_name, INTERFACE_LEN, "%s", argv[optind++]);
#endif
                    break;
                case ACTION_DELETE:
                        goto ERR_COMMAND;
                    break;
                default:
                        goto ERR_COMMAND;
                    break;
            }
            break;
        case OBJECT_CONNECTION:
            switch(command->action) {
                case ACTION_CREATE:
                    /* NAME TYPE LOCAL_ADDRESS LOCAL_PORT REMOTE_ADDRESS REMOTE_PORT */
                    snprintf(command->connection.name, NAME_LEN, "%s", argv[optind++]);
                    command->connection.type = connection_type_from_str(argv[optind++]);
                    if (command->connection.type == CONNECTION_TYPE_UNDEFINED)
                        goto ERR_PARAM;
                    command->connection.family = ip_address_get_family(argv[optind]);
                    if (!IS_VALID_FAMILY(command->connection.family))
                        goto ERR_PARAM;
                    if (ip_address_pton(argv[optind++], &command->connection.local_addr) < 0)
                        goto ERR_PARAM;
                    command->connection.local_port = atoi(argv[optind++]);
                    family = ip_address_get_family(argv[optind]);
                    if (!IS_VALID_FAMILY(family) || (command->connection.family != family))
                        goto ERR_PARAM;
                    if (ip_address_pton(argv[optind++], &command->connection.remote_addr) < 0)
                        goto ERR_PARAM;
                    command->connection.remote_port = atoi(argv[optind++]);

                    {
                    char buf_connection[MAXSZ_HC_CONNECTION];
                    if (hc_connection_snprintf(buf_connection, MAXSZ_HC_CONNECTION, &command->connection) >= MAXSZ_HC_CONNECTION)
	                    printf("PARSED !!\n");
                    else
                        printf("PARSED %s\n", buf_connection);
                    }

                    break;
                case ACTION_DELETE:
                    goto ERR_COMMAND;
                    break;
                default:
                    goto ERR_COMMAND;
                    break;
            }
            break;
        case OBJECT_ROUTE:
            switch(command->action) {
                case ACTION_CREATE:
                    goto ERR_COMMAND;
                    break;
                case ACTION_DELETE:
                    goto ERR_COMMAND;
                    break;
                default:
                    goto ERR_COMMAND;
                    break;
            }
            break;
        case OBJECT_STRATEGY:
            switch(command->action) {
                case ACTION_LIST:
                    break;
                default:
                    goto ERR_COMMAND;
                    break;
            }
            break;
        default:
            goto ERR_COMMAND;
            break;
    }

    return 0;

ERR_PARAM:
ERR_COMMAND:
    return -1;
}

int main(int argc, char *argv[])
{
    hc_data_t * data;
    int rc = 1;
    hc_command_t command;
    char buf_listener[MAXSZ_HC_LISTENER];
    char buf_connection[MAXSZ_HC_CONNECTION];
    char buf_route[MAXSZ_HC_ROUTE];
    char buf_strategy[MAXSZ_HC_STRATEGY];

    if (parse_options(argc, argv, &command) < 0)
        die(OPTIONS, "Bad arguments");

    hc_sock_t * s = hc_sock_create();
    if (!s)
        die(SOCKET, "Error creating socket.");

    if (hc_sock_connect(s) < 0)
        die(CONNECT, "Error connecting to the forwarder.");

    switch(command.object) {
        case OBJECT_LISTENER:
            switch(command.action) {
                case ACTION_CREATE:
                    if (hc_listener_create(s, &command.listener) < 0)
                        die(COMMAND, "Error creating listener");
                    printf("OK\n");
                    break;
                case ACTION_DELETE:
                    die(COMMAND, "Not implemented.");
                    break;
                case ACTION_LIST:
                    if (hc_listener_list(s, &data) < 0)
                        die(COMMAND, "Error getting listeners.");

                    printf("Listeners:\n");
                    foreach_listener(l, data) {
                        if (hc_listener_snprintf(buf_listener, MAXSZ_HC_LISTENER+17, l) >= MAXSZ_HC_LISTENER)
                            die(COMMAND, "Display error");
                        printf("[%d] %s\n", l->id, buf_listener);
                    }

                    hc_data_free(data);
                    break;
                default:
                    die(COMMAND, "Unsupported command for listener");
                    break;
            }
            break;
        case OBJECT_CONNECTION:
            switch(command.action) {
                case ACTION_CREATE:
                    die(COMMAND, "Not implemented.");
                    break;
                case ACTION_DELETE:
                    die(COMMAND, "Not implemented.");
                    break;
                case ACTION_LIST:
                    if (hc_connection_list(s, &data) < 0)
                        die(COMMAND, "Error getting connections.");

                    printf("Connections:\n");
                    foreach_connection(c, data) {
                        if (hc_connection_snprintf(buf_connection, MAXSZ_HC_CONNECTION, c) >= MAXSZ_HC_CONNECTION)
                            die(COMMAND, "Display error");
                        printf("[%s] %s\n", c->name, buf_connection);
                    }

                    hc_data_free(data);
                    break;
                default:
                    die(COMMAND, "Unsupported command for connection");
                    break;
            }
            break;
        case OBJECT_ROUTE:
            switch(command.action) {
                case ACTION_CREATE:
                    die(COMMAND, "Not implemented.");
                    break;
                case ACTION_DELETE:
                    die(COMMAND, "Not implemented.");
                    break;
                case ACTION_LIST:
                    if (hc_route_list(s, &data) < 0)
                        die(COMMAND, "Error getting routes.");

                    printf("Routes:\n");
                    foreach_route(r, data) {
                        if (hc_route_snprintf(buf_route, MAXSZ_HC_ROUTE, r) >= MAXSZ_HC_ROUTE)
                            die(COMMAND, "Display error");
                        printf("%s\n", buf_route);
                    }

                    hc_data_free(data);
                    break;
                default:
                    die(COMMAND, "Unsupported command for route");
                    break;
            }
            break;
        case OBJECT_STRATEGY:
            switch(command.action) {
                case ACTION_LIST:
                    if (hc_strategy_list(s, &data) < 0)
                        die(COMMAND, "Error getting routes.");

                    printf("Forwarding strategies:\n");
                    foreach_strategy(st, data) {
                        if (hc_strategy_snprintf(buf_strategy, MAXSZ_HC_STRATEGY, st) >= MAXSZ_HC_STRATEGY)
                            die(COMMAND, "Display error");
                        printf("%s\n", buf_strategy);
                    }

                    hc_data_free(data);
                    break;
                default:
                    die(COMMAND, "Unsupported command for strategy");
                    break;
            }
            break;
        default:
           die(COMMAND, "Unsupported object");
           break;
    }


    /* ROUTES */

ERR_COMMAND:
ERR_CONNECT:
    hc_sock_free(s);
ERR_SOCKET:
ERR_OPTIONS:
    return (rc < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
