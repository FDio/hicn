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
#include <ctype.h> // isalpha isalnum
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // getopt

#include <hicn/ctrl.h>
#include <hicn/util/ip_address.h>
#include <hicn/util/token.h>


#define die(LABEL, MESSAGE) do {    \
        printf(MESSAGE "\n");       \
        rc = -1;                    \
        goto ERR_ ## LABEL;         \
} while(0)

#define foreach_object  \
    _(UNDEFINED)        \
    _(FACE)             \
    _(ROUTE)            \
    _(STRATEGY)         \
    _(LISTENER)         \
    _(CONNECTION)       \
    _(N)

typedef enum {
#define _(x) OBJECT_ ## x,
foreach_object
#undef _
} hc_object_t;

void usage(const char * prog)
{
    fprintf(stderr, "Usage: %s [ [-d] [-f|-l|-c|-r] PARAMETERS | [-F|-L|-C|-R] ]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "High-level commands\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "%s -f <NAME> <TYPE> <LOCAL_ADDRESS> <LOCAL_PORT> <REMOTE_ADDRESS> <REMOTE_PORT>\n", prog);
    fprintf(stderr, "    Create a face on specified address and port.\n");
    fprintf(stderr, "%s -fc ...\n", prog);
    fprintf(stderr, "    Delete a face...\n");
    fprintf(stderr, "%s -F\n", prog);
    fprintf(stderr, "    List all faces.\n");
    fprintf(stderr, "%s -r ...>\n", prog);
    fprintf(stderr, "    Create a route...\n");
    fprintf(stderr, "%s -dr ...\n", prog);
    fprintf(stderr, "    Delete a route...\n");
    fprintf(stderr, "%s -R\n", prog);
    fprintf(stderr, "    List all routes.\n");
    fprintf(stderr, "%s -S\n", prog);
    fprintf(stderr, "    List all availble forwarding strategies.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Low level commands (hicn-light specific)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "%s -l <NAME> <TYPE> <ADDRESS> <PORT> <INTERFACE_NAME>\n", prog);
    fprintf(stderr, "    Create a listener on specified address and port.\n");
    fprintf(stderr, "%s -dl ...\n", prog);
    fprintf(stderr, "    Delete a listener...\n");
    fprintf(stderr, "%s -L\n", prog);
    fprintf(stderr, "    List all listeners.\n");
    fprintf(stderr, "%s -c <NAME> <TYPE> <LOCAL_ADDRESS> <LOCAL_PORT> <REMOTE_ADDRESS> <REMOTE_PORT>\n", prog);
    fprintf(stderr, "    Create a connection on specified address and port.\n");
    fprintf(stderr, "%s -dc ...\n", prog);
    fprintf(stderr, "    Delete a connection...\n");
    fprintf(stderr, "%s -C\n", prog);
    fprintf(stderr, "    List all connections.\n");
}

typedef struct {
    hc_action_t action;
    hc_object_t object;
    union {
        hc_face_t face;
        hc_route_t route;
        hc_connection_t connection;
        hc_listener_t listener;
    };
} hc_command_t;

/**
 * Return true if string is purely an integer
 */
static inline
bool
is_number(const char *string) {
  size_t len = strlen(string);
  for (size_t i = 0; i < len; i++)
    if (!isdigit(string[i]))
      return false;
  return true;
}

/**
 * A symbolic name must be at least 1 character and must begin with an alpha.
 * The remainder must be an alphanum.
 */
static inline
bool
is_symbolic_name(const char *name)
{
    size_t len = strlen(name);
    if (len <= 0)
        return false;
    if (!isalpha(name[0]))
        return false;
    for (size_t i = 1; i < len; i++) {
        if (!isalnum(name[i]))
            return false;
    }
    return true;
}

face_type_t
face_type_from_str(const char * str)
{
#define _(x)                                    \
    if (strcasecmp(str, STRINGIZE(x)) == 0)     \
        return FACE_TYPE_ ## x;                 \
    else
foreach_face_type
#undef _
        return FACE_TYPE_UNDEFINED;
}


int
parse_options(int argc, char *argv[], hc_command_t * command)
{
    command->object = OBJECT_UNDEFINED;
    command->action = ACTION_CREATE;
    int nargs = -1; /* unset */
    int opt;
    int family;

    while ((opt = getopt(argc, argv, "dflcrFLCRSh")) != -1) {
        switch (opt) {
            case 'd':
                command->action = ACTION_DELETE;
                break;
            case 'f':
                command->object = OBJECT_FACE;
                break;
            case 'l':
                command->object = OBJECT_LISTENER;
                break;
            case 'c':
                command->object = OBJECT_CONNECTION;
                break;
            case 'r':
                command->object = OBJECT_ROUTE;
                nargs = 0; // XXX
                break;
            case 'F':
                command->action = ACTION_LIST;
                command->object = OBJECT_FACE;
                nargs = 0;
                break;
            case 'L':
                command->action = ACTION_LIST;
                command->object = OBJECT_LISTENER;
                nargs = 0;
                break;
            case 'C':
                command->action = ACTION_LIST;
                command->object = OBJECT_CONNECTION;
                nargs = 0;
                break;
            case 'R':
                command->action = ACTION_LIST;
                command->object = OBJECT_ROUTE;
                nargs = 0;
                break;
            case 'S':
                command->action = ACTION_LIST;
                command->object = OBJECT_STRATEGY;
                nargs = 0;
                break;
            default: /* "h" */
                usage(argv[0]);
                exit(EXIT_SUCCESS);
        }
    }

    if (command->object == OBJECT_UNDEFINED) {
        fprintf(stderr, "Missing object specification: connection | listener | route\n");
        return -1;
    }

    if (nargs == 0)
        return 0;

    /* Parse and validate parameters for add/delete */
    switch(command->object) {
        case OBJECT_FACE:
            switch(command->action) {
                case ACTION_CREATE:
                    if ((argc - optind != 6) && (argc - optind != 7)) {
                        fprintf(stderr, "Usage:\n");
                        fprintf(stderr, "%s -f TYPE LOCAL_ADDRESS LOCAL_PORT REMOTE_ADDRESS REMOTE_PORT [INTERFACE_NAME]\n", argv[0]);
                        goto ERR_PARAM;
                    }
                    /* NAME will be autogenerated (and currently not used) */
                    //snprintf(command->face.name, SYMBOLIC_NAME_LEN, "%s", argv[optind++]);
                    command->face.face.type = face_type_from_str(argv[optind++]);
                    if (command->face.face.type == FACE_TYPE_UNDEFINED)
                        goto ERR_PARAM;
                    command->face.face.family = ip_address_get_family(argv[optind]);
                    if (!IS_VALID_FAMILY(command->face.face.family))
                        goto ERR_PARAM;
                    if (ip_address_pton(argv[optind++], &command->face.face.local_addr) < 0)
                        goto ERR_PARAM;
                    command->face.face.local_port = atoi(argv[optind++]);
                    family = ip_address_get_family(argv[optind]);
                    if (!IS_VALID_FAMILY(family) || (command->face.face.family != family))
                        goto ERR_PARAM;
                    if (ip_address_pton(argv[optind++], &command->face.face.remote_addr) < 0)
                        goto ERR_PARAM;
                    command->face.face.remote_port = atoi(argv[optind++]);
                    if (argc != optind) {
                        netdevice_set_name(&command->face.face.netdevice, argv[optind++]);
                    }

                    break;
                case ACTION_DELETE:
                    if ((argc - optind != 1) && (argc - optind != 5) && (argc - optind != 6)) {
                        fprintf(stderr, "Usage:\n");
                        fprintf(stderr, "%s -ld ID\n", argv[0]);
                        //fprintf(stderr, "%s -ld NAME\n", argv[0]);
                        fprintf(stderr, "%s -ld TYPE LOCAL_ADDRESS LOCAL_PORT REMOTE_ADDRESS REMOTE_PORT [INTERFACE_NAME]\n", argv[0]);
                        goto ERR_PARAM;
                    }

                    if (argc - optind == 1) {
                        /* Id or name */
                        if (is_number(argv[optind])) {
                            command->face.id = atoi(argv[optind++]);
                            snprintf(command->face.name, SYMBOLIC_NAME_LEN, "%s", argv[optind++]);
                        //} else if (is_symbolic_name(argv[optind])) {
                        //    snprintf(command->face.name, SYMBOLIC_NAME_LEN, "%s", argv[optind++]);
                        } else {
                            fprintf(stderr, "Invalid argument\n");
                            goto ERR_PARAM;
                        }
                    } else {
                        command->face.face.type = face_type_from_str(argv[optind++]);
                        if (command->face.face.type == FACE_TYPE_UNDEFINED)
                            goto ERR_PARAM;
                        command->face.face.family = ip_address_get_family(argv[optind]);
                        if (!IS_VALID_FAMILY(command->face.face.family))
                            goto ERR_PARAM;
                        if (ip_address_pton(argv[optind++], &command->face.face.local_addr) < 0)
                            goto ERR_PARAM;
                        command->face.face.local_port = atoi(argv[optind++]);
                        family = ip_address_get_family(argv[optind]);
                        if (!IS_VALID_FAMILY(family) || (command->face.face.family != family))
                            goto ERR_PARAM;
                        if (ip_address_pton(argv[optind++], &command->face.face.remote_addr) < 0)
                            goto ERR_PARAM;
                        command->face.face.remote_port = atoi(argv[optind++]);
                        if (argc != optind) {
                            netdevice_set_name(&command->face.face.netdevice, argv[optind++]);
                        }
                    }
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

        case OBJECT_LISTENER:
            switch(command->action) {
                case ACTION_CREATE:
                    if ((argc - optind != 4) && (argc - optind != 5)) {
                        fprintf(stderr, "Usage:\n");
                        fprintf(stderr, "%s -l NAME TYPE LOCAL_ADDRESS LOCAL_PORT [INTERFACE_NAME]\n", argv[0]);
                        goto ERR_PARAM;
                    }
                    snprintf(command->listener.name, SYMBOLIC_NAME_LEN, "%s", argv[optind++]);
                    command->listener.type = connection_type_from_str(argv[optind++]);
                    if (command->listener.type == CONNECTION_TYPE_UNDEFINED)
                        goto ERR_PARAM;
                    command->listener.family = ip_address_get_family(argv[optind]);
                    if (!IS_VALID_FAMILY(command->listener.family))
                        goto ERR_PARAM;
                    if (ip_address_pton(argv[optind++], &command->listener.local_addr) < 0)
                        goto ERR_PARAM;
                    command->listener.local_port = atoi(argv[optind++]);
                    if (argc != optind) {
                        snprintf(command->listener.interface_name, INTERFACE_LEN, "%s", argv[optind++]);
                    }
                    break;

                case ACTION_DELETE:
                    if ((argc - optind != 1) && (argc - optind != 3) && (argc - optind != 4)) {
                        fprintf(stderr, "Usage:\n");
                        fprintf(stderr, "%s -ld ID\n", argv[0]);
                        fprintf(stderr, "%s -ld NAME\n", argv[0]);
                        fprintf(stderr, "%s -ld TYPE LOCAL_ADDRESS LOCAL_PORT [INTERFACE_NAME]\n", argv[0]);
                        goto ERR_PARAM;
                    }

                    if (argc - optind == 1) {
                        /* Id or name */
                        if (is_number(argv[optind])) {
                            command->listener.id = atoi(argv[optind++]);
                            snprintf(command->listener.name, SYMBOLIC_NAME_LEN, "%s", argv[optind++]);
                        } else if (is_symbolic_name(argv[optind])) {
                            snprintf(command->listener.name, SYMBOLIC_NAME_LEN, "%s", argv[optind++]);
                        } else {
                            fprintf(stderr, "Invalid argument\n");
                            goto ERR_PARAM;
                        }
                    } else {
                        command->listener.type = connection_type_from_str(argv[optind++]);
                        if (command->listener.type == CONNECTION_TYPE_UNDEFINED)
                            goto ERR_PARAM;
                        command->listener.family = ip_address_get_family(argv[optind]);
                        if (!IS_VALID_FAMILY(command->listener.family))
                            goto ERR_PARAM;
                        if (ip_address_pton(argv[optind++], &command->listener.local_addr) < 0)
                            goto ERR_PARAM;
                        command->listener.local_port = atoi(argv[optind++]);
                        if (argc != optind) {
                            snprintf(command->listener.interface_name, INTERFACE_LEN, "%s", argv[optind++]);
                        }
                    }
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
                    if ((argc - optind != 6) && (argc - optind != 7)) {
                        fprintf(stderr, "Usage:\n");
                        fprintf(stderr, "%s -c NAME TYPE LOCAL_ADDRESS LOCAL_PORT REMOTE_ADDRESS REMOTE_PORT [INTERFACE_NAME]\n", argv[0]);
                        goto ERR_PARAM;
                    }
                    snprintf(command->connection.name, SYMBOLIC_NAME_LEN, "%s", argv[optind++]);
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

                    break;
                case ACTION_DELETE:
                    if ((argc - optind != 1) && (argc - optind != 5) && (argc - optind != 6)) {
                        fprintf(stderr, "Usage:\n");
                        fprintf(stderr, "%s -ld ID\n", argv[0]);
                        fprintf(stderr, "%s -ld NAME\n", argv[0]);
                        fprintf(stderr, "%s -ld TYPE LOCAL_ADDRESS LOCAL_PORT REMOTE_ADDRESS REMOTE_PORT [INTERFACE_NAME]\n", argv[0]);
                        goto ERR_PARAM;
                    }

                    if (argc - optind == 1) {
                        /* Id or name */
                        if (is_number(argv[optind])) {
                            command->connection.id = atoi(argv[optind++]);
                            snprintf(command->connection.name, SYMBOLIC_NAME_LEN, "%s", argv[optind++]);
                        } else if (is_symbolic_name(argv[optind])) {
                            snprintf(command->connection.name, SYMBOLIC_NAME_LEN, "%s", argv[optind++]);
                        } else {
                            fprintf(stderr, "Invalid argument\n");
                            goto ERR_PARAM;
                        }
                    } else {
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
                    }
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
    hc_command_t command = {0};
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
        case OBJECT_FACE:
            switch(command.action) {
                case ACTION_CREATE:
                    if (hc_face_create(s, &command.face) < 0)
                        die(COMMAND, "Error creating face");
                    printf("OK\n");
                    break;

                case ACTION_DELETE:
                    if (hc_face_delete(s, &command.face) < 0)
                        die(COMMAND, "Error creating face");
                    printf("OK\n");
                    break;

                case ACTION_LIST:
                    if (hc_face_list(s, &data) < 0)
                        die(COMMAND, "Error getting connections.");

                    printf("Faces:\n");
                    foreach_face(f, data) {
                        if (hc_face_snprintf(buf_connection, MAXSZ_HC_FACE, f) >= MAXSZ_HC_FACE)
                            die(COMMAND, "Display error");
                        printf("[%s] %s\n", f->name, buf_connection);
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

        case OBJECT_LISTENER:
            switch(command.action) {
                case ACTION_CREATE:
                    if (hc_listener_create(s, &command.listener) < 0)
                        die(COMMAND, "Error creating listener");
                    printf("OK\n");
                    break;
                case ACTION_DELETE:
                    if (hc_listener_delete(s, &command.listener) < 0)
                        die(COMMAND, "Error deleting listener");
                    printf("OK\n");
                    break;
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
                    if (hc_connection_create(s, &command.connection) < 0)
                        die(COMMAND, "Error creating connection");
                    printf("OK\n");
                    break;
                case ACTION_DELETE:
                    if (hc_connection_delete(s, &command.connection) < 0)
                        die(COMMAND, "Error creating connection");
                    printf("OK\n");
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
