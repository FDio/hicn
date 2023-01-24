/*
 * Copyright (c) 2021-2023 Cisco and/or its affiliates.
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
 * \file command_listener.h
 * \brief Implementation of listener command.
 */
#include <math.h>
#include <hicn/ctrl/command.h>

/* Parameters */

#define protocol_hicn                                                      \
  {                                                                        \
    .name = "protocol", .help = "Protocol [hicn].",                        \
    .type = TYPE_ENUM(face_type), .offset = offsetof(hc_listener_t, type), \
  }

#define protocol_tcp_udp                                                   \
  {                                                                        \
    .name = "protocol", .help = "Protocol [tcp | udp]",                    \
    .type = TYPE_ENUM(face_type), .offset = offsetof(hc_listener_t, type), \
  }

#define symbolic                                                          \
  {                                                                       \
    .name = "symbolic",                                                   \
    .help =                                                               \
        "User defined name for listener, must start with alpha and be "   \
        "alphanum",                                                       \
    .type = TYPE_SYMBOLIC_OR_ID, .offset = offsetof(hc_listener_t, name), \
  }

#define local_address                                                       \
  {                                                                         \
    .name = "local_addr",                                                   \
    .help =                                                                 \
        "IPv4 or IPv6 address (or prefix protocol = hicn) assigend to the " \
        "local interface",                                                  \
    .type = TYPE_IP_ADDRESS, .offset = offsetof(hc_listener_t, local_addr), \
    .offset2 = offsetof(hc_listener_t, family),                             \
  }

#define local_port                                 \
  {                                                \
    .name = "local_port", .help = "Local port.",   \
    .type = TYPE_UINT16(1, UINT16_MAX),            \
    .offset = offsetof(hc_listener_t, local_port), \
  }

#define interface                                              \
  {                                                            \
    .name = "interface", .help = "Interface on which to bind", \
    .type = TYPE_INTERFACE_NAME,                               \
    .offset = offsetof(hc_listener_t, interface_name),         \
  }

#define symbolic_or_id                                                    \
  {                                                                       \
    .name = "symbolic", .help = "The listener symbolic name or id",       \
    .type = TYPE_SYMBOLIC_OR_ID, .offset = offsetof(hc_listener_t, name), \
  }

/* Commands */

/* The parse sets the wrong face_type_t for listener, we fix that here */
int on_listener_create(hc_listener_t* listener) {
  switch (listener->type) {
    case FACE_TYPE_UDP:
      listener->type = FACE_TYPE_UDP_LISTENER;
      break;
    case FACE_TYPE_TCP:
      listener->type = FACE_TYPE_TCP_LISTENER;
      break;
    case FACE_TYPE_HICN:
      listener->type = FACE_TYPE_HICN_LISTENER;
      break;
    case FACE_TYPE_UDP_LISTENER:
    case FACE_TYPE_TCP_LISTENER:
    case FACE_TYPE_HICN_LISTENER:
      break;
    case FACE_TYPE_UNDEFINED:
    case FACE_TYPE_N:
      return -1;
  }
  return 0;
}

#if 0
static const command_parser_t command_listener_create4 = {
    .action = ACTION_CREATE,
    .object = OBJECT_TYPE_LISTENER,
    .nparams = 4,
    .parameters = {protocol_hicn, symbolic, local_address, interface},
    .post_hook = (parser_hook_t)on_listener_create,
};
COMMAND_REGISTER(command_listener_create4);
#endif

static const command_parser_t command_listener_create4 = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_LISTENER,
    .nparams = 4,
    .parameters = {protocol_tcp_udp, symbolic, local_address, local_port},
    .post_hook = (parser_hook_t)on_listener_create,
};
COMMAND_REGISTER(command_listener_create4);

static const command_parser_t command_listener_create5 = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_LISTENER,
    .nparams = 5,
    .parameters = {protocol_tcp_udp, symbolic, local_address, local_port,
                   interface},
    .post_hook = (parser_hook_t)on_listener_create,
};
COMMAND_REGISTER(command_listener_create5);

static const command_parser_t command_listener_list = {
    .action = ACTION_LIST,
    .object_type = OBJECT_TYPE_LISTENER,
    .nparams = 0,
};
COMMAND_REGISTER(command_listener_list);

static const command_parser_t command_listener_remove = {
    .action = ACTION_DELETE,
    .object_type = OBJECT_TYPE_LISTENER,
    .nparams = 1,
    .parameters = {symbolic_or_id},
};
COMMAND_REGISTER(command_listener_remove);
