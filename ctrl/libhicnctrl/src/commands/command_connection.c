#include <math.h>
#include <hicn/ctrl/command.h>

/* Parameters */

#define type_hicn                                                            \
  {                                                                          \
    .name = "type", .help = "connection type (hICN)",                        \
    .type = TYPE_ENUM(face_type), .offset = offsetof(hc_connection_t, type), \
  }

#define type_tcp_udp                                                         \
  {                                                                          \
    .name = "type", .help = "connection type [tcp | udp]",                   \
    .type = TYPE_ENUM(face_type), .offset = offsetof(hc_connection_t, type), \
  }

#define symbolic                                                              \
  {                                                                           \
    .name = "symbolic",                                                       \
    .help = "symbolic name, e.g. 'conn1' (must be unique, start with alpha)", \
    .type = TYPE_SYMBOLIC_OR_ID, .offset = offsetof(hc_connection_t, name),   \
  }

#define local_address                                                         \
  {                                                                           \
    .name = "local_addr", .help = "local IP address on which to bind.",       \
    .type = TYPE_IP_ADDRESS, .offset = offsetof(hc_connection_t, local_addr), \
    .offset2 = offsetof(hc_connection_t, family),                             \
  }

#define local_port                                   \
  {                                                  \
    .name = "local_port", .help = "Local port.",     \
    .type = TYPE_UINT16(1, UINT16_MAX),              \
    .offset = offsetof(hc_connection_t, local_port), \
  }

#define remote_address                                                         \
  {                                                                            \
    .name = "remote_address",                                                  \
    .help = "The IPv4 or IPv6 or hostname of the remote system.",              \
    .type = TYPE_IP_ADDRESS, .offset = offsetof(hc_connection_t, remote_addr), \
    .offset2 = offsetof(hc_connection_t, family),                              \
  }

#define remote_port                                   \
  {                                                   \
    .name = "remote_port", .help = "Remote port.",    \
    .type = TYPE_UINT16(1, UINT16_MAX),               \
    .offset = offsetof(hc_connection_t, remote_port), \
  }

#define interface                                              \
  {                                                            \
    .name = "interface", .help = "Interface on which to bind", \
    .type = TYPE_INTERFACE_NAME,                               \
    .offset = offsetof(hc_connection_t, interface_name),       \
  }

#define symbolic_or_id                                                      \
  {                                                                         \
    .name = "symbolic", .help = "The connection symbolic name or id",       \
    .type = TYPE_SYMBOLIC_OR_ID, .offset = offsetof(hc_connection_t, name), \
  }

/* Commands */

int on_connection_create(hc_connection_t* connection) {
  connection->admin_state = FACE_STATE_UP;
  return 0;
}

#if 0
static command_parser_t command_connection_create4 = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_CONNECTION,
    .nparams = 4,
    .parameters = {type_hicn, symbolic, local_address, remote_address},
    .post_hook = (parser_hook_t)on_connection_create,
};
COMMAND_REGISTER(command_connection_create4);

static const command_parser_t command_connection_create5 = {
    .action = ACTION_CREATE,
    .object = OBJECT_TYPE_CONNECTION,
    .nparams = 5,
    .parameters = {type_hicn, symbolic, local_address, remote_address,
                   interface},
    .post_hook = (parser_hook_t)on_connection_create,
};
COMMAND_REGISTER(command_connection_create5);
#endif

static const command_parser_t command_connection_create4 = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_CONNECTION,
    .nparams = 4,
    .parameters = {type_tcp_udp, symbolic, remote_address, remote_port},
    .post_hook = (parser_hook_t)on_connection_create,
};
COMMAND_REGISTER(command_connection_create4);

static const command_parser_t command_connection_create5 = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_CONNECTION,
    .nparams = 5,
    .parameters = {type_tcp_udp, symbolic, remote_address, remote_port,
                   interface},
    .post_hook = (parser_hook_t)on_connection_create,
};
COMMAND_REGISTER(command_connection_create5);

static const command_parser_t command_connection_create6 = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_CONNECTION,
    .nparams = 6,
    .parameters = {type_tcp_udp, symbolic, remote_address, remote_port,
                   local_address, local_port},
    .post_hook = (parser_hook_t)on_connection_create,
};
COMMAND_REGISTER(command_connection_create6);

static const command_parser_t command_connection_create7 = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_CONNECTION,
    .nparams = 7,
    .parameters = {type_tcp_udp, symbolic, remote_address, remote_port,
                   local_address, local_port, interface},
    .post_hook = (parser_hook_t)on_connection_create,
};
COMMAND_REGISTER(command_connection_create7);

static const command_parser_t command_connection_list = {
    .action = ACTION_LIST,
    .object_type = OBJECT_TYPE_CONNECTION,
    .nparams = 0,
};
COMMAND_REGISTER(command_connection_list);

static const command_parser_t command_connection_remove = {
    .action = ACTION_DELETE,
    .object_type = OBJECT_TYPE_CONNECTION,
    .nparams = 1,
    .parameters = {symbolic_or_id},
};
COMMAND_REGISTER(command_connection_remove);
