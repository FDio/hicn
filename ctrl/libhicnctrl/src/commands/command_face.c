#include <hicn/ctrl/command.h>

/* Parameters */

#define type_hicn                                                             \
  {                                                                           \
    .name = "type", .help = "face type (hICN)", .type = TYPE_ENUM(face_type), \
    .offset = offsetof(hc_face_t, type),                                      \
  }

#define type_tcp_udp                                                   \
  {                                                                    \
    .name = "type", .help = "face type [tcp | udp]",                   \
    .type = TYPE_ENUM(face_type), .offset = offsetof(hc_face_t, type), \
  }

#define local_address                                                   \
  {                                                                     \
    .name = "local_addr", .help = "local IP address on which to bind.", \
    .type = TYPE_IP_ADDRESS, .offset = offsetof(hc_face_t, local_addr), \
    .offset2 = offsetof(hc_face_t, family),                             \
  }

#define local_port                               \
  {                                              \
    .name = "local_port", .help = "Local port.", \
    .type = TYPE_UINT16(1, UINT16_MAX),          \
    .offset = offsetof(hc_face_t, local_port),   \
  }

#define remote_address                                                   \
  {                                                                      \
    .name = "remote_address",                                            \
    .help = "The IPv4 or IPv6 or hostname of the remote system.",        \
    .type = TYPE_IP_ADDRESS, .offset = offsetof(hc_face_t, remote_addr), \
    .offset2 = offsetof(hc_face_t, family),                              \
  }

#define remote_port                                \
  {                                                \
    .name = "remote_port", .help = "Remote port.", \
    .type = TYPE_UINT16(1, UINT16_MAX),            \
    .offset = offsetof(hc_face_t, remote_port),    \
  }

#define interface                                                           \
  {                                                                         \
    .name = "interface", .help = "Interface on which to bind",              \
    .type = TYPE_INTERFACE_NAME,                                            \
    .offset = offsetof(hc_face_t, netdevice) + offsetof(netdevice_t, name), \
  }

#define symbolic_or_id                                                \
  {                                                                   \
    .name = "symbolic", .help = "The face symbolic name or id",       \
    .type = TYPE_SYMBOLIC_OR_ID, .offset = offsetof(hc_face_t, name), \
  }

/* Commands */

int on_face_create(hc_face_t* face) {
  face->admin_state = FACE_STATE_UP;
  return 0;
}

static command_parser_t command_face_create3 = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_FACE,
    .nparams = 3,
    .parameters = {type_hicn, local_address, remote_address},
    .post_hook = (parser_hook_t)on_face_create,
};
COMMAND_REGISTER(command_face_create3);

#if 0
static const command_parser_t command_face_create4 = {
    .action = ACTION_CREATE,
    .object = OBJECT_TYPE_FACE,
    .nparams = 4,
    .parameters = {type_hicn, local_address, remote_address,
                   interface},
    .post_hook = (parser_hook_t)on_face_create,
};
COMMAND_REGISTER(command_face_create4);
#endif

static const command_parser_t command_face_create5 = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_FACE,
    .nparams = 5,
    .parameters = {type_tcp_udp, remote_address, remote_port, local_address,
                   local_port},
    .post_hook = (parser_hook_t)on_face_create,
};
COMMAND_REGISTER(command_face_create5);

static const command_parser_t command_face_create6 = {
    .action = ACTION_CREATE,
    .object_type = OBJECT_TYPE_FACE,
    .nparams = 6,
    .parameters = {type_tcp_udp, remote_address, remote_port, local_address,
                   local_port, interface},
    .post_hook = (parser_hook_t)on_face_create,
};
COMMAND_REGISTER(command_face_create6);

static const command_parser_t command_face_list = {
    .action = ACTION_LIST,
    .object_type = OBJECT_TYPE_FACE,
    .nparams = 0,
};
COMMAND_REGISTER(command_face_list);
