#include <math.h>
#include "command.h"

/* Parameters */

static const command_parameter_t protocol_hicn = {
    .name = "protocol",
    .help = "Protocol [hicn].",
    .type = TYPE_ENUM(connection_type),
    .offset = offsetof(hc_listener_t, type),
};

static const command_parameter_t protocol_tcp_udp = {
    .name = "protocol",
    .help = "Protocol [tcp | udp]",
    .type = TYPE_ENUM(connection_type),
    .offset = offsetof(hc_listener_t, type),
};

static const command_parameter_t symbolic = {
    .name = "symbolic",
    .help = "User defined name for listener, must start with alpha and be alphanum",
    .type = TYPE_SYMBOLIC,
    .offset = offsetof(hc_listener_t, name),
};

static const command_parameter_t local_address = {
    .name = "local_addr",
    .help = "IPv4 or IPv6 address (or prefix protocol = hicn) assigend to the local interface",
    .type = TYPE_IP_ADDRESS,
    .offset = offsetof(hc_listener_t, local_addr),
    .offset2 = offsetof(hc_listener_t, family),
};

static const command_parameter_t local_port = {
    .name = "local_port",
    .help = "Local port.",
    .type = TYPE_INT(1, pow(2, 16) - 1),
    .offset = offsetof(hc_listener_t, local_port),
};

static const command_parameter_t interface = {
    .name = "interface",
    .help = "Interface on which to bind", // optional ?
    .type = TYPE_STRN(IFNAMSIZ),
    .offset = offsetof(hc_listener_t, interface_name),
};

static const command_parameter_t symbolic_or_id = {
    .name = "symbolic",
    .help = "The listener symbolic name or id",
    .type = TYPE_SYMBOLIC_OR_ID,
    .offset = offsetof(hc_listener_t, name),
};

/* Commands */

static const command_parser_t command_listener_create4 = {
    .action = ACTION_CREATE,
    .object = OBJECT_LISTENER,
    .nparams = 4,
    .parameters = { protocol_hicn, symbolic, local_address, interface },
};
COMMAND_REGISTER(command_listener_create4);

static const command_parser_t command_listener_create6 = {
    .action = ACTION_CREATE,
    .object = OBJECT_LISTENER,
    .nparams = 5,
    .parameters = { protocol_tcp_udp, symbolic, local_address, local_port, interface }
};
COMMAND_REGISTER(command_listener_create6);

static const command_parser_t command_listener_list = {
    .action = ACTION_LIST,
    .object = OBJECT_LISTENER,
    .nparams = 0,
};
COMMAND_REGISTER(command_listener_list);

static const command_parser_t command_listener_remove = {
    .action = ACTION_DELETE,
    .object = OBJECT_LISTENER,
    .nparams = 1,
    .parameters = { symbolic_or_id },
};
COMMAND_REGISTER(command_listener_remove);
