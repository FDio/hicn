#include "command.h"

/* Parameters */

static const command_parameter_t symbolic_or_id = {
    .name = "symbolic_or_id",
    .help = "The symbolic name for an egress, or the egress route id (see 'help list routes')",
    .type = TYPE_SYMBOLIC_OR_ID,
    .offset = offsetof(hc_route_t, face_id),
};

static const command_parameter_t prefix = {
    .name = "prefix",
    .help = "The hicn name as IPv4 or IPv6 address (e.g 1234::0/64).",
    .type = TYPE_IP_PREFIX,
    .offset = offsetof(hc_route_t, remote_addr),
    .offset2 = offsetof(hc_route_t, len),
    .offset3 = offsetof(hc_route_t, family),
};

static const command_parameter_t cost = {
    .name = "cost",
    .help = "Positive integer representing cost.",
    .type = TYPE_INT(1, 255),
    .offset = offsetof(hc_route_t, cost),
};

/* Commands */

static const command_parser_t command_route_create = {
    .action = ACTION_CREATE,
    .object = OBJECT_ROUTE,
    .nparams = 3,
    .parameters = { symbolic_or_id, prefix, cost },
};
COMMAND_REGISTER(command_route_create);

static const command_parser_t command_route_list = {
    .action = ACTION_LIST,
    .object = OBJECT_ROUTE,
    .nparams = 0,
};
COMMAND_REGISTER(command_route_list);

static const command_parser_t command_route_remove = {
    .action = ACTION_DELETE,
    .object = OBJECT_ROUTE,
    .nparams = 2,
    .parameters = { symbolic_or_id, prefix },
};
COMMAND_REGISTER(command_route_remove);
