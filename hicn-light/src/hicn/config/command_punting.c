#include "command.h"

/* Parameters */

static const command_parameter_t symbolic_or_id = {
    .name = "symbolic_or_id",
    .help = "The symbolic name for an egress, or the egress punting id (see 'help list puntings')",
    .type = TYPE_SYMBOLIC_OR_ID,
    .offset = offsetof(hc_punting_t, face_id),
};

static const command_parameter_t prefix = {
    .name = "prefix",
    .help = "Prefix to add as a punting rule. (example 1234::0/64)",
    .type = TYPE_IP_PREFIX,
    .offset = offsetof(hc_punting_t, prefix),
    .offset2 = offsetof(hc_punting_t, prefix_len),
    .offset3 = offsetof(hc_punting_t, family),
};

/* Commands */

static const command_parser_t command_punting_create = {
    .action = ACTION_CREATE,
    .object = OBJECT_PUNTING,
    .nparams = 2,
    .parameters = { symbolic_or_id, prefix },
};
COMMAND_REGISTER(command_punting_create);

static const command_parser_t command_punting_list = {
    .action = ACTION_LIST,
    .object = OBJECT_PUNTING,
    .nparams = 0,
};
COMMAND_REGISTER(command_punting_list);
