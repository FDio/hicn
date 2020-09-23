#include "command.h"

/* Parameters */

/* Commands */

// XXX missing add

static const command_parser_t command_face_list = {
    .action = ACTION_LIST,
    .object = OBJECT_FACE,
    .nparams = 0,
};
COMMAND_REGISTER(command_face_list);
