#include <math.h>
#include <hicn/ctrl/command.h>

/* Commands */

static const command_parser_t command_stats_list = {
    .action = ACTION_LIST,
    .object_type = OBJECT_TYPE_STATS,
    .nparams = 0,
};
COMMAND_REGISTER(command_stats_list);

static const command_parser_t command_face_stats_list = {
    .action = ACTION_LIST,
    .object_type = OBJECT_TYPE_FACE_STATS,
    .nparams = 0,
};
COMMAND_REGISTER(command_face_stats_list);
