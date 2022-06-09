#include <math.h>
#include "command.h"

/* Commands */

static const command_parser_t command_stats_get = {
    .action = ACTION_GET,
    .object = OBJECT_STATS,
    .nparams = 0,
};
COMMAND_REGISTER(command_stats_get);

static const command_parser_t command_stats_list = {
    .action = ACTION_LIST,
    .object = OBJECT_STATS,
    .nparams = 0,
};
COMMAND_REGISTER(command_stats_list);