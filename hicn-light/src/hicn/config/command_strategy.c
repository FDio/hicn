#include "command.h"

/* Parameters */

/* Commands */

static const command_parser_t command_strategy_list = {
    .action = ACTION_LIST,
    .object = OBJECT_STRATEGY,
    .nparams = 0,
};
COMMAND_REGISTER(command_strategy_list);
