#ifndef HICNLIGHT_PARSE_CMD
#define HICNLIGHT_PARSE_CMD

#include <hicn/ctrl/api.h>

int parse(const char* cmd, hc_command_t* command);
int help(const char* cmd);

/**
 * @brief Convert the action enum to the action name used in the commands (e.g.
 * from ACTION_CREATE to "add").
 */
const char* action_to_cmd_action(hc_action_t action);

#endif /* HICNLIGHT_PARSE_CMD */
