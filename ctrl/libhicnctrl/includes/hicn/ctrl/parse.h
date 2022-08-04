#ifndef HICNLIGHT_PARSE_CMD
#define HICNLIGHT_PARSE_CMD

#include <hicn/ctrl/api.h>

#include "command.h"

/* Update sscanf accordingly in parse_cmd.c */
#define MAX_PARAMETERS 10
#define MAX_SCANF_PARAM_LEN 100

typedef int (*parser_hook_t)(void* arg);

#if 0
typedef struct {
  const char* name;
  const char* help;
  parser_type_t type;
  size_t offset;
  /*
   * quick hack to let the functions update two or more parameters, like for
   * IP_ADDRESS or IP_PREFIX types
   */
  size_t offset2;
  size_t offset3;
} command_parameter_t;

typedef struct {
  hc_action_t action;
  hc_object_type_t object;
  unsigned nparams;
  command_parameter_t parameters[MAX_PARAMETERS];
  parser_hook_t post_hook;
} command_parser_t;

#define TYPE_STRN(N)      \
  (parser_type_t) {       \
    .name = TYPENAME_STR, \
    .str = {              \
        .max_size = N,    \
    },                    \
  }
#define TYPE_FMT_STRN(N) "%s"

#define TYPE_INT(MIN, MAX) \
  (parser_type_t) {        \
    .name = TYPENAME_INT,  \
    .sint = {              \
        .min = (MIN),      \
        .max = (MAX),      \
    },                     \
  }
#define TYPE_FMT_INT "%d"

#define TYPE_UINT(min, max) \
  (parser_type_t) {         \
    .name = TYPENAME_UINT,  \
    .uint = {               \
        .min = min,         \
        .max = max,         \
    },                      \
  }
#define TYPE_FMT_UINT "%u"

#define TYPE_SYMBOLIC_OR_ID TYPE_STRN(SYMBOLIC_NAME_LEN)
#define TYPE_FMT_SYMBOLIC_OR_ID "%s"

#define TYPE_INTERFACE_NAME TYPE_STRN(INTERFACE_LEN)
#define TYPE_FMT_INTERFACE_NAME "%s"

#define TYPE_IP_ADDRESS \
  (parser_type_t) { .name = TYPENAME_IP_ADDRESS, }
#define TYPE_FMT_IP_ADDRESS "%s"

#define TYPE_IP_PREFIX \
  (parser_type_t) { .name = TYPENAME_IP_PREFIX, }
#define TYPE_FMT_IP_PREFIX "%s"

#define TYPE_ON_OFF \
  (parser_type_t) { .name = TYPENAME_ON_OFF, }
#define TYPE_FMT_ON_OFF "%s"

#define TYPE_ENUM(x)                                    \
  (parser_type_t) {                                     \
    .name = TYPENAME_ENUM,                              \
    .enum_ = {                                          \
        .from_str = (int (*)(const char*))x##_from_str, \
    },                                                  \
  }
/* We need to allocate room for the intermediate string */
#define TYPE_FMT_ENUM "%s"

#define TYPE_POLICY_STATE(TAG)     \
  (parser_type_t) {                \
    .name = TYPENAME_POLICY_STATE, \
    .policy_state = {              \
        .tag = TAG,                \
    },                             \
  }
/* We need to allocate room for the intermediate string */
#define TYPE_FMT_POLICY_STATE "%s"
#endif

int parse_getopt_args(const command_parser_t* parser, int argc, char* argv[],
                      hc_command_t* command);

int parse(const char* cmd, hc_command_t* command);
int help(const char* cmd);

/**
 * @brief Convert the action enum to the action name used in the commands (e.g.
 * from ACTION_CREATE to "add").
 */
const char* action_to_cmd_action(hc_action_t action);

#endif /* HICNLIGHT_PARSE_CMD */
