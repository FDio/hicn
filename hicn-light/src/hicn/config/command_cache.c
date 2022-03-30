#include <math.h>
#include "command.h"

/* Parameters */

#define serve                                                            \
  {                                                                      \
    .name = "serve",                                                     \
    .help =                                                              \
        "Enables/disables replies from local content store. Either the " \
        "string 'on' or 'off'",                                          \
    .type = TYPE_ON_OFF, .offset = offsetof(hc_cache_t, serve),          \
  }

#define store                                                                 \
  {                                                                           \
    .name = "store",                                                          \
    .help =                                                                   \
        "enables/disables the storage of incoming data packets in the local " \
        "content store. Either the string 'on' or 'off'",                     \
    .type = TYPE_ON_OFF, .offset = offsetof(hc_cache_t, store),               \
  }

/* Commands */

static const command_parser_t command_cache_set_serve = {
    .action = ACTION_SERVE,
    .object = OBJECT_CACHE,
    .nparams = 1,
    .parameters = {serve},
};
COMMAND_REGISTER(command_cache_set_serve);

static const command_parser_t command_cache_set_store = {
    .action = ACTION_STORE,
    .object = OBJECT_CACHE,
    .nparams = 1,
    .parameters = {store},
};
COMMAND_REGISTER(command_cache_set_store);

static const command_parser_t command_cache_clear = {
    .action = ACTION_CLEAR,
    .object = OBJECT_CACHE,
    .nparams = 0,
};
COMMAND_REGISTER(command_cache_clear);

static const command_parser_t command_cache_list = {
    .action = ACTION_LIST,
    .object = OBJECT_CACHE,
    .nparams = 0,
};
COMMAND_REGISTER(command_cache_list);
