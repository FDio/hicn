#include "command.h"

/* Parameters */

#define topics                                                                 \
  {                                                                            \
    .name = "topics",                                                          \
    .help =                                                                    \
        "Topics to subscribe to, e.g. 6 (110 in binary) means topic 2 (10 in " \
        "binary, TOPIC_CONNECTION) and topic 4 (100 in binary, "               \
        "TOPIC_LISTENER).",                                                    \
    .type = TYPE_INT(1, 255), .offset = offsetof(hc_subscription_t, topics),   \
  }

/* Commands */

static const command_parser_t command_subscription_create = {
    .action = ACTION_CREATE,
    .object = OBJECT_SUBSCRIPTION,
    .nparams = 1,
    .parameters = {topics},
};
COMMAND_REGISTER(command_subscription_create);