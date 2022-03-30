#include "command.h"

/* Parameters */
#define prefix                                                          \
  {                                                                     \
    .name = "prefix",                                                   \
    .help = "The hicn name as IPv4 or IPv6 address (e.g 1234::0/64).",  \
    .type = TYPE_IP_PREFIX, .offset = offsetof(hc_strategy_t, address), \
    .offset2 = offsetof(hc_strategy_t, len),                            \
    .offset3 = offsetof(hc_strategy_t, family),                         \
  }

#define strategy                                                               \
  {                                                                            \
    .name = "strategy",                                                        \
    .help =                                                                    \
        "Strategy type (e.g. 'random', 'loadbalancer', 'low_latency', "        \
        "'replication', 'bestpath').",                                         \
    .type = TYPE_ENUM(strategy_type), .offset = offsetof(hc_strategy_t, type), \
  }

#define local_prefix                                                          \
  {                                                                           \
    .name = "local_prefix",                                                   \
    .help = "The hicn name as IPv4 or IPv6 address (e.g 1234::0/64).",        \
    .type = TYPE_IP_PREFIX, .offset = offsetof(hc_strategy_t, local_address), \
    .offset2 = offsetof(hc_strategy_t, local_len),                            \
    .offset3 = offsetof(hc_strategy_t, local_family),                         \
  }

/* Commands */

static const command_parser_t command_strategy_list = {
    .action = ACTION_SET,
    .object = OBJECT_STRATEGY,
    .nparams = 2,
    .parameters = {prefix, strategy},
};
COMMAND_REGISTER(command_strategy_list);

static const command_parser_t local_prefix_add = {
    .action = ACTION_CREATE,
    .object = OBJECT_LOCAL_PREFIX,
    .nparams = 3,
    .parameters = {prefix, strategy, local_prefix},
};
COMMAND_REGISTER(local_prefix_add);
