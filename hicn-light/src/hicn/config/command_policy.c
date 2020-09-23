#include <hicn/policy.h>

#include "command.h"

/* Parameters */

static const command_parameter_t prefix = {
    .name = "prefix",
    .help = "The hicn name as IPv4 or IPv6 address (e.g 1234::0/64).",
    .type = TYPE_IP_PREFIX,
    .offset = offsetof(hc_policy_t, remote_addr),
    .offset2 = offsetof(hc_policy_t, len),
    .offset3 = offsetof(hc_policy_t, family),
};

static const command_parameter_t app_name = {
    .name = "app_name",
    .help = "The application name associated to this policy",
    .type = TYPE_STR,
    .offset = offsetof(hc_policy_t, policy.app_name),
};


#define _(x, y)                                         \
static const command_parameter_t flag_ ## x = {         \
    .name = "flag:" #x,                                 \
    .help = "A value among [neutral|require|prefer|avoid|prohibit] with an optional '!' character prefix for disabling changes", \
    .type = TYPE_POLICY_STATE(POLICY_TAG_ ## x),        \
    .offset = offsetof(hc_policy_t, policy.tags),       \
};
    foreach_policy_tag
#undef _

/* Commands */

static const command_parser_t command_policy_create = {
    .action = ACTION_CREATE,
    .object = OBJECT_POLICY,
    .nparams = 2 + POLICY_TAG_N,
    .parameters = { prefix, app_name,
#define _(x, y) flag_ ## x,
    foreach_policy_tag
#undef _
    },
};
COMMAND_REGISTER(command_policy_create);

static const command_parser_t command_policy_list = {
    .action = ACTION_LIST,
    .object = OBJECT_POLICY,
    .nparams = 0,
};
COMMAND_REGISTER(command_policy_list);
