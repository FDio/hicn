#ifndef HICNLIGHT_CONFIG_COMMAND
#define HICNLIGHT_CONFIG_COMMAND

/**
 * @file command.h
 * @brief Commands.
 */

#include <stddef.h> // offsetof
#include <hicn/util/ip_address.h>

#include <hicn/ctrl/api.h>

/* Update sscanf accordingly in parse_cmd.c */
#define MAX_PARAMETERS 10
#define MAX_SCANF_PARAM_LEN 10

typedef int (*parser_hook_t)(void * arg);

typedef enum {
    TYPENAME_UNDEFINED,
    TYPENAME_INT,
    TYPENAME_UINT,
    TYPENAME_STR,
    TYPENAME_SYMBOLIC,
    TYPENAME_SYMBOLIC_OR_ID,
    TYPENAME_IP_ADDRESS,
    TYPENAME_IP_PREFIX,
    TYPENAME_ENUM,
    TYPENAME_POLICY_STATE,
} parser_typename_t;

typedef struct {
    parser_typename_t name;
    union {
        struct {
            size_t max_size;
        } str;
        struct {
            int min;
            int max;
        } sint;
        struct {
            int min;
            int max;
        } uint;
        struct {
            int (*from_str)(const char * str);
        } enum_;
        struct {
            policy_tag_t tag;
        } policy_state;
    };
} parser_type_t;

typedef struct {
    const char * name;
    const char * help;
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

#define TYPE_STRN(N) (parser_type_t) {                          \
    .name = TYPENAME_STR,                                       \
    .str = {                                                    \
        .max_size = 0,                                          \
    },                                                          \
}
#define TYPE_FMT_STRN(N) "%s"

#define TYPE_INT(MIN, MAX) (parser_type_t) {                    \
    .name = TYPENAME_INT,                                       \
    .sint = {                                                   \
        .min = (MIN),                                           \
        .max = (MAX),                                           \
    },                                                          \
}
#define TYPE_FMT_INT "%d"

#define TYPE_UINT(min, max) (parser_type_t) {                   \
    .name = TYPENAME_INT,                                       \
    .uint = {                                                   \
        .min = min,                                             \
        .max = max,                                             \
    },                                                          \
}
#define TYPE_FMT_UINT "%u"

#define TYPE_STR TYPE_STRN(0)
#define TYPE_FMT_STR "%s"

#define TYPE_SYMBOLIC TYPE_STRN(NAME_LEN)
#define TYPE_FMT_SYMBOLIC "%s"

#define TYPE_SYMBOLIC_OR_ID TYPE_STRN(NAME_LEN)
#define TYPE_FMT_SYMBOLIC_OR_ID "%s"

#define TYPE_IP_ADDRESS (parser_type_t) {                       \
    .name = TYPENAME_IP_ADDRESS,                                \
}
#define TYPE_FMT_IP_ADDRESS "%s"

#define TYPE_IP_PREFIX (parser_type_t) {                        \
    .name = TYPENAME_IP_PREFIX,                                 \
}
#define TYPE_FMT_IP_PREFIX "%s"

#define TYPE_ENUM(x) (parser_type_t) {                          \
    .name = TYPENAME_ENUM,                                      \
    .enum_ = {                                                  \
        .from_str = (int(*)(const char *)) x ## _from_str,      \
    },                                                          \
}
/* We need to allocate room for the intermediate string */
#define TYPE_FMT_ENUM "%ms"

#define TYPE_POLICY_STATE(TAG) (parser_type_t) {                \
    .name = TYPENAME_POLICY_STATE,                              \
    .policy_state = {                                           \
        .tag = TAG,                                             \
    },                                                          \
}
/* We need to allocate room for the intermediate string */
#define TYPE_FMT_POLICY_STATE "%ms"

/**
 * \brief Register a protocol
 * \param protocol Pointer to a protocol_t structure describing the protocol to register
 * \return None
 */

void command_register(const command_parser_t * command);

/**
 * \brief Search a registered protocol in the library according to its name
 * \param[in] action The action of the command.
 * \param[in] object The object of the command.
 * \param[in] nparams The number of parameters expected in the command.
 * \return A pointer to the corresponding command if any, NULL othewise
 */
const command_parser_t * command_search(hc_action_t action, hc_object_type_t object,
        unsigned nparams);

#define COMMAND_REGISTER(MOD)    \
static void __init_ ## MOD (void) __attribute__ ((constructor));    \
static void __init_ ## MOD (void) {    \
    command_register(&MOD); \
}

#endif /* HICNLIGHT_CONFIG_COMMAND */
