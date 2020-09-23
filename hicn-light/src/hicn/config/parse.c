#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <hicn/ctrl/cli.h>
#include <hicn/util/log.h>

#include "parse.h"

// help add [done]
// help list
// help quit
// help remove
// help set
// help unset
// help cache
// help mapme
// help update
//
// add connection hicn <symbolic> <remote_ip> <local_ip>
//   <symbolic>              : symbolic name, e.g. 'conn1' (must be unique, start with alpha)
//   <remote_ip>  : the IPv4 or IPv6 or hostname of the remote system
//   <local_ip>              : optional local IP address to bind to

/*
 * As there is no portable way to generate a va_list to use with sscanf to
 * support a variable number of arguments, and no way to use a variable array
 * initialize in a nested struct, we use a fixed maximum number of parameters
 *
 * NOTE: update sscanf accordingly
 */

#include "command.h"

static void * sscanf_params[MAX_PARAMETERS];

const char * action_str[] = {
#define _(x) [ACTION_ ## x] = #x,
    foreach_action
#undef _
};

#define action_str(x) action_str[x]

hc_action_t
action_from_str(const char * action_str)
{
#define _(x)                                    \
    if (strcasecmp(action_str, # x) == 0)       \
        return ACTION_ ## x;                    \
    else
    foreach_action
#undef _
    if (strcasecmp(action_str, "add") == 0)
        return ACTION_CREATE;
    else
    if (strcasecmp(action_str, "remove") == 0)
        return ACTION_DELETE;
    else
        return ACTION_UNDEFINED;
}

const char * object_str[] = {
#define _(x) [OBJECT_ ## x] = #x,
    foreach_object
#undef _
};

#define object_str(x) object_str[x]

hc_object_type_t
object_from_str(const char * object_str)
{
#define _(x)                                    \
    if (strcasecmp(object_str, # x) == 0)       \
        return OBJECT_ ## x;                    \
    else
    foreach_object
#undef _
        return OBJECT_UNDEFINED;
}

const char *
parser_type_fmt(const parser_type_t * type)
{
    switch(type->name) {
        case TYPENAME_INT:
            return TYPE_FMT_INT;
        case TYPENAME_UINT:
            return TYPE_FMT_UINT;
        case TYPENAME_STR:
            return (type->str.max_size > 0)
                ? TYPE_FMT_STRN(type->str.max_size)
                : TYPE_FMT_STR;
        case TYPENAME_SYMBOLIC:
            return TYPE_FMT_SYMBOLIC;
        case TYPENAME_SYMBOLIC_OR_ID:
            return TYPE_FMT_SYMBOLIC_OR_ID;
        case TYPENAME_IP_ADDRESS:
            return TYPE_FMT_IP_ADDRESS;
        case TYPENAME_IP_PREFIX:
            return TYPE_FMT_IP_PREFIX;
        case TYPENAME_ENUM:
            return TYPE_FMT_ENUM;
        case TYPENAME_POLICY_STATE:
            return TYPE_FMT_POLICY_STATE;
        case TYPENAME_UNDEFINED:
        default:
            return NULL;
    }
}

int
parser_type_func(const parser_type_t * type, void * src, void *dst, void * dst2, void * dst3)
{
    switch(type->name) {
        case TYPENAME_INT:
            *(int*)dst = *(int*)src;
            break;
        case TYPENAME_UINT:
            *(unsigned*)dst = *(unsigned*)src;
            break;
        case TYPENAME_STR:
            if (type->str.max_size > 0) {
                strncpy(dst, src, type->str.max_size);
            } else {
                strcpy(dst, src);
            }
            break;
        case TYPENAME_SYMBOLIC:
            break;
        case TYPENAME_SYMBOLIC_OR_ID:
            break;
        case TYPENAME_IP_ADDRESS:
            *(ip_address_t*)dst = IP_ADDRESS_EMPTY; // XXX
            *(int*)dst2 = AF_INET;
            break;
        case TYPENAME_IP_PREFIX:
            *(ip_address_t*)dst = IP_ADDRESS_EMPTY; // XXX
            *(int*)dst2 = 128;
            *(int*)dst3 = AF_INET;
            break;
        case TYPENAME_ENUM:
            /* Enum index from string */
            assert(type->enum_.from_str);
            const char * str = *(const char **)src;
            *(int*)dst = type->enum_.from_str(str);
            break;
        case TYPENAME_POLICY_STATE:
        {
            assert(IS_VALID_POLICY_TAG(type->policy_state.tag));
            policy_tag_t tag = type->policy_state.tag;
            /* Format string is "%ms" */
            const char * str = *(const char **)src;
            policy_tag_state_t *pts = ((policy_tag_state_t*)dst);
            pts[tag].disabled = (str[0] == '!') ? 1 : 0;
            pts[tag].state = policy_state_from_str(str + pts[tag].disabled);
            break;
        }
        case TYPENAME_UNDEFINED:
        default:
            return -1;
    }
    return 0;
}

int
parse_params(const command_parser_t * parser, const char * params_s,
        hc_command_t * command)
{
    char fmt[1024];
    int n;
    size_t size = 0;

    char * pos = fmt;

    int must_free[MAX_PARAMETERS];

    unsigned count = 0;
    for (unsigned i = 0; i < parser->nparams; i++) {
        const command_parameter_t * p = &parser->parameters[i];
        const char * fmt = parser_type_fmt(&p->type);
        if (!fmt) {
            WARN("Ignored parameter %s with unknown type formatter", p->name);
            continue;
        }
        must_free[count] = (strcmp(fmt, "%ms") == 0),

        n = snprintf(pos, 1024 - size, "%s", fmt);
        pos += n;

        *pos = ' ';
        pos++;

        size += n + 1;
        count++;
    }
    *pos = '\0';

    void ** sp = sscanf_params;
    /* Update MAX_PARAMETERS accordingly in command.h */
    sscanf(params_s, fmt, &sp[0], &sp[1], &sp[2], &sp[3], &sp[4], &sp[5],
            &sp[6], &sp[7], &sp[8], &sp[9]);

    for (unsigned i = 0; i < count; i++) {
        const command_parameter_t * p = &parser->parameters[i];
        if (parser_type_func(&p->type, &sp[i], &command->object.as_uint8 + p->offset,
                    &command->object.as_uint8 + p->offset2,
                    &command->object.as_uint8 + p->offset3) < 0) {
            ERROR("Error during parsing of parameter '%s' value\n", p->name);
            goto ERR;
        }
        if (must_free[i])
            free(sp[i]);
    }
    return 0;

ERR:
    return -1;
}

int
parse(const char * cmd, hc_command_t * command)
{
    int nparams = 0;
    char * action_s = NULL;
    char * object_s = NULL;
    char * params_s = NULL;

    errno = 0;
    // XXX broken with zero parameters
    int n = sscanf(cmd, "%ms %ms%m[^\n]s", &action_s, &object_s, &params_s);
    if ((n < 2) || (n > 3)) {
        if (errno != 0)
            perror("scanf");
        return -1;
    }

    command->action = action_from_str(action_s);
    command->object.type = object_from_str(object_s);

    if (params_s) { //strlen(params_s) > 0) {
        for (char *ptr = params_s; (ptr = strchr(ptr, ' ')) != NULL; ptr++)
            nparams++;
    }

    /*
     * This checks is important even with 0 parameters as it checks whether the
     * command exists.
     */
    const command_parser_t * parser = command_search(command->action, command->object.type, nparams);
    if (!parser) {
        ERROR("Could not find parser for command '%s %s'", action_s, object_s);
        goto ERR;
    }

    if (params_s) {
        if (parse_params(parser, params_s, command) < 0) {
            ERROR("Could not parse '%s %s' command", action_s, object_s);
            goto ERR;
        }
    }

    if (parser->post_hook)
        parser->post_hook(&command->object.as_uint8);

    /* LIST commands with 0 parameters do not expect an output */
    if (params_s) {
        char buf[MAXSZ_OBJECT];
        int rc = hc_object_snprintf(buf, MAXSZ_OBJECT, &command->object);
        if (rc < 0)
            snprintf(buf, MAXSZ_OBJECT, "%s", "[hc_snprintf_error]");
        else if (rc >= MAXSZ_OBJECT) {
            buf[MAXSZ_OBJECT-1] = '\0';
            buf[MAXSZ_OBJECT-2] = '.';
            buf[MAXSZ_OBJECT-3] = '.';
            buf[MAXSZ_OBJECT-4] = '.';
        }

        DEBUG("%s %s <%s>", action_s, object_s, buf);
    } else {
        DEBUG("%s %s <No parameters>", action_s, object_s);
    }

    free(action_s);
    free(object_s);
    free(params_s);

    return 0;

ERR:
    free(action_s);
    free(object_s);
    free(params_s);
    return -1;
}

#if 0 // tests
/* For the tests, we will need to test all non-compliant inputs */
const char * cmds[] = {
        "add connection hicn conn1 8.8.8.8 127.0.0.1 eth0",
        "add connection udp <symbolic> <remote_ip> <port> <local_ip> <port> eth0",
        "add listener udp lst1 127.0.0.1 9695 eth0",
        //"add face",
        "add route 3 b001::/16 1",
        //"add punting",
        //"add strategy",
        "add policy b001::/16 webex require avoid prohibit !prohibit neutral !require prefer",
        "list connection", // need pluralize
        "list listener",
        "list face",
        "list route",
        "list punting",
        "list strategy",
        "list policy",
        "remove connection 1",
        "remove listener 1",
        //"remove face",
        "remove route 1 b001::/16",
        //"remove punting",
        //"remove policy",
        "set debug",
        "unset debug",
        "set strategy b001::/16 random", // related prefixes (10 max) ?
        "set strategy b001::/16 load_balancer",
        "set strategy b001::/16 low_latency",
        "set wldr <on|off> <connection_id>", // on-off vs unset
        "cache clear",
        "cache store on/off", // set/unset
        "cache serve on/off",
        "mapme enable on/off",
        "mapme discovery on/off",
        "mapme timescale 500ms",
        "mapme retx 500ms",
        "update connection conn1 WT",
};

#define array_size(x) sizeof(x) / sizeof(typeof(x[0]))
int main()
{
    for (unsigned i = 0; i < array_size(cmds); i++) {
        printf("PARSING [%d] %s\n", i, cmds[i]);
        if (parse(cmds[i]) < 0) {
            ERROR("Could not parse command: %s\n", cmds[i]);
            continue;
        }
    }
    exit(EXIT_SUCCESS);

ERR:
    exit(EXIT_FAILURE);
}
#endif
