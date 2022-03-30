#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

//#include <hicn/ctrl/cli.h>
#include <hicn/util/log.h>
#include <hicn/util/sstrncpy.h>
#include "parse.h"

/*
 * As there is no portable way to generate a va_list to use with sscanf to
 * support a variable number of arguments, and no way to use a variable array
 * initialize in a nested struct, we use a fixed maximum number of parameters
 *
 * NOTE: update sscanf accordingly
 */

#include "command.h"

const char *action_str[] = {
#define _(x) [ACTION_##x] = #x,
    foreach_action
#undef _
};

#define action_str(x) action_str[x]

hc_action_t action_from_str(const char *action_str) {
#define _(x)                           \
  if (strcasecmp(action_str, #x) == 0) \
    return ACTION_##x;                 \
  else
  foreach_action
#undef _
      if (strcasecmp(action_str, "add") == 0) return ACTION_CREATE;
  else if (strcasecmp(action_str, "remove") == 0) return ACTION_DELETE;
  else return ACTION_UNDEFINED;
}

const char *object_str[] = {
#define _(x) [OBJECT_##x] = #x,
    foreach_object
#undef _
};

#define object_str(x) object_str[x]

hc_object_type_t object_from_str(const char *object_str) {
#define _(x)                           \
  if (strcasecmp(object_str, #x) == 0) \
    return OBJECT_##x;                 \
  else
  foreach_object
#undef _
      return OBJECT_UNDEFINED;
}

const char *action_to_cmd_action(hc_action_t action) {
  switch (action) {
    case ACTION_CREATE:
      return "add";
    case ACTION_UPDATE:
      return "update";
    case ACTION_DELETE:
      return "remove";
    case ACTION_LIST:
      return "list";
    case ACTION_SET:
      return "set";
    case ACTION_SERVE:
      return "serve";
    case ACTION_STORE:
      return "store";
    case ACTION_CLEAR:
      return "clear";
    default:
      return "UNDEFINED";
  }
}

const char *parser_type_fmt(const parser_type_t *type) {
  switch (type->name) {
    case TYPENAME_INT:
      return TYPE_FMT_INT;
    case TYPENAME_UINT:
      return TYPE_FMT_UINT;
    case TYPENAME_STR:
      return TYPE_FMT_STRN(type->str.max_size);
    case TYPENAME_SYMBOLIC_OR_ID:
      return TYPE_FMT_SYMBOLIC_OR_ID;
    case TYPENAME_INTERFACE_NAME:
      return TYPE_FMT_INTERFACE_NAME;
    case TYPENAME_IP_ADDRESS:
      return TYPE_FMT_IP_ADDRESS;
    case TYPENAME_IP_PREFIX:
      return TYPE_FMT_IP_PREFIX;
    case TYPENAME_ON_OFF:
      return TYPE_FMT_ON_OFF;
    case TYPENAME_ENUM:
      return TYPE_FMT_ENUM;
    case TYPENAME_POLICY_STATE:
      return TYPE_FMT_POLICY_STATE;
    case TYPENAME_UNDEFINED:
    default:
      return NULL;
  }
}

int parser_type_func(const parser_type_t *type, void *src, void *dst,
                     void *dst2, void *dst3) {
  ip_address_t addr;
  char *addr_str;
  char *len_str;
  int len, tmp, rc;

  switch (type->name) {
    case TYPENAME_INT:
      tmp = *(int *)src;
      if (tmp < type->sint.min || tmp > type->sint.max) {
        ERROR("Input number (%d) not inside range [%d, %d]", tmp,
              type->sint.min, type->sint.max);
        return -1;
      }
      *(int *)dst = *(int *)src;
      break;
    case TYPENAME_UINT:
      tmp = *(int *)src;
      if (tmp < type->uint.min || tmp > type->uint.max) {
        ERROR("Input number (%d) not inside range [%d, %d]", tmp,
              type->uint.min, type->uint.max);
        return -1;
      }
      *(unsigned *)dst = *(unsigned *)src;
      break;
    case TYPENAME_STR:
      rc = strcpy_s(dst, type->str.max_size, src);
      if (rc != EOK) {
        ERROR("Input string is too long");
        return -1;
      }
      break;
    case TYPENAME_IP_ADDRESS:
      rc = ip_address_pton((char *)src, &addr);
      if (rc < 0) {
        ERROR("Wrong IP address format");
        return -1;
      }

      *(ip_address_t *)dst = addr;
      *(int *)dst2 = ip_address_get_family((char *)src);
      break;
    case TYPENAME_ON_OFF:
      if (strcmp((char *)src, "off") == 0) {
        *(unsigned *)dst = 0;
      } else if (strcmp((char *)src, "on") == 0) {
        *(unsigned *)dst = 1;
      } else {
        ERROR("on/off are the only possible values");
        return -1;
      }
      break;
    case TYPENAME_IP_PREFIX:
      addr_str = strtok((char *)src, "/");
      len_str = strtok(NULL, " ");
      rc = ip_address_pton((char *)src, &addr);
      if (rc < 0) {
        ERROR("Wrong IP address format");
        return -1;
      }
      len = atoi(len_str);

      *(ip_address_t *)dst = addr;
      *(int *)dst2 = len;
      *(int *)dst3 = ip_address_get_family(addr_str);
      break;
    case TYPENAME_ENUM:
      /* Enum index from string */
      assert(type->enum_.from_str);
      *(int *)dst = type->enum_.from_str((char *)src);
      break;
    case TYPENAME_POLICY_STATE: {
      assert(IS_VALID_POLICY_TAG(type->policy_state.tag));
      policy_tag_t tag = type->policy_state.tag;
      /* Format string is "%ms" */
      const char *str = *(const char **)src;
      policy_tag_state_t *pts = ((policy_tag_state_t *)dst);
      pts[tag].disabled = (str[0] == '!') ? 1 : 0;
      pts[tag].state = policy_state_from_str(str + pts[tag].disabled);
      break;
    }
    case TYPENAME_UNDEFINED:
    default:
      ERROR("Unknown format");
      return -1;
  }
  return 0;
}

int parse_params(const command_parser_t *parser, const char *params_s,
                 hc_command_t *command) {
  char fmt[1024];
  int n;
  size_t size = 0;
  char *pos = fmt;
  /* Update MAX_PARAMETERS accordingly in command.h */
  char sscanf_params[MAX_PARAMETERS][MAX_SCANF_PARAM_LEN];

  unsigned count = 0;
  for (unsigned i = 0; i < parser->nparams; i++) {
    const command_parameter_t *p = &parser->parameters[i];
    const char *_fmt = parser_type_fmt(&p->type);
    // printf("    _fmt=%s\n", _fmt);
    if (!_fmt) {
      WARN("Ignored parameter %s with unknown type formatter", p->name);
      continue;
    }
    n = snprintf(pos, 1024 - size, "%s", _fmt);
    pos += n;

    *pos = ' ';
    pos++;

    size += n + 1;
    count++;
  }
  *pos = '\0';
  DEBUG("parser format: %s", fmt);

  int ret = sscanf(params_s, fmt, sscanf_params[0], sscanf_params[1],
                   sscanf_params[2], sscanf_params[3], sscanf_params[4],
                   sscanf_params[5], sscanf_params[6], sscanf_params[7],
                   sscanf_params[8], sscanf_params[9]);
  if (ret != parser->nparams) {
    ERROR("Parsing failed: check for string used where integer was expected");
    goto ERR;
  }

  for (unsigned i = 0; i < count; i++) {
    const command_parameter_t *p = &parser->parameters[i];
    if (parser_type_func(&p->type, sscanf_params[i],
                         &command->object.as_uint8 + p->offset,
                         &command->object.as_uint8 + p->offset2,
                         &command->object.as_uint8 + p->offset3) < 0) {
      ERROR("Error during parsing of parameter '%s' value", p->name);
      goto ERR;
    }
  }
  return 0;

ERR:
  return -1;
}

int parse(const char *cmd, hc_command_t *command) {
  int nparams = 0;
  char action_s[MAX_SCANF_PARAM_LEN];
  char object_s[MAX_SCANF_PARAM_LEN];
  char params_s[MAX_SCANF_PARAM_LEN];

  // if n = 2 later, params_s is uninitialized
  memset(params_s, 0, MAX_SCANF_PARAM_LEN * sizeof(char));

  errno = 0;
  int n = sscanf(cmd, "%s %s%[^\n]s", action_s, object_s, params_s);
  if ((n < 2) || (n > 3)) {
    if (errno != 0) perror("scanf");
    return -1;
  }

  command->action = action_from_str(action_s);
  command->object.type = object_from_str(object_s);

  if (strnlen_s(params_s, MAX_SCANF_PARAM_LEN) > 0) {
    for (char *ptr = params_s; (ptr = strchr(ptr, ' ')) != NULL; ptr++)
      nparams++;
  }

  /*
   * This checks is important even with 0 parameters as it checks whether the
   * command exists.
   */
  const command_parser_t *parser =
      command_search(command->action, command->object.type, nparams);
  if (!parser) {
    ERROR("Could not find parser for command '%s %s'", action_s, object_s);
    return -1;
  }

  if (strnlen_s(params_s, MAX_SCANF_PARAM_LEN) > 0) {
    if (parse_params(parser, params_s, command) < 0) return -1;
  }

  if (parser->post_hook) parser->post_hook(&command->object.as_uint8);
  return 0;
}

int help(const char *cmd) {
  int nparams = 1;
  char action_s[MAX_SCANF_PARAM_LEN];
  char object_s[MAX_SCANF_PARAM_LEN];
  char params_s[MAX_SCANF_PARAM_LEN];
  hc_object_type_t object = OBJECT_UNDEFINED;
  hc_action_t action = ACTION_UNDEFINED;

  int n = sscanf(cmd, "help %[^\n]s", params_s);

  // No arguments provided to the help command: just list available objects
  if (n != 1) goto CMD_LIST;

  // Count number of provided parameters
  for (char *ptr = params_s; (ptr = strchr(ptr, ' ')) != NULL; ptr++) nparams++;
  if (nparams > 2) {
    fprintf(stderr, "Error: too many arguments.\n");
    return -1;
  }

  // Object specified: list actions available for that object
  if (nparams == 1) {
    object = object_from_str(params_s);
    if (object == OBJECT_UNDEFINED) {
      fprintf(stderr, "Error: undefined object.\n");
      return -1;
    }

    goto CMD_LIST;
  }

  // Object and action specified: list detailed commands
  n = sscanf(params_s, "%s %[^\n]s", object_s, action_s);
  assert(n == 2);
  object = object_from_str(object_s);
  action = action_from_str(action_s);
  if (object == OBJECT_UNDEFINED || action == ACTION_UNDEFINED) {
    fprintf(stderr, "Error: undefined object and/or action.\n");
    return -1;
  }

CMD_LIST:
  printf("Available commands:\n");
  command_list(object, action);
  return 0;
}

#if 0  // tests
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
        "set strategy b001::/16 replication",
        "set strategy b001::/16 bestpath",
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
