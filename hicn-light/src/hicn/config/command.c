
/**
 * @file command.c
 * @brief Implementation of commands.
 */

#include <search.h> /* tfind, tdestroy, twalk */
#include <stdio.h>
#include <ctype.h>
#include "command.h"
#include "parse.h"

/* Commands are registered in the following tree. */
static void *commands_root = NULL; /**< Tree ordered by name */

#ifdef __linux__
static void nothing_to_free() {}

__attribute__((destructor)) static void command_clear() {
  tdestroy(commands_root, nothing_to_free);
}
#endif /* __linux__ */

static int _command_compare(const command_parser_t *c1,
                            const command_parser_t *c2) {
  if (c1->object != c2->object) return c2->object - c1->object;
  if (c1->action != c2->action) return c2->action - c1->action;
  if (c1->nparams != c2->nparams) return c2->nparams - c1->nparams;
  return 0;
}

#define command_compare (int (*)(const void *, const void *))(_command_compare)

void command_register(const command_parser_t *command) {
  // Insert the command in the tree if the keys does not exist yet
  tsearch(command, &commands_root, command_compare);
}

const command_parser_t *command_search(const hc_action_t action,
                                       hc_object_type_t object,
                                       unsigned nparams) {
  command_parser_t **command, search;

  search.action = action;
  search.object = object;
  search.nparams = nparams;
  command = tfind(&search, &commands_root, command_compare);

  return command ? *command : NULL;
}

static inline void to_lowercase(char *p) {
  for (; *p; ++p) *p = tolower(*p);
}

typedef struct {
  hc_object_type_t object;
  hc_action_t action;
} cmd_search_params_t;

static hc_object_type_t prev_obj = OBJECT_UNDEFINED;
static hc_action_t prev_action = ACTION_UNDEFINED;
static void traversal_action(const void *nodep, VISIT which,
                             void *cmd_params0) {
  cmd_search_params_t *cmd_params = cmd_params0;

  // Execute this function during inorder traversal
  if (which != postorder && which != leaf) return;

  command_parser_t *datap;
  datap = *(command_parser_t **)nodep;
  char *obj_str = strdup(object_str(datap->object));
  to_lowercase(obj_str);

  // List all objects
  if (cmd_params->object == OBJECT_UNDEFINED &&
      cmd_params->action == ACTION_UNDEFINED) {
    if (datap->object == prev_obj) goto FREE_STR;
    prev_obj = datap->object;

    printf("\thelp %s\n", obj_str);
    goto FREE_STR;
  }

  // List actions for specific object
  if (datap->object != cmd_params->object) goto FREE_STR;
  if (cmd_params->action == ACTION_UNDEFINED) {
    if (datap->action == prev_action) goto FREE_STR;
    prev_action = datap->action;

    printf("\thelp %s %s\n", obj_str, action_to_cmd_action(datap->action));
    goto FREE_STR;
  }

  // List commands for specific object and action
  if (datap->action != cmd_params->action) goto FREE_STR;
  printf("   %s %s ", action_to_cmd_action(datap->action), obj_str);
  for (int i = 0; i < datap->nparams; i++)
    printf("<%s> ", datap->parameters[i].name);
  printf("\n\n");
  // List options' details
  if (datap->nparams == 0) goto FREE_STR;
  for (int i = 0; i < datap->nparams; i++)
    printf("%16s: %s\n", datap->parameters[i].name, datap->parameters[i].help);
  printf("\n");

FREE_STR:
  free(obj_str);
}

void command_list(hc_object_type_t object, hc_action_t action) {
#if defined(__linux__) && !defined(__ANDROID__)
  cmd_search_params_t cmd_params = {.object = object, .action = action};
  twalk_r(commands_root, traversal_action, &cmd_params);
#else
  fprintf(stderr, "twalk_r() function only available on linux");
  (void)traversal_action;
#endif
}
