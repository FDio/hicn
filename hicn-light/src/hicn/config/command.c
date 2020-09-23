
/**
 * @file command.c
 * @brief Implementation of commands.
 */

#include <search.h> /* tfind, tdestroy, twalk */
#include <stdio.h>

#include "command.h"

/* Commands are registered in the following tree. */
static void * commands_root    = NULL;  /**< Tree ordered by name */

static void nothing_to_free() {}

#ifdef __linux__
__attribute__((destructor))
static
void
command_clear()
{
    tdestroy(commands_root, nothing_to_free);
}
#endif /* __linux__ */

static
int
_command_compare(const command_parser_t * c1,
        const command_parser_t * c2)
{
    if (c1->action != c2->action)
        return c2->action - c1->action;
    if (c1->object != c2->object)
        return c2->object - c1->object;
    if (c1->nparams != c2->nparams)
        return c2->nparams - c1->nparams;
    return 0;
}

#define command_compare (int (*)(const void *, const void *))(_command_compare)

void
command_register(const command_parser_t * command)
{
    // Insert the command in the tree if the keys does not exist yet
    tsearch(command, &commands_root, command_compare);
}

const command_parser_t *
command_search(hc_action_t action, hc_object_type_t object, unsigned nparams)
{
    command_parser_t ** command, search;

    search.action = action;
    search.object = object;
    search.nparams = nparams;
    command = tfind(&search, &commands_root, command_compare);

    return command ? *command : NULL;
}
