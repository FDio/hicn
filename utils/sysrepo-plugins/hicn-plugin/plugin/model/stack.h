#ifndef __STACK_H__
#define __STACK_H__


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../hicn_vpp_comm.h"

#define UNUSED(x) (void)x

struct elt {
    void *data; //vapi_payload structure
    struct elt *next;
    int id; //id of the stack element to count total nb of elements
};

static inline hicn_error_e push(struct elt **stack, void *data, int length)
{
    struct elt *el;

    //new stack node
    el = malloc(sizeof(struct elt));
    if (!el)
        return -HICN_ENOMEM;
    el->data = malloc(length);
    if (!el->data)
        return -HICN_ENOMEM;

    memcpy(el->data, data, length);
    if (*stack)
        el->id = (*stack)->id++;
    else
        el->id = 0;
    el->next = *stack; //point to old value of stack
    *stack = el; //el is new stack head

    return HICN_OK;
}

static inline void * pop(struct elt **stack)
{
    struct elt *prev;
    void *data;

    if (!(*stack))
        return NULL;

    data = (*stack)->data; //get data at stack head
    prev = *stack; //save stack to free memory later
    *stack = (*stack)->next; //new stack

    free(prev);
    prev = NULL;

    return data;
}

#endif //__STACK_H__