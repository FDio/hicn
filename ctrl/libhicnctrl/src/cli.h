#include <hicn/ctrl.h>

typedef int (*command_function)(hc_sock_t *, hc_command_t *);
extern command_function command_vft[][ACTION_N];
