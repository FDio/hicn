#include "error.h"

const char* HICN_SOCKET_ERROR_STRING[] = {
#define _(a, b, c) [b] = c,
    foreach_hicn_socket_error
#undef _
};
