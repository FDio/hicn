#ifndef HICNCTRL_MODULE_HICNLIGHT_CONNECTION_H
#define HICNCTRL_MODULE_HICNLIGHT_CONNECTION_H

#include "../../module.h"

int hc_connection_to_local_listener(const hc_connection_t *connection,
                                    hc_listener_t *listener);

DECLARE_MODULE_OBJECT_OPS_H(hicnlight, connection);

#endif /* HICNCTRL_MODULE_HICNLIGHT_CONNECTION_H */
