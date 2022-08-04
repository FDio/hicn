#ifndef HICNCTRL_MODULE_HICNLIGHT_CONNECTION_H
#define HICNCTRL_MODULE_HICNLIGHT_CONNECTION_H

#include "../../module.h"

int hc_connection_to_local_listener(const hc_connection_t *connection,
                                    hc_listener_t *listener);

#if 1

DECLARE_MODULE_OBJECT_OPS_H(hicnlight, connection);
// extern const hc_module_object_ops_t hicnlight_connection_module_ops;

#else

int _hicnlight_connection_parse(const uint8_t *buffer, size_t size,
                                hc_object_t *object);

int hicnlight_connection_serialize_create(const hc_object_t *object,
                                          uint8_t *packet);
int hicnlight_connection_serialize_delete(const hc_object_t *object,
                                          uint8_t *packet);
int hicnlight_connection_serialize_list(const hc_object_t *object,
                                        uint8_t *packet);

#endif
#endif /* HICNCTRL_MODULE_HICNLIGHT_CONNECTION_H */
