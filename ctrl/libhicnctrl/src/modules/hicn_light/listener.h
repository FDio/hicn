#ifndef HICNCTRL_MODULE_HICNLIGHT_LISTENER_H
#define HICNCTRL_MODULE_HICNLIGHT_LISTENER_H

#include "../../module.h"

#if 1
DECLARE_MODULE_OBJECT_OPS_H(hicnlight, listener);
#else

int _hicnlight_listener_parse(const uint8_t *buffer, size_t size,
                              hc_object_t *object);

int hicnlight_listener_serialize_create(const hc_object_t *object,
                                        uint8_t *packet);
int hicnlight_listener_serialize_delete(const hc_object_t *object,
                                        uint8_t *packet);
int hicnlight_listener_serialize_list(const hc_object_t *object,
                                      uint8_t *packet);
#endif

#endif /* HICNCTRL_MODULE_HICNLIGHT_LISTENER_H */
