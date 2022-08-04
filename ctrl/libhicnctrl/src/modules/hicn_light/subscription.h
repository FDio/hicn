#ifndef HICNCTRL_MODULE_HICNLIGHT_SUBSCRIPTION_H
#define HICNCTRL_MODULE_HICNLIGHT_SUBSCRIPTION_H

#include "../../module.h"

#if 1

DECLARE_MODULE_OBJECT_OPS_H(hicnlight, subscription);

#else

int _hicnlight_subscription_parse(const uint8_t *buffer, size_t size,
                                  hc_object_t *object);

int hicnlight_subscription_serialize_create(const hc_object_t *object,
                                            uint8_t *packet);

int hicnlight_subscription_serialize_delete(const hc_object_t *object,
                                            uint8_t *packet);

int hicnlight_subscription_serialize_list(const hc_object_t *object,
                                          uint8_t *packet);

#endif

#endif /* HICNCTRL_MODULE_HICNLIGHT_SUBSCRIPTION_H */
