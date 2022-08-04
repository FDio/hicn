#ifndef HICNCTRL_MODULE_HICNLIGHT_STRATEGY_H
#define HICNCTRL_MODULE_HICNLIGHT_STRATEGY_H

#include "../../module.h"

#if 1

DECLARE_MODULE_OBJECT_OPS_H(hicnlight, strategy);

int _hicnlight_strategy_parse(const uint8_t *buffer, size_t size,
                              hc_object_t *object);

int hicnlight_strategy_serialize_create(const hc_object_t *object,
                                        uint8_t *packet);

int hicnlight_strategy_serialize_delete(const hc_object_t *object,
                                        uint8_t *packet);

int hicnlight_strategy_serialize_list(const hc_object_t *object,
                                      uint8_t *packet);

#endif

#endif /* HICNCTRL_MODULE_HICNLIGHT_STRATEGY_H */
