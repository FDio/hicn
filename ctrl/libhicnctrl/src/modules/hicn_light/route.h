/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * \file modules/hicn_light/route.h
 * \brief route object VFT for hicn_light.
 */

#ifndef HICNCTRL_MODULE_HICNLIGHT_ROUTE_H
#define HICNCTRL_MODULE_HICNLIGHT_ROUTE_H

#include "../../module.h"

#if 1

DECLARE_MODULE_OBJECT_OPS_H(hicnlight, route);

#else

int _hicnlight_route_parse(const uint8_t *buffer, size_t size,
                           hc_object_t *object);
int hicnlight_route_serialize_create(const hc_object_t *object,
                                     uint8_t *packet);
int hicnlight_route_serialize_delete(const hc_object_t *object,
                                     uint8_t *packet);
int hicnlight_route_serialize_list(const hc_object_t *object, uint8_t *packet);

#endif

#endif /* HICNCTRL_MODULE_HICNLIGHT_ROUTE_H */
