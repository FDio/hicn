/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
 * \file route.h
 * \brief Route.
 */

#ifndef HICNCTRL_IMPL_OBJECTS_ROUTE_H
#define HICNCTRL_IMPL_OBJECTS_ROUTE_H

#include "../object_vft.h"

bool hc_route_has_face(const hc_route_t* route);

DECLARE_OBJECT_OPS_H(OBJECT_TYPE_ROUTE, route);

#endif /* HICNCTRL_IMPL_OBJECTS_ROUTE_H */
