/*
 * Copyright (c) 2021-2023 Cisco and/or its affiliates.
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
 * \file object_vft.c
 * \brief Implementation of object VFT.
 */

#include "object_vft.h"

#include "objects/listener.h"
#include "objects/connection.h"
#include "objects/route.h"
#include "objects/face.h"
#include "objects/mapme.h"
#include "objects/stats.h"
#include "objects/strategy.h"
#include "objects/subscription.h"
#include "objects/active_interface.h"

const hc_object_ops_t *object_vft[] = {
    [OBJECT_TYPE_CONNECTION] = &hc_connection_ops,
    [OBJECT_TYPE_LISTENER] = &hc_listener_ops,
    [OBJECT_TYPE_ROUTE] = &hc_route_ops,
    [OBJECT_TYPE_FACE] = &hc_face_ops,
    [OBJECT_TYPE_STRATEGY] = &hc_strategy_ops,
    [OBJECT_TYPE_MAPME] = &hc_mapme_ops,
    [OBJECT_TYPE_SUBSCRIPTION] = &hc_subscription_ops,
    [OBJECT_TYPE_ACTIVE_INTERFACE] = &hc_active_interface_ops,
    [OBJECT_TYPE_STATS] = &hc_stats_ops,
    [OBJECT_TYPE_FACE_STATS] = &hc_face_stats_ops,
};
