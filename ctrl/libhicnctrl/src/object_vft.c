#include "object_vft.h"

#include "objects/listener.h"
#include "objects/connection.h"
#include "objects/route.h"
#include "objects/face.h"
#include "objects/strategy.h"
#include "objects/subscription.h"
#include "objects/active_interface.h"

const hc_object_ops_t *object_vft[] = {
    [OBJECT_TYPE_LISTENER] = &hc_listener_ops,
    [OBJECT_TYPE_CONNECTION] = &hc_connection_ops,
    [OBJECT_TYPE_ROUTE] = &hc_route_ops,
    [OBJECT_TYPE_FACE] = &hc_face_ops,
    [OBJECT_TYPE_STRATEGY] = &hc_strategy_ops,
    [OBJECT_TYPE_SUBSCRIPTION] = &hc_subscription_ops,
    [OBJECT_TYPE_ACTIVE_INTERFACE] = &hc_active_interface_ops,
};
