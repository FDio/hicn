#include <hicn/ctrl/api.h>
#include <hicn/ctrl/cli.h>

typedef int (*hc_object_snprintf_type)(char*, size_t, uint8_t*);

static const hc_object_snprintf_type map_object_snprintf[] = {
    [OBJECT_CONNECTION] = (hc_object_snprintf_type)hc_connection_snprintf,
    [OBJECT_LISTENER] = (hc_object_snprintf_type)hc_listener_snprintf,
    [OBJECT_ROUTE] = (hc_object_snprintf_type)hc_route_snprintf,
    [OBJECT_FACE] = (hc_object_snprintf_type)hc_face_snprintf,
    [OBJECT_STRATEGY] = (hc_object_snprintf_type)hc_strategy_snprintf,
    [OBJECT_POLICY] = (hc_object_snprintf_type)hc_policy_snprintf,
    [OBJECT_PUNTING] = (hc_object_snprintf_type)hc_punting_snprintf,
};

int
hc_object_type_snprintf(char * buffer, size_t size, hc_object_type_t type, uint8_t * data)
{
    return map_object_snprintf[type](buffer, size, data);
}

int
hc_object_snprintf(char * buffer, size_t size, hc_object_t * object)
{
    // XXX assert valid object
    return hc_object_type_snprintf(buffer, size, object->type, &object->as_uint8);
#if 0
    switch(object->type) {
        case OBJECT_CONNECTION:
            return hc_connection_snprintf(buffer, size, &object->connection);
        case OBJECT_LISTENER:
            return hc_listener_snprintf(buffer, size, &object->listener);
        case OBJECT_ROUTE:
            return hc_route_snprintf(buffer, size, &object->route);
        case OBJECT_FACE:
            return hc_face_snprintf(buffer, size, &object->face);
        case OBJECT_STRATEGY:
            return hc_strategy_snprintf(buffer, size, &object->strategy);
        case OBJECT_POLICY:
            return hc_policy_snprintf(buffer, size, &object->policy);
        case OBJECT_PUNTING:
            return hc_punting_snprintf(buffer, size, &object->punting);
        case OBJECT_UNDEFINED:
        case OBJECT_N:
        default:
            return -1;
    }
#endif
}
