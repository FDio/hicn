#ifndef HICNCTRL_MODULE_HICNLIGHT_FACE
#define HICNCTRL_MODULE_HICNLIGHT_FACE

#include <hicn/ctrl/objects/connection.h>
#include <hicn/ctrl/objects/face.h>

int hc_face_from_connection(const hc_connection_t *connection, hc_face_t *face);

int hc_face_to_connection(const hc_face_t *face, hc_connection_t *connection,
                          bool generate_name);

int hc_face_to_listener(const hc_face_t *face, hc_listener_t *listener);

#endif /* HICNCTRL_MODULES_HICNLIGHT_FACE */
