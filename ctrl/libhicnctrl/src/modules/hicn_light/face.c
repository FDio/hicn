#include <hicn/ctrl/objects/listener.h>
#include <hicn/util/log.h>

#include "base.h"
#include "face.h"

int hc_face_from_connection(const hc_connection_t *connection,
                            hc_face_t *face) {
  int rc;
  switch (connection->type) {
    case FACE_TYPE_TCP:
      *face = (hc_face_t){
          .id = connection->id,
          .type = FACE_TYPE_TCP,
          .family = connection->family,
          .local_addr = connection->local_addr,
          .local_port = connection->local_port,
          .remote_addr = connection->remote_addr,
          .remote_port = connection->remote_port,
          .admin_state = connection->admin_state,
          .state = connection->state,
          .priority = connection->priority,
          .tags = connection->tags,
      };
      break;
    case FACE_TYPE_UDP:
      *face = (hc_face_t){
          .id = connection->id,
          .type = FACE_TYPE_UDP,
          .family = connection->family,
          .local_addr = connection->local_addr,
          .local_port = connection->local_port,
          .remote_addr = connection->remote_addr,
          .remote_port = connection->remote_port,
          .admin_state = connection->admin_state,
          .state = connection->state,
          .priority = connection->priority,
          .tags = connection->tags,
      };
      break;
    case FACE_TYPE_HICN:
      *face = (hc_face_t){
          .id = connection->id,
          .type = FACE_TYPE_HICN,
          .family = connection->family,
          .netdevice.index = NETDEVICE_UNDEFINED_INDEX,  // XXX
          .local_addr = connection->local_addr,
          .remote_addr = connection->remote_addr,
          .admin_state = connection->admin_state,
          .state = connection->state,
          .priority = connection->priority,
          .tags = connection->tags,
      };
      break;
    default:
      return -1;
  }
  face->netdevice.name[0] = '\0';
  face->netdevice.index = 0;
  rc = snprintf(face->name, SYMBOLIC_NAME_LEN, "%s", connection->name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[hc_connection_to_face] Unexpected truncation of symbolic name "
        "string");
  rc = snprintf(face->netdevice.name, INTERFACE_LEN, "%s",
                connection->interface_name);
  if (rc >= INTERFACE_LEN)
    WARN(
        "[hc_connection_to_face] Unexpected truncation of interface name "
        "string");
  netdevice_update_index(&face->netdevice);
  return 0;
}

int hc_face_to_connection(const hc_face_t *face, hc_connection_t *connection,
                          bool generate_name) {
  int rc;

  switch (face->type) {
    case FACE_TYPE_HICN:
      *connection = (hc_connection_t){
          .type = FACE_TYPE_HICN,
          .family = face->family,
          .local_addr = face->local_addr,
          .local_port = 0,
          .remote_addr = face->remote_addr,
          .remote_port = 0,
          .admin_state = face->admin_state,
          .state = face->state,
          .priority = face->priority,
          .tags = face->tags,
      };
      rc = snprintf(connection->name, SYMBOLIC_NAME_LEN, "%s",
                    face->netdevice.name);
      if (rc >= SYMBOLIC_NAME_LEN)
        WARN(
            "[hc_face_to_connection] Unexpected truncation of symbolic "
            "name string");
      break;
    case FACE_TYPE_TCP:
      *connection = (hc_connection_t){
          .type = FACE_TYPE_TCP,
          .family = face->family,
          .local_addr = face->local_addr,
          .local_port = face->local_port,
          .remote_addr = face->remote_addr,
          .remote_port = face->remote_port,
          .admin_state = face->admin_state,
          .state = face->state,
          .priority = face->priority,
          .tags = face->tags,
      };
      if (generate_name) {
        rc = snprintf(connection->name, SYMBOLIC_NAME_LEN, "tcp%u", RANDBYTE());
        if (rc >= SYMBOLIC_NAME_LEN)
          WARN(
              "[hc_face_to_connection] Unexpected truncation of "
              "symbolic name string");
      } else {
        memset(connection->name, 0, SYMBOLIC_NAME_LEN);
      }
      break;
    case FACE_TYPE_UDP:
      *connection = (hc_connection_t){
          .type = FACE_TYPE_UDP,
          .family = face->family,
          .local_addr = face->local_addr,
          .local_port = face->local_port,
          .remote_addr = face->remote_addr,
          .remote_port = face->remote_port,
          .admin_state = face->admin_state,
          .state = face->state,
          .priority = face->priority,
          .tags = face->tags,
      };
      if (generate_name) {
        rc = snprintf(connection->name, SYMBOLIC_NAME_LEN, "udp%u", RANDBYTE());
        if (rc >= SYMBOLIC_NAME_LEN)
          WARN(
              "[hc_face_to_connection] Unexpected truncation of "
              "symbolic name string");
      } else {
        memset(connection->name, 0, SYMBOLIC_NAME_LEN);
      }
      snprintf(connection->interface_name, INTERFACE_LEN, "%s",
               face->netdevice.name);
      break;
    default:
      return -1;
  }

  connection->id = face->id;
  rc = snprintf(connection->interface_name, INTERFACE_LEN, "%s",
                face->netdevice.name);
  if (rc >= INTERFACE_LEN)
    WARN(
        "hc_face_to_connection] Unexpected truncation of interface name "
        "string");

  return 0;
}

int hc_face_to_listener(const hc_face_t *face, hc_listener_t *listener) {
  switch (face->type) {
    case FACE_TYPE_HICN_LISTENER:
      break;
    case FACE_TYPE_TCP_LISTENER:
      break;
    case FACE_TYPE_UDP_LISTENER:
      break;
    default:
      return -1;
  }
  return -1; /* XXX Not implemented */
}
