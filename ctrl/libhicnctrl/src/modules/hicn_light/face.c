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

#if 0
/*----------------------------------------------------------------------------*
 * Face
 *
 * Face support is not directly available in hicn-light, but we can offer such
 * an interface through a combination of listeners and connections. The code
 * starts with some conversion functions between faces/listeners/connections.
 *
 * We also need to make sure that there always exist a (single) listener when
 *a connection is created, and in the hICN face case, that there is a single
 * connection attached to this listener.
 *
 *----------------------------------------------------------------------------*/

/* FACE CREATE */

static int _hcng_face_create(hc_sock_t *socket, hc_face_t *face) {
#if 0
  hc_listener_t listener;
  hc_listener_t *listener_found;

  hc_connection_t connection;
  hc_connection_t *connection_found;

  char face_s[MAXSZ_HC_FACE];
  int rc = hc_face_snprintf(face_s, MAXSZ_HC_FACE, face);
  if (rc >= MAXSZ_HC_FACE)
    WARN("[hc_face_create] Unexpected truncation of face string");
  DEBUG("[hc_face_create] face=%s", face_s);

  switch (face->face.type) {
    case FACE_TYPE_HICN:
    case FACE_TYPE_TCP:
    case FACE_TYPE_UDP:
      if (hc_face_to_connection(face, &connection, true) < 0) {
        ERROR("[hc_face_create] Could not convert face to connection.");
        return -1;
      }

      /* Ensure we have a corresponding local listener */
      if (hc_connection_to_local_listener(&connection, &listener) < 0) {
        ERROR("[hc_face_create] Could not convert face to local listener.");
        return -1;
      }

      if (_hcng_listener_get(socket, &listener, &listener_found) < 0) {
        ERROR("[hc_face_create] Could not retrieve listener");
        return -1;
      }

      if (!listener_found) {
        /* We need to create the listener if it does not exist */
        if (hc_listener_create(socket, &listener) < 0) {
          ERROR("[hc_face_create] Could not create listener.");
          free(listener_found);
          return -1;
        }
      } else {
        free(listener_found);
      }

      /* Create corresponding connection */
      if (_hcng_connection_create(socket, &connection) < 0) {
        ERROR("[hc_face_create] Could not create connection.");
        return -1;
      }

      /*
       * Once the connection is created, we need to list all connections
       * and compare with the current one to find the created face ID.
       */
      if (_hcng_connection_get(socket, &connection, &connection_found) < 0) {
        ERROR("[hc_face_create] Could not retrieve connection");
        return -1;
      }

      if (!connection_found) {
        ERROR("[hc_face_create] Could not find newly created connection.");
        return -1;
      }

      face->id = connection_found->id;
      free(connection_found);

      break;

    case FACE_TYPE_HICN_LISTENER:
    case FACE_TYPE_TCP_LISTENER:
    case FACE_TYPE_UDP_LISTENER:
      if (hc_face_to_listener(face, &listener) < 0) {
        ERROR("Could not convert face to listener.");
        return -1;
      }
      if (hc_listener_create(socket, &listener) < 0) {
        ERROR("[hc_face_create] Could not create listener.");
        return -1;
      }
      break;
    default:
      ERROR("[hc_face_create] Unknwon face type.");

      return -1;
  };

#endif
  return 0;
}

static int _hcng_face_get(hc_sock_t *socket, hc_face_t *face,
                          hc_face_t **face_found) {
#if 0
  hc_listener_t listener;
  hc_listener_t *listener_found;

  hc_connection_t connection;
  hc_connection_t *connection_found;

  char face_s[MAXSZ_HC_FACE];
  int rc = hc_face_snprintf(face_s, MAXSZ_HC_FACE, face);
  if (rc >= MAXSZ_HC_FACE)
    WARN("[hc_face_get] Unexpected truncation of face string");
  DEBUG("[hc_face_get] face=%s", face_s);

  switch (face->face.type) {
    case FACE_TYPE_HICN:
    case FACE_TYPE_TCP:
    case FACE_TYPE_UDP:
      if (hc_face_to_connection(face, &connection, false) < 0) return -1;
      if (_hcng_connection_get(socket, &connection, &connection_found) < 0)
        return -1;
      if (!connection_found) {
        *face_found = NULL;
        return 0;
      }
      *face_found = malloc(sizeof(hc_face_t));
      hc_connection_to_face(connection_found, *face_found);
      free(connection_found);
      break;

    case FACE_TYPE_HICN_LISTENER:
    case FACE_TYPE_TCP_LISTENER:
    case FACE_TYPE_UDP_LISTENER:
      if (hc_face_to_listener(face, &listener) < 0) return -1;
      if (_hcng_listener_get(socket, &listener, &listener_found) < 0) return -1;
      if (!listener_found) {
        *face_found = NULL;
        return 0;
      }
      *face_found = malloc(sizeof(hc_face_t));
      hc_listener_to_face(listener_found, *face_found);
      free(listener_found);
      break;

    default:
      return -1;
  }

#endif
  return 0;
}

/* FACE DELETE */

static int _hcng_face_delete(hc_sock_t *socket, hc_face_t *face,
                             uint8_t delete_listener) {
#if 0
  char face_s[MAXSZ_HC_FACE];
  int rc = hc_face_snprintf(face_s, MAXSZ_HC_FACE, face);
  if (rc >= MAXSZ_HC_FACE)
    WARN("[hc_face_delete] Unexpected truncation of face string");
  DEBUG("[hc_face_delete] face=%s", face_s);

  hc_connection_t connection;
  if (hc_face_to_connection(face, &connection, false) < 0) {
    ERROR("[hc_face_delete] Could not convert face to connection.");
    return -1;
  }

  if (_hcng_connection_delete(socket, &connection) < 0) {
    ERROR("[hc_face_delete] Error removing connection");
    return -1;
  }

  if (!delete_listener) {
    return 0;
  }

  /* If this is the last connection attached to the listener, remove it */

  hc_data_t *connections;
  hc_listener_t listener = {{0}};

  /*
   * Ensure we have a corresponding local listener
   * NOTE: hc_face_to_listener is not appropriate
   */
  if (hc_connection_to_local_listener(&connection, &listener) < 0) {
    ERROR("[hc_face_create] Could not convert face to local listener.");
    return -1;
  }
#if 1
  /*
   * The name is generated to prepare listener creation, we need it to be
   * empty for deletion. The id should not need to be reset though.
   */
  listener.id = 0;
  memset(listener.name, 0, sizeof(listener.name));
#endif
  if (_hcng_connection_list(socket, &connections) < 0) {
    ERROR("[hc_face_delete] Error getting the list of listeners");
    return -1;
  }

  bool delete = true;
  foreach_connection(c, connections) {
    if ((ip_address_cmp(&c->local_addr, &listener.local_addr, c->family) ==
         0) &&
        (c->local_port == listener.local_port) &&
        (strcmp(c->interface_name, listener.interface_name) == 0)) {
      delete = false;
    }
  }

  if (delete) {
    if (_hcng_listener_delete(socket, &listener) < 0) {
      ERROR("[hc_face_delete] Error removing listener");
      return -1;
    }
  }

  hc_data_free(connections);

#endif
  return 0;
}

/* FACE LIST */

static int _hcng_face_list(hc_sock_t *socket, hc_data_t **pdata) {
#if 0
  hc_data_t *connection_data;
  hc_face_t face;

  DEBUG("[hc_face_list]");

  if (_hcng_connection_list(socket, &connection_data) < 0) {
    ERROR("[hc_face_list] Could not list connections.");
    return -1;
  }

  hc_data_t *face_data =
      hc_data_create(sizeof(hc_connection_t), sizeof(hc_face_t), NULL);
  foreach_connection(c, connection_data) {
    if (hc_connection_to_face(c, &face) < 0) {
      ERROR("[hc_face_list] Could not convert connection to face.");
      goto ERR;
    }
    hc_data_push(face_data, &face);
  }

  *pdata = face_data;
  hc_data_free(connection_data);
  DEBUG("[hc_face_list] done");
  return 0;

ERR:
  hc_data_free(connection_data);
  DEBUG("[hc_face_list] error");
#endif
  return -1;
}

static int hc_connection_parse_to_face(void *in, hc_face_t *face) {
  hc_connection_t connection;

  if (hcng_connection_parse(in, &connection) < 0) {
    ERROR("[hc_connection_parse_to_face] Could not parse connection");
    return -1;
  }

  if (hc_connection_to_face(&connection, face) < 0) {
    ERROR(
        "[hc_connection_parse_to_face] Could not convert connection to "
        "face.");
    return -1;
  }

  return 0;
}

static int _hcng_face_set_admin_state(hc_sock_t *s, const char *conn_id_or_name,
                                      face_state_t admin_state) {
  return hc_connection_set_admin_state(s, conn_id_or_name, admin_state);
}

static int _hcng_face_set_priority(hc_sock_t *s, const char *conn_id_or_name,
                                   uint32_t priority) {
  return hc_connection_set_priority(s, conn_id_or_name, priority);
}

static int _hcng_face_set_tags(hc_sock_t *s, const char *conn_id_or_name,
                               policy_tags_t tags) {
  return hc_connection_set_tags(s, conn_id_or_name, tags);
}

#endif
