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
 * \file modules/hicn_plugin/route.c
 * \brief Implementation of route object VFT for hicn_plugin.
 */

#include "base.h"
#include "route.h"

static vapi_error_e create_udp_tunnel_cb(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_udp_tunnel_add_del_reply *reply) {
  if (reply == NULL || rv != VAPI_OK) return rv;

  if (reply->retval != VAPI_OK) return reply->retval;

  u32 *uei = (u32 *)callback_ctx;
  *uei = reply->uei;

  return reply->retval;
}

static vapi_error_e parse_route_create(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_ip_route_add_del_reply *reply) {
  if (reply == NULL || rv != VAPI_OK) return rv;

  if (reply->retval != VAPI_OK) return reply->retval;

  return reply->retval;
}

static vapi_error_e hicn_enable_cb(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_enable_disable_reply *reply) {
  if (reply == NULL || rv != VAPI_OK) return rv;
  face_id_t *faceid = (face_id_t *)callback_ctx;

  if (reply->nfaces) {
    *faceid = reply->faceids[0];
  }

  return reply->retval;
}

static int _vpp_route_create(hc_sock_t *sock, hc_route_t *route) {
  if (!IS_VALID_FAMILY(route->family)) return -1;

  hc_sock_vpp_data_t *s = (hc_sock_vpp_data_t *)sock->data;
  int ret = -1;
  vapi_lock();

  vapi_msg_ip_route_add_del *msg =
      vapi_alloc_ip_route_add_del(s->g_vapi_ctx_instance, 1);

  msg->payload.is_add = 1;
  if (route->family == AF_INET) {
    memcpy(&msg->payload.route.prefix.address.un.ip4[0], &route->remote_addr.v4,
           4);
    msg->payload.route.prefix.address.af = ADDRESS_IP4;
    msg->payload.route.paths[0].proto = FIB_API_PATH_NH_PROTO_IP4;
  } else {
    memcpy(&msg->payload.route.prefix.address.un.ip6[0], &route->remote_addr.v6,
           16);
    msg->payload.route.prefix.address.af = ADDRESS_IP6;
    msg->payload.route.paths[0].proto = FIB_API_PATH_NH_PROTO_IP6;
  }

  msg->payload.route.prefix.len = route->len;

  msg->payload.route.paths[0].sw_if_index = ~0;
  msg->payload.route.paths[0].table_id = 0;

  hc_face_t *face = &(route->face);

  face->netdevice.index = ~0;
  face->id = INVALID_FACE_ID;

  switch (face->type) {
    case FACE_TYPE_HICN: {
      if (hicn_ip_address_is_v4(&(face->remote_addr))) {
        memcpy(&(msg->payload.route.paths[0].nh.address.ip4),
               &face->remote_addr.v4, sizeof(ip4_address_t));
        msg->payload.route.paths[0].proto = FIB_API_PATH_NH_PROTO_IP4;
      } else {
        memcpy(&(msg->payload.route.paths[0].nh.address.ip6),
               &face->remote_addr.v6, sizeof(ip6_address_t));
        msg->payload.route.paths[0].proto = FIB_API_PATH_NH_PROTO_IP6;
      }

      msg->payload.route.paths[0].type = FIB_API_PATH_TYPE_NORMAL;
      msg->payload.route.paths[0].flags = FIB_API_PATH_FLAG_NONE;

      break;
    }
    case FACE_TYPE_UDP: {
      vapi_msg_hicn_api_udp_tunnel_add_del *msg2 = NULL;
      u32 uei = ~0;

      if (hicn_ip_address_is_v4(&(face->remote_addr)) &&
          hicn_ip_address_is_v4(&(face->local_addr))) {
        msg2 = vapi_alloc_hicn_api_udp_tunnel_add_del(s->g_vapi_ctx_instance);
        memcpy(msg2->payload.src_addr.un.ip4, &face->local_addr.v4,
               sizeof(ip4_address_t));
        msg2->payload.src_addr.af = ADDRESS_IP4;

        memcpy(msg2->payload.dst_addr.un.ip4, &face->remote_addr.v4,
               sizeof(ip4_address_t));
        msg2->payload.dst_addr.af = ADDRESS_IP4;

      } else if (!hicn_ip_address_is_v4(&(route->face.remote_addr)) &&
                 !hicn_ip_address_is_v4(&(route->face.local_addr))) {
        msg2 = vapi_alloc_hicn_api_udp_tunnel_add_del(s->g_vapi_ctx_instance);
        memcpy(msg2->payload.src_addr.un.ip6, &face->local_addr.v6,
               sizeof(ip6_address_t));
        msg2->payload.src_addr.af = ADDRESS_IP6;

        memcpy(msg2->payload.dst_addr.un.ip6, &face->remote_addr.v6,
               sizeof(ip6_address_t));
        msg2->payload.dst_addr.af = ADDRESS_IP6;
      } else {
        // NOT IMPLEMENTED
        ret = -1;
        goto done;
      }

      msg2->payload.src_port = face->local_port;
      msg2->payload.dst_port = face->remote_port;
      msg2->payload.is_add = 1;

      int ret = vapi_hicn_api_udp_tunnel_add_del(s->g_vapi_ctx_instance, msg2,
                                                 create_udp_tunnel_cb, &uei);

      if (ret) {
        ERROR("Error in vapi_hicn_api_udp_tunnel_add_del");
        vapi_msg_free(s->g_vapi_ctx_instance, msg);
        goto done;
      }

      msg->payload.route.paths[0].type = FIB_API_PATH_TYPE_UDP_ENCAP;
      msg->payload.route.paths[0].flags = FIB_API_PATH_FLAG_NONE;
      msg->payload.route.paths[0].nh.obj_id = uei;

      face->netdevice.index = uei;

      break;
    }
    default:
      ret = -1;
      goto done;
  }

  ret = vapi_ip_route_add_del(s->g_vapi_ctx_instance, msg, parse_route_create,
                              NULL);

  if (ret) {
    ERROR("Error in vapi_ip_route_add_del");
    goto done;
  }

  vapi_msg_hicn_api_enable_disable *msg3 =
      vapi_alloc_hicn_api_enable_disable(s->g_vapi_ctx_instance);

  if (route->family == AF_INET) {
    memcpy(&msg3->payload.prefix.address.un.ip4[0], &route->remote_addr.v4, 4);
    msg3->payload.prefix.address.af = ADDRESS_IP4;
  } else {
    memcpy(&msg3->payload.prefix.address.un.ip6[0], &route->remote_addr.v6, 16);
    msg3->payload.prefix.address.af = ADDRESS_IP6;
  }

  msg3->payload.prefix.len = route->len;
  msg3->payload.enable_disable = 1;

  ret = vapi_hicn_api_enable_disable(s->g_vapi_ctx_instance, msg3,
                                     hicn_enable_cb, &face->id);

  if (ret) {
    ERROR("Error in vapi_hicn_api_enable_disable");
  }

done:
  vapi_unlock();
  return ret;
}

static vapi_error_e hicn_disable_cb(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_enable_disable_reply *reply) {
  if (reply == NULL || rv != VAPI_OK) return rv;

  return reply->retval;
}

static vapi_error_e parse_route_delete(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_ip_route_add_del_reply *reply) {
  if (reply == NULL || rv != VAPI_OK) return rv;

  return reply->retval;
}

static int _vpp_route_delete(hc_sock_t *sock, hc_route_t *route) {
  if (!IS_VALID_FAMILY(route->family)) return -1;

  hc_sock_vpp_data_t *s = (hc_sock_vpp_data_t *)sock->data;

  vapi_lock();

  vapi_msg_hicn_api_enable_disable *msg =
      vapi_alloc_hicn_api_enable_disable(s->g_vapi_ctx_instance);

  if (route->family == AF_INET) {
    memcpy(&msg->payload.prefix.address.un.ip4[0], &route->remote_addr.v4, 4);
    msg->payload.prefix.address.af = ADDRESS_IP4;
  } else {
    memcpy(&msg->payload.prefix.address.un.ip6[0], &route->remote_addr.v6, 16);
    msg->payload.prefix.address.af = ADDRESS_IP6;
  }

  msg->payload.prefix.len = route->len;
  msg->payload.enable_disable = 0;

  vapi_error_e ret = vapi_hicn_api_enable_disable(s->g_vapi_ctx_instance, msg,
                                                  hicn_disable_cb, NULL);

  if (ret) {
    ERROR("Error in vapi_hicn_api_enable_disable in route delete");
    goto done;
  }

  vapi_msg_ip_route_add_del *msg2 =
      vapi_alloc_ip_route_add_del(s->g_vapi_ctx_instance, 1);

  msg2->payload.is_add = 0;
  if (route->family == AF_INET) {
    memcpy(&msg2->payload.route.prefix.address.un.ip4[0],
           &route->remote_addr.v4, 4);
    msg2->payload.route.prefix.address.af = ADDRESS_IP4;
  } else {
    memcpy(&msg2->payload.route.prefix.address.un.ip6[0],
           &route->remote_addr.v6, 16);
    msg2->payload.route.prefix.address.af = ADDRESS_IP6;
  }

  msg2->payload.route.prefix.len = route->len;

  msg2->payload.route.paths[0].sw_if_index = ~0;
  msg2->payload.route.paths[0].table_id = 0;

  hc_face_t *face = &(route->face);
  switch (face->type) {
    case FACE_TYPE_HICN: {
      if (hicn_ip_address_is_v4(&(face->remote_addr))) {
        memcpy(&(msg2->payload.route.paths[0].nh.address.ip4),
               &face->remote_addr.v4, sizeof(ip4_address_t));
        msg2->payload.route.paths[0].proto = FIB_API_PATH_NH_PROTO_IP4;
      } else {
        memcpy(&(msg2->payload.route.paths[0].nh.address.ip6),
               &face->remote_addr.v6, sizeof(ip6_address_t));
        msg2->payload.route.paths[0].proto = FIB_API_PATH_NH_PROTO_IP6;
      }

      msg2->payload.route.paths[0].type = FIB_API_PATH_TYPE_NORMAL;
      msg2->payload.route.paths[0].flags = FIB_API_PATH_FLAG_NONE;

      break;
    }
    case FACE_TYPE_UDP: {
      msg2->payload.route.paths[0].type = FIB_API_PATH_TYPE_UDP_ENCAP;
      msg2->payload.route.paths[0].flags = FIB_API_PATH_FLAG_NONE;
      msg2->payload.route.paths[0].nh.obj_id = face->netdevice.index;
      break;
    }
    default:
      return -1;
  }

  ret = vapi_ip_route_add_del(s->g_vapi_ctx_instance, msg2, parse_route_delete,
                              NULL);

  if (ret) {
    ERROR("Error in vapi_ip_route_add_del in route delete");
    goto done;
  }

done:

  vapi_unlock();
  return ret;
}

/* ROUTE LIST */

static vapi_error_e parse_udp_encap_list(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_udp_encap_details *reply) {
  if (reply == NULL || rv != VAPI_OK) return rv;

  hc_face_t *face = (hc_face_t *)callback_ctx;

  if (face->netdevice.index == reply->udp_encap.id) {
    switch (reply->udp_encap.src_ip.af) {
      case ADDRESS_IP4: {
        memcpy(&face->local_addr.v4, &(reply->udp_encap.src_ip.un.ip4),
               sizeof(ip4_address_t));
        memcpy(&face->remote_addr.v4, &(reply->udp_encap.dst_ip.un.ip4),
               sizeof(ip4_address_t));
        break;
      }
      case ADDRESS_IP6: {
        memcpy(&face->local_addr.v6, &(reply->udp_encap.src_ip.un.ip6),
               sizeof(ip6_address_t));
        memcpy(&face->remote_addr.v6, &(reply->udp_encap.dst_ip.un.ip6),
               sizeof(ip6_address_t));
        break;
      }
      default:
        break;
    }

    face->local_port = reply->udp_encap.src_port;
    face->remote_port = reply->udp_encap.dst_port;
  }
  return rv;
}

static int _fill_face_with_info(hc_face_t *face, vapi_type_fib_path *path) {
  switch (path->type) {
    case FIB_API_PATH_FLAG_NONE: {
      face->type = FACE_TYPE_HICN;
      switch (path->proto) {
        case FIB_API_PATH_NH_PROTO_IP4:
          memcpy(&face->remote_addr.v4, &(path->nh.address.ip4),
                 sizeof(ipv4_address_t));
          break;
        case FIB_API_PATH_NH_PROTO_IP6:
          memcpy(&face->remote_addr.v6, &(path->nh.address.ip6),
                 sizeof(ipv6_address_t));
          break;
        default:
          break;
      }
      face->netdevice.index = path->sw_if_index;
    } break;
    case FIB_API_PATH_TYPE_UDP_ENCAP: {
      face->type = FACE_TYPE_UDP;
      face->netdevice.index = clib_net_to_host_u32(path->nh.obj_id);
      // Let's make the compiler happy
      (void)parse_udp_encap_list;
      // vapi_msg_udp_encap_dump *msg;
      // msg = vapi_alloc_udp_encap_dump(s->g_vapi_ctx_instance);
      // vapi_udp_encap_dump(s->g_vapi_ctx_instance, msg, parse_udp_encap_list,
      // face);
    } break;
    default:
      return -1;
  }
  return 0;
}

static vapi_error_e parse_route_list(vapi_ctx_t ctx, void *callback_ctx,
                                     vapi_error_e rv, bool is_last,
                                     vapi_payload_ip_route_details *reply) {
  if (reply == NULL || rv != VAPI_OK) return rv;

  // XXX DEBUG XXX
  if (reply && is_last) printf("COUCOU\n");

  if (is_last) return 0;

  hc_data_t *data = (hc_data_t *)callback_ctx;

  /*
   * Implementation:
   * A route has n paths... we iterate for each path and search for a
   * corresponding face in the hc_data_t result struct... and we fill the face
   * info with the route path.
   *
   * TODO
   *  - comment on paths
   *  - explain the jump to END, this was previously implemented with a
   * boolean flags skipping all remaining tests in the function...
   */
  for (int j = 0; j < reply->route.n_paths; j++) {
    hc_data_foreach(data, obj, {
      hc_route_t *route = &obj->route;

      if (hicn_ip_address_is_v4(&(route->remote_addr)) &&
          memcmp(route->remote_addr.v4.as_u8,
                 reply->route.prefix.address.un.ip4,
                 sizeof(ipv4_address_t)) == 0 &&
          route->len == reply->route.prefix.len && route->face_id == ~0) {
        _fill_face_with_info(&(route->face), &reply->route.paths[j]);
        goto END;

      } else if (memcmp(route->remote_addr.v6.as_u8,
                        reply->route.prefix.address.un.ip6,
                        sizeof(ipv6_address_t)) == 0 &&
                 route->len == reply->route.prefix.len &&
                 route->face_id == ~0) {
        _fill_face_with_info(&(route->face), &reply->route.paths[j]);
        goto END;
      }
    });
  }

END:
  return rv;
}

/**
 * Populates the hc_data_t structure passed as the context with...
 */
static vapi_error_e parse_hicn_route_list(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_routes_details *reply) {
  if (reply == NULL || rv != VAPI_OK) return rv;

  if (reply && is_last) printf("COUCOU\n");
  if (is_last) return 0;

  hc_data_t *data = (hc_data_t *)callback_ctx;

  for (int i = 0; i < reply->nfaces; i++) {
    hc_route_t route;
    memset(&route, 0, sizeof(hc_route_t));

    /*
     * We set the face_id to ~0 to act as a marker in parse_route_list that
     * the route is missing face information.
     */
    route.face_id = ~0;
    route.cost = 1;
    route.len = reply->prefix.len;
    if (reply->prefix.address.af == ADDRESS_IP6) {
      memcpy(route.remote_addr.v6.as_u8, reply->prefix.address.un.ip6, 16);
      route.family = AF_INET6;
    } else {
      memcpy(route.remote_addr.v4.as_u8, reply->prefix.address.un.ip4, 4);
      route.family = AF_INET;
    }

    hc_data_push(data, &route);
  }

  return rv;
}

/*
 * hicn_api_routes_dump
 * ip_route_dump
 *
 * @returns hc_data_t<hc_route_t>
 */
static int _vpp_route_list(hc_sock_t *sock, hc_data_t *data) {
  int ret;
  hc_sock_vpp_data_t *s = (hc_sock_vpp_data_t *)sock->data;

  vapi_lock();

  /* Start by retrieving hicn routes (we have no face information at this
   * stage)... */
  vapi_msg_hicn_api_routes_dump *msg;
  msg = vapi_alloc_hicn_api_routes_dump(s->g_vapi_ctx_instance);
  if (!msg) goto ERR_MSG;

  ret = vapi_hicn_api_routes_dump(s->g_vapi_ctx_instance, msg,
                                  parse_hicn_route_list, data);
  if (ret != VAPI_OK) goto ERR_API;

  /*
   * ... an complement them using IP (v4 and v6 routes). Similar routes will
   * be aggregated, based on IP prefix, in parse_*_route_list.
   */
  vapi_msg_ip_route_dump *msg2;
  for (unsigned i = 0; i < 2; i++) {
    msg2 = vapi_alloc_ip_route_dump(s->g_vapi_ctx_instance);
    if (!msg2) goto ERR_MSG;

    msg2->payload.table.table_id = 0;
    msg2->payload.table.is_ip6 = i;

    ret = vapi_ip_route_dump(s->g_vapi_ctx_instance, msg2, parse_route_list,
                             data);
    if (ret != VAPI_OK) goto ERR_API;
  }

  goto END;

ERR_MSG:
  ret = VAPI_ENOMEM;
  goto END;

ERR_API:
END:
  vapi_unlock();
  return ret;
}

static int vpp_route_create(hc_sock_t *sock, hc_object_t *object,
                            hc_data_t *data) {
  int rc = _vpp_route_create(sock, &object->route);
  if (rc < 0)
    hc_data_set_complete(data);
  else
    hc_data_set_error(data);
  return rc;
}

static int vpp_route_delete(hc_sock_t *sock, hc_object_t *object,
                            hc_data_t *data) {
  int rc = _vpp_route_delete(sock, &object->route);
  if (rc < 0)
    hc_data_set_complete(data);
  else
    hc_data_set_error(data);
  return rc;
}

static int vpp_route_list(hc_sock_t *sock, hc_object_t *object,
                          hc_data_t *data) {
  assert(!object || hc_object_is_empty(object));
  return _vpp_route_list(sock, data);
}

DECLARE_VPP_MODULE_OBJECT_OPS(vpp, route);
