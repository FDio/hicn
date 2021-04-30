/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <arpa/inet.h>
#include <hicn/http-proxy/forwarder_interface.h>
#include <hicn/transport/utils/log.h>

#include <chrono>
#include <iostream>
#include <thread>
#include <unordered_set>

namespace transport {

ForwarderInterface::~ForwarderInterface() {}

int ForwarderInterface::connectToForwarder() {
  sock_ = hc_sock_create();
  if (!sock_) return -1;

  if (hc_sock_connect(sock_) < 0) {
    hc_sock_free(sock_);
    sock_ = nullptr;
    return -1;
  }

  return 0;
}

void ForwarderInterface::close() {
  if (!closed_) {
    internal_ioservice_.post([this]() {
      work_.reset();
      if (sock_) {
        hc_sock_free(sock_);
        sock_ = nullptr;
      }
    });

    if (thread_->joinable()) {
      thread_->join();
    }
  }
}

void ForwarderInterface::removeConnectedUserNow(uint32_t route_id) {
  internalRemoveConnectedUser(route_id);
}

void ForwarderInterface::scheduleRemoveConnectedUser(uint32_t route_id) {
  internal_ioservice_.post(
      [this, route_id]() { internalRemoveConnectedUser(route_id); });
}

int32_t ForwarderInterface::getMainListenerPort() {
  if (!sock_) return -1;

  hc_data_t *data;
  if (hc_listener_list(sock_, &data) < 0) return -1;

  int ret = -1;
  foreach_listener(l, data) {
    std::string interface = std::string(l->interface_name);
    if (interface.compare("lo") != 0) {
      ret = l->local_port;
      break;
    }
  }

  hc_data_free(data);
  return ret;
}

void ForwarderInterface::internalRemoveConnectedUser(uint32_t route_id) {
  auto it = route_status_.find(route_id);
  if (it == route_status_.end()) return;

  if (!sock_) return;

  // remove route
  hc_data_t *data;
  if (hc_route_list(sock_, &data) < 0) return;

  std::vector<hc_route_t *> routes_to_remove;
  foreach_route(r, data) {
    char remote_addr[INET6_ADDRSTRLEN];
    int ret = ip_address_ntop(&r->remote_addr, remote_addr, r->len, r->family);
    if (ret < 0) continue;

    std::string route_addr(remote_addr);
    if (route_addr.compare(it->second->route_addr) == 0 &&
        r->len == it->second->route_len) {
      // route found
      routes_to_remove.push_back(r);
    }
  }

  route_status_.erase(it);

  if (routes_to_remove.size() == 0) {
    // nothing to do here
    hc_data_free(data);
    return;
  }

  std::unordered_set<uint32_t> connids_to_remove;
  for (unsigned i = 0; i < routes_to_remove.size(); i++) {
    connids_to_remove.insert(routes_to_remove[i]->face_id);
    if (hc_route_delete(sock_, routes_to_remove[i]) < 0) {
      TRANSPORT_LOGE("Error removing route from forwarder.");
    }
  }

  // remove connection
  if (hc_connection_list(sock_, &data) < 0) {
    hc_data_free(data);
    return;
  }

  // collects pointerst to the connections using the conn IDs
  std::vector<hc_connection_t *> conns_to_remove;
  foreach_connection(c, data) {
    if (connids_to_remove.find(c->id) != connids_to_remove.end()) {
      // conn found
      conns_to_remove.push_back(c);
    }
  }

  if (conns_to_remove.size() == 0) {
    // nothing else to do here
    hc_data_free(data);
    return;
  }

  for (unsigned i = 0; i < conns_to_remove.size(); i++) {
    if (hc_connection_delete(sock_, conns_to_remove[i]) < 0) {
      TRANSPORT_LOGE("Error removing connection from forwarder.");
    }
  }

  hc_data_free(data);
}

void ForwarderInterface::internalCreateFaceAndRoute(RouteInfoPtr route_info,
                                                    uint8_t max_try,
                                                    asio::steady_timer *timer,
                                                    SetRouteCallback callback) {
  int ret = tryToCreateFaceAndRoute(route_info.get());

  if (ret < 0 && max_try > 0) {
    max_try--;
    timer->expires_from_now(std::chrono::milliseconds(500));
    timer->async_wait([this, _route_info = std::move(route_info), max_try,
                       timer, callback](std::error_code ec) {
      if (ec) return;
      internalCreateFaceAndRoute(std::move(_route_info), max_try, timer,
                                 std::move(callback));
    });
    return;
  }

  if (max_try == 0 && ret < 0) {
    pending_add_route_counter_--;
    external_ioservice_.post([callback]() { callback(false, ~0); });
  } else {
    pending_add_route_counter_--;
    route_status_[route_id_] = std::move(route_info);
    external_ioservice_.post(
        [route_id = route_id_, callback]() { callback(route_id, true); });
    route_id_++;
  }

  delete timer;
}

int ForwarderInterface::tryToCreateFaceAndRoute(route_info_t *route_info) {
  if (!sock_) return -1;

  hc_data_t *data;
  if (hc_listener_list(sock_, &data) < 0) {
    return -1;
  }

  bool found = false;
  uint32_t face_id;

  foreach_listener(l, data) {
    std::string interface = std::string(l->interface_name);
    if (interface.compare("lo") != 0) {
      found = true;

      ip_address_t remote_ip;
      if (ip_address_pton(route_info->remote_addr.c_str(), &remote_ip) < 0) {
        hc_data_free(data);
        return -1;
      }

      hc_face_t face;
      memset(&face, 0, sizeof(hc_face_t));

      face.face.type = FACE_TYPE_UDP;
      face.face.family = route_info->family;
      face.face.local_addr = l->local_addr;
      face.face.remote_addr = remote_ip;
      face.face.local_port = l->local_port;
      face.face.remote_port = route_info->remote_port;

      if (netdevice_set_name(&face.face.netdevice, l->interface_name) < 0) {
        hc_data_free(data);
        return -1;
      }

      if (hc_face_create(sock_, &face) < 0) {
        hc_data_free(data);
        return -1;
      }

      face_id = face.id;
      break;
    }
  }

  if (!found) {
    hc_data_free(data);
    return -1;
  }

  ip_address_t route_ip;
  hc_route_t route;

  if (ip_address_pton(route_info->route_addr.c_str(), &route_ip) < 0) {
    hc_data_free(data);
    return -1;
  }

  route.face_id = face_id;
  route.family = AF_INET6;
  route.remote_addr = route_ip;
  route.len = route_info->route_len;
  route.cost = 1;

  if (hc_route_create(sock_, &route) < 0) {
    hc_data_free(data);
    return -1;
  }

  hc_data_free(data);
  return 0;
}

}  // namespace transport
