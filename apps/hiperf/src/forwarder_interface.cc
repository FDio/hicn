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

#include <arpa/inet.h>
#include <forwarder_interface.h>
#include <hicn/transport/utils/log.h>

#include <chrono>
#include <iostream>
#include <thread>
#include <unordered_set>

extern "C" {
#include <hicn/error.h>
#include <hicn/util/ip_address.h>
#include <hicn/util/sstrncpy.h>
}

// XXX the main listener should be retrieve in this class at initialization, aka
// when hICN becomes avialable
//
// XXX the main listener port will be retrieved in the forwarder
// interface... everything else will be delayed until we have this
// information

namespace hiperf {

ForwarderInterface::ForwarderInterface(asio::io_service &io_service)
    : external_ioservice_(io_service), timer_(io_service) {}

ForwarderInterface::ForwarderInterface(asio::io_service &io_service,
                                       ICallback *callback,
                                       forwarder_type_t fwd_type)
    : external_ioservice_(io_service), timer_(io_service) {
  initForwarderInterface(callback, fwd_type);
}

ForwarderInterface::~ForwarderInterface() {
  if (thread_ && thread_->joinable()) {
    internal_ioservice_.dispatch([this]() {
      if (sock_) {
        hc_sock_free(sock_);
        sock_ = nullptr;
      }

      work_.reset();
    });

    thread_->join();
  }
}

void ForwarderInterface::initForwarderInterface(ICallback *callback,
                                                forwarder_type_t fwd_type) {
  forwarder_interface_callback_ = callback;
  work_ = std::make_unique<asio::io_service::work>(internal_ioservice_);
  sock_ = nullptr;
  thread_ = std::make_unique<std::thread>([this]() {
    std::cout << "Starting Forwarder Interface thread" << std::endl;
    internal_ioservice_.run();
    std::cout << "Stopping Forwarder Interface thread" << std::endl;
  });
  check_routes_timer_ = nullptr;
  pending_add_route_counter_ = 0;
  hicn_listen_port_ = 9695;
  /* We start in disabled state even when a forwarder is always available */
  state_ = State::Disabled;
  fwd_type_ = fwd_type;
  num_reattempts = 0;
  std::cout << "Forwarder interface created... connecting to forwarder...\n";
  internal_ioservice_.post([this]() { onHicnServiceAvailable(true); });
}

void ForwarderInterface::onHicnServiceAvailable(bool flag) {
  if (flag) {
    switch (state_) {
      case State::Disabled:
      case State::Requested:
        state_ = State::Available;
      case State::Available:
        connectToForwarder();
        /* Synchronous */
        if (state_ != State::Connected) {
          std::cout << "ConnectToForwarder failed" << std::endl;
          goto REATTEMPT;
        }
        state_ = State::Ready;

        std::cout << "Connected to forwarder... cancelling reconnection timer"
                  << std::endl;

        timer_.cancel();
        num_reattempts = 0;

        std::cout << "Forwarder interface is ready... communicate to controller"
                  << std::endl;

        forwarder_interface_callback_->onHicnServiceReady();
      case State::Connected:
      case State::Ready:
        break;
    }
  } else {
    if (sock_) {
      hc_sock_free(sock_);
      sock_ = nullptr;
    }
    state_ = State::Disabled;  // XXX to be checked upon callback to prevent the
                               // state from going forward (used to manage
                               // concurrency)
  }
  return;

REATTEMPT:
  /* Schedule reattempt */
  std::cout << "Failed to connect, scheduling reattempt" << std::endl;
  num_reattempts++;

  timer_.expires_from_now(
      std::chrono::milliseconds(ForwarderInterface::REATTEMPT_DELAY_MS));
  // timer_.async_wait(std::bind(&ForwarderInterface::onHicnServiceAvailable,
  // this, flag, std::placeholders::_1));
  timer_.async_wait([this, flag](const std::error_code &ec) {
    if (ec) return;
    onHicnServiceAvailable(flag);
  });
}

int ForwarderInterface::connectToForwarder() {
  sock_ = hc_sock_create_forwarder(fwd_type_);
  if (!sock_) {
    std::cout << "Could not create socket" << std::endl;
    goto ERR_SOCK;
  }

  if (hc_sock_connect(sock_) < 0) {
    std::cout << "Could not connect to forwarder" << std::endl;
    goto ERR;
  }

  std::cout << "Forwarder interface connected" << std::endl;
  state_ = State::Connected;
  return 0;

ERR:
  hc_sock_free(sock_);
  sock_ = nullptr;
ERR_SOCK:
  return -1;
}

int ForwarderInterface::checkListener() {
  if (!sock_) return -1;

  hc_data_t *data;
  if (hc_listener_list(sock_, &data) < 0) return -1;

  int ret = -1;
  foreach_listener(l, data) {
    std::string interface = std::string(l->interface_name);
    if (interface.compare("lo") != 0) {
      hicn_listen_port_ = l->local_port;
      state_ = State::Ready;
      ret = 0;
      std::cout << "Got listener port" << std::endl;
      break;
    }
  }

  hc_data_free(data);
  return ret;
}

void ForwarderInterface::close() {
  std::cout << "ForwarderInterface::close" << std::endl;

  state_ = State::Disabled;
  /* Cancelling eventual reattempts */
  timer_.cancel();

  if (sock_) {
    hc_sock_free(sock_);
    sock_ = nullptr;
  }

  internal_ioservice_.post([this]() { work_.reset(); });

  if (thread_->joinable()) {
    thread_->join();
  }
}

#if 0
void ForwarderInterface::enableCheckRoutesTimer() {
  if (check_routes_timer_ != nullptr) return;

  check_routes_timer_ =
      std::make_unique<asio::steady_timer>(internal_ioservice_);
  checkRoutesLoop();
}

void ForwarderInterface::removeConnectedUserNow(ProtocolPtr protocol) {
  internalRemoveConnectedUser(protocol);
}

void ForwarderInterface::scheduleRemoveConnectedUser(ProtocolPtr protocol) {
  internal_ioservice_.post(
      [this, protocol]() { internalRemoveConnectedUser(protocol); });
}
#endif

void ForwarderInterface::createFaceAndRoute(const RouteInfoPtr &route_info) {
  std::vector<RouteInfoPtr> routes;
  routes.push_back(std::move(route_info));
  createFaceAndRoutes(routes);
}

void ForwarderInterface::createFaceAndRoutes(
    const std::vector<RouteInfoPtr> &routes_info) {
  pending_add_route_counter_++;
  auto timer = new asio::steady_timer(internal_ioservice_);
  internal_ioservice_.post([this, routes_info, timer]() {
    internalCreateFaceAndRoutes(routes_info, ForwarderInterface::MAX_REATTEMPT,
                                timer);
  });
}

void ForwarderInterface::deleteFaceAndRoute(const RouteInfoPtr &route_info) {
  std::vector<RouteInfoPtr> routes;
  routes.push_back(std::move(route_info));
  deleteFaceAndRoutes(routes);
}

void ForwarderInterface::deleteFaceAndRoutes(
    const std::vector<RouteInfoPtr> &routes_info) {
  internal_ioservice_.post([this, routes_info]() {
    for (auto &route : routes_info) {
      internalDeleteFaceAndRoute(route);
    }
  });
}

void ForwarderInterface::setStrategy(std::string prefix, uint32_t prefix_len,
                                     std::string strategy) {
  if (!sock_) return;

  ip_address_t ip_prefix;
  if (ip_address_pton(prefix.c_str(), &ip_prefix) < 0) {
    return;
  }

  strategy_type_t strategy_type = strategy_type_from_str(strategy.c_str());
  if (strategy_type == STRATEGY_TYPE_UNDEFINED) return;

  hc_strategy_t strategy_conf;
  strategy_conf.address = ip_prefix;
  strategy_conf.len = prefix_len;
  strategy_conf.family = AF_INET6;
  strategy_conf.type = strategy_type;

  hc_strategy_set(sock_, &strategy_conf);
}

void ForwarderInterface::internalDeleteFaceAndRoute(
    const RouteInfoPtr &route_info) {
  if (!sock_) return;

  hc_data_t *data;
  if (hc_route_list(sock_, &data) < 0) return;

  std::vector<hc_route_t *> routes_to_remove;
  foreach_route(r, data) {
    char remote_addr[INET6_ADDRSTRLEN];
    int ret = ip_address_ntop(&r->remote_addr, remote_addr, r->len, r->family);
    if (ret < 0) continue;

    std::string route_addr(remote_addr);
    if (route_addr.compare(route_info->route_addr) == 0 &&
        r->len == route_info->route_len) {
      // route found
      routes_to_remove.push_back(r);
    }
  }

  if (routes_to_remove.size() == 0) {
    // nothing to do here
    hc_data_free(data);
    return;
  }

  std::unordered_set<uint32_t> connids_to_remove;
  for (unsigned i = 0; i < routes_to_remove.size(); i++) {
    connids_to_remove.insert(routes_to_remove[i]->face_id);
    if (hc_route_delete(sock_, routes_to_remove[i]) < 0) {
      std::cout << "Error removing route from forwarder." << std::endl;
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
      std::cout << "Error removing connection from forwarder." << std::endl;
    }
  }

  hc_data_free(data);
}

void ForwarderInterface::internalCreateFaceAndRoutes(
    const std::vector<RouteInfoPtr> &route_info, uint8_t max_try,
    asio::steady_timer *timer) {
  uint32_t face_id;

  std::vector<RouteInfoPtr> failed;
  for (auto &route : route_info) {
    int ret = tryToCreateFace(route.get(), &face_id);
    if (ret >= 0) {
      auto ret = tryToCreateRoute(route.get(), face_id);
      if (ret < 0) {
        failed.push_back(route);
        std::cerr << "Error creating route and face" << std::endl;
        continue;
      }
    }
  }

  if (failed.size() > 0) {
    if (max_try == 0) {
      /* All attempts failed */
      goto RESULT;
    }
    max_try--;
    timer->expires_from_now(std::chrono::milliseconds(500));
    timer->async_wait(
        [this, failed, max_try, timer](const std::error_code &ec) {
          if (ec) return;
          internalCreateFaceAndRoutes(failed, max_try, timer);
        });
    return;
  }

#if 0
  // route_status_[protocol] = std::move(route_info);
  for (size_t i = 0; i < route_info.size(); i++) {
    route_status_.insert(
        std::pair<ClientId, RouteInfoPtr>(protocol, std::move(route_info[i])));
  }
#endif

RESULT:
  std::cout << "Face / Route create ok, now calling back protocol" << std::endl;
  pending_add_route_counter_--;
  external_ioservice_.post([this, r = std::move(route_info)]() mutable {
    forwarder_interface_callback_->onRouteConfigured(r);
  });
  delete timer;
}

int ForwarderInterface::tryToCreateFace(RouteInfo *route_info,
                                        uint32_t *face_id) {
  bool found = false;

  // check connection with the forwarder
  if (!sock_) {
    std::cout << "[ForwarderInterface::tryToCreateFace] socket error"
              << std::endl;
    goto ERR_SOCK;
  }

  // get listeners list
  hc_data_t *data;
  if (hc_listener_list(sock_, &data) < 0) {
    std::cout << "[ForwarderInterface::tryToCreateFace] cannot list listeners";
    goto ERR_LIST;
  }

  char _local_address[128];
  foreach_listener(l, data) {
    std::cout << "Processing " << l->interface_name << std::endl;
    std::string interface = std::string(l->interface_name);
    int ret = ip_address_ntop(&l->local_addr, _local_address, 128, AF_INET);
    if (ret < 0) {
      std::cerr << "Error in ip_address_ntop" << std::endl;
      goto ERR;
    }

    std::string local_address = std::string(_local_address);
    uint16_t local_port = l->local_port;

    if (interface.compare(route_info->interface) == 0 &&
        local_address.compare(route_info->local_addr) == 0 &&
        local_port == route_info->local_port) {
      found = true;
      break;
    }
  }

  std::cout << route_info->remote_addr << std::endl;

  ip_address_t local_address, remote_address;
  ip_address_pton(route_info->local_addr.c_str(), &local_address);
  ip_address_pton(route_info->remote_addr.c_str(), &remote_address);

  if (!found) {
    // Create listener
    hc_listener_t listener;
    memset(&listener, 0, sizeof(hc_listener_t));

    std::string name = "l_" + route_info->name;
    listener.local_addr = local_address;
    listener.type = FACE_TYPE_UDP;
    listener.family = AF_INET;
    listener.local_port = route_info->local_port;
    int ret = strcpy_s(listener.name, SYMBOLIC_NAME_LEN - 1, name.c_str());
    if (ret < EOK) goto ERR;
    ret = strcpy_s(listener.interface_name, INTERFACE_LEN - 1,
                   route_info->interface.c_str());
    if (ret < EOK) goto ERR;

    std::cout << "------------> " << route_info->interface << std::endl;

    ret = hc_listener_create(sock_, &listener);

    if (ret < 0) {
      std::cerr << "Error creating listener." << std::endl;
      return -1;
    } else {
      std::cout << "Listener " << listener.id << " created." << std::endl;
    }
  }

  // Create face
  hc_face_t face;
  memset(&face, 0, sizeof(hc_face_t));

  // crate face with the local interest
  face.face.type = FACE_TYPE_UDP;
  face.face.family = route_info->family;
  face.face.local_addr = local_address;
  face.face.remote_addr = remote_address;
  face.face.local_port = route_info->local_port;
  face.face.remote_port = route_info->remote_port;

  if (netdevice_set_name(&face.face.netdevice, route_info->interface.c_str()) <
      0) {
    std::cout << "[ForwarderInterface::tryToCreateFaceAndRoute] "
                 "netdevice_set_name "
                 "("
              << face.face.netdevice.name << ", "
              << route_info->interface << ") error" << std::endl;
    goto ERR;
  }

  // create face
  if (hc_face_create(sock_, &face) < 0) {
    std::cout << "[ForwarderInterface::tryToCreateFace] error creating face";
    goto ERR;
  }

  std::cout << "Face created successfully" << std::endl;

  // assing face to the return value
  *face_id = face.id;

  hc_data_free(data);
  return 0;

ERR:
  hc_data_free(data);
ERR_LIST:
ERR_SOCK:
  return -1;
}

int ForwarderInterface::tryToCreateRoute(RouteInfo *route_info,
                                         uint32_t face_id) {
  std::cout << "Trying to create route" << std::endl;

  // check connection with the forwarder
  if (!sock_) {
    std::cout << "[ForwarderInterface::tryToCreateRoute] socket error";
    return -1;
  }

  ip_address_t route_ip;
  hc_route_t route;

  if (ip_address_pton(route_info->route_addr.c_str(), &route_ip) < 0) {
    std::cout << "[ForwarderInterface::tryToCreateRoute] ip_address_pton error";
    return -1;
  }

  route.face_id = face_id;
  route.family = AF_INET6;
  route.remote_addr = route_ip;
  route.len = route_info->route_len;
  route.cost = 1;

  if (hc_route_create(sock_, &route) < 0) {
    std::cout << "[ForwarderInterface::tryToCreateRoute] error creating route";
    return -1;
  }

  std::cout << "[ForwarderInterface::tryToCreateRoute] OK" << std::endl;
  return 0;
}

#if 0  // not used
void ForwarderInterface::checkRoutesLoop() {
  check_routes_timer_->expires_from_now(std::chrono::milliseconds(1000));
  check_routes_timer_->async_wait([this](const std::error_code &ec) {
    if (ec) return;
    if (pending_add_route_counter_ == 0) checkRoutes();
  });
}

void ForwarderInterface::checkRoutes() {
  std::cout << "someone called the checkRoutes function" << std::endl;
  if (!sock_) return;

  hc_data_t *data;
  if (hc_route_list(sock_, &data) < 0) {
    return;
  }

  std::unordered_set<std::string> routes_set;
  foreach_route(r, data) {
    char remote_addr[INET6_ADDRSTRLEN];
    int ret = ip_address_ntop(&r->remote_addr, remote_addr, r->len, r->family);
    if (ret < 0) continue;
    std::string route(std::string(remote_addr) + "/" + std::to_string(r->len));
    routes_set.insert(route);
  }

  for (auto it = route_status_.begin(); it != route_status_.end(); it++) {
    std::string route(it->second->route_addr + "/" +
                      std::to_string(it->second->route_len));
    if (routes_set.find(route) == routes_set.end()) {
      // the route is missing
      createFaceAndRoute(it->second, it->first);
      break;
    }
  }

  hc_data_free(data);
}
#endif

#if 0
      using ListenerRetrievedCallback =
          std::function<void(std::error_code, uint32_t)>;

      ListenerRetrievedCallback listener_retrieved_callback_;

#ifdef __ANDROID__
            hicn_listen_port_(9695),
#else
            hicn_listen_port_(0),
#endif
            timer_(forward_engine_.getIoService()),

      void initConfigurationProtocol(void)
      {
        // We need the configuration, which is different for every protocol...
        // so we move this step down towards the protocol implementation itself.
        if (!permanent_hicn) {
          doInitConfigurationProtocol();
        } else {
          // XXX This should be moved somewhere else
          getMainListener(
              [this](const std::error_code &ec, uint32_t hicn_listen_port) {
                if (!ec)
                {
                  hicn_listen_port_ = hicn_listen_port;
                  doInitConfigurationProtocol();
                }
              });
          }
      }

      template <typename Callback>
      void getMainListener(Callback &&callback)
      {
        listener_retrieved_callback_ = std::forward<Callback &&>(callback);
        tryToConnectToForwarder();
      }
    private:
      void doGetMainListener(const std::error_code &ec)
      {
        if (!ec)
        {
          // ec == 0 --> timer expired
          int ret = forwarder_interface_.getMainListenerPort();
          if (ret <= 0)
          {
            // Since without the main listener of the forwarder the proxy cannot
            // work, we can stop the program here until we get the listener port.
            std::cout <<
                "Could not retrieve main listener port from the forwarder. "
                "Retrying.";

            timer_.expires_from_now(std::chrono::milliseconds(RETRY_INTERVAL));
            timer_.async_wait(std::bind(&Protocol::doGetMainListener, this,
                                        std::placeholders::_1));
          }
          else
          {
            timer_.cancel();
            retx_count_ = 0;
            hicn_listen_port_ = uint16_t(ret);
            listener_retrieved_callback_(
                make_error_code(configuration_error::success), hicn_listen_port_);
          }
        }
        else
        {
          std::cout <<  "Timer for retrieving main hicn listener canceled." << std::endl;
        }
      }

      void tryToConnectToForwarder()
      {
        doTryToConnectToForwarder(std::make_error_code(std::errc(0)));
      }

      void doTryToConnectToForwarder(const std::error_code &ec)
      {
        if (!ec)
        {
          // ec == 0 --> timer expired
          int ret = forwarder_interface_.connect();
          if (ret < 0)
          {
            // We were not able to connect to the local forwarder. Do not give up
            // and retry.
            std::cout <<  "Could not connect to local forwarder. Retrying." << std::endl;

            timer_.expires_from_now(std::chrono::milliseconds(RETRY_INTERVAL));
            timer_.async_wait(std::bind(&Protocol::doTryToConnectToForwarder, this,
                                        std::placeholders::_1));
          }
          else
          {
            timer_.cancel();
            retx_count_ = 0;
            doGetMainListener(std::make_error_code(std::errc(0)));
          }
        }
        else
        {
          std::cout <<  "Timer for re-trying forwarder connection canceled." << std::endl;
        }
      }


    template <typename ProtocolImplementation>
    constexpr uint32_t Protocol<ProtocolImplementation>::RETRY_INTERVAL;

#endif

constexpr uint32_t ForwarderInterface::REATTEMPT_DELAY_MS;
constexpr uint32_t ForwarderInterface::MAX_REATTEMPT;

}  // namespace hiperf
