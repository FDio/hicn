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

#pragma once

extern "C" {
#include <hicn/ctrl/api.h>
#include <hicn/util/ip_address.h>
}

#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE 1
#endif

#ifdef __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#endif
#include <hicn/transport/core/asio_wrapper.h>
#ifdef __APPLE__
#pragma clang diagnostic pop
#endif
#include <functional>
#include <thread>
#include <unordered_map>

namespace transport {

typedef std::function<void(uint32_t, bool)> SetRouteCallback;

struct route_info_t {
  int family;
  std::string remote_addr;
  uint16_t remote_port;
  std::string route_addr;
  uint8_t route_len;
};

using RouteInfoPtr = std::shared_ptr<route_info_t>;

class ForwarderInterface {
 public:
  ForwarderInterface(asio::io_service &io_service)
      : external_ioservice_(io_service),
        work_(std::make_unique<asio::io_service::work>(internal_ioservice_)),
        sock_(nullptr),
        thread_(std::make_unique<std::thread>(
            [this]() { internal_ioservice_.run(); })),
        check_routes_timer_(nullptr),
        pending_add_route_counter_(0),
        route_id_(0),
        closed_(false) {}

  ~ForwarderInterface();

  int connectToForwarder();

  void removeConnectedUserNow(uint32_t route_id);

  // to be called at the server
  // at the client this creates a race condition
  // and the program enters in a loop
  void scheduleRemoveConnectedUser(uint32_t route_id);

  template <typename Callback>
  void createFaceAndRoute(RouteInfoPtr &&route_info, Callback &&callback) {
    internal_ioservice_.post([this, _route_info = std::move(route_info),
                              _callback = std::forward<Callback>(callback)]() {
      pending_add_route_counter_++;
      uint8_t max_try = 5;
      auto timer = new asio::steady_timer(internal_ioservice_);
      internalCreateFaceAndRoute(std::move(_route_info), max_try, timer,
                                 std::move(_callback));
    });
  }

  int32_t getMainListenerPort();

  void close();

 private:
  void internalRemoveConnectedUser(uint32_t route_id);

  void internalCreateFaceAndRoute(RouteInfoPtr route_info, uint8_t max_try,
                                  asio::steady_timer *timer,
                                  SetRouteCallback callback);

  int tryToCreateFaceAndRoute(route_info_t *route_info);

  asio::io_service &external_ioservice_;
  asio::io_service internal_ioservice_;
  std::unique_ptr<asio::io_service::work> work_;
  hc_sock_t *sock_;
  std::unique_ptr<std::thread> thread_;
  std::unordered_map<uint32_t, RouteInfoPtr> route_status_;
  std::unique_ptr<asio::steady_timer> check_routes_timer_;
  uint32_t pending_add_route_counter_;
  uint32_t route_id_;
  bool closed_;
};

}  // namespace transport
