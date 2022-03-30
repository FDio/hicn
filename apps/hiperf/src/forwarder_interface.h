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

#include <hicn/transport/utils/noncopyable.h>

extern "C" {
#ifndef WITH_POLICY
#define WITH_POLICY
#endif
#include <hicn/ctrl/api.h>
#include <hicn/util/ip_address.h>
}

#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#endif
#include <asio.hpp>
#include <functional>
#include <thread>
#include <unordered_map>

namespace hiperf {

class ForwarderInterface : ::utils::NonCopyable {
  static const uint32_t REATTEMPT_DELAY_MS = 500;
  static const uint32_t MAX_REATTEMPT = 10;

 public:
  struct RouteInfo {
    int family;
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    std::string route_addr;
    uint8_t route_len;
    std::string interface;
    std::string name;
  };

  using RouteInfoPtr = std::shared_ptr<RouteInfo>;

  class ICallback {
   public:
    virtual void onHicnServiceReady() = 0;
    virtual void onRouteConfigured(std::vector<RouteInfoPtr> &route_info) = 0;
  };

  enum class State {
    Disabled,  /* Stack is stopped */
    Requested, /* Stack is starting */
    Available, /* Forwarder is running */
    Connected, /* Control socket connected */
    Ready,     /* Listener present */
  };

 public:
  explicit ForwarderInterface(asio::io_service &io_service);
  explicit ForwarderInterface(asio::io_service &io_service, ICallback *callback,
                              forwarder_type_t fwd_type);

  ~ForwarderInterface();

  void initForwarderInterface(ICallback *callback, forwarder_type_t fwd_type);

  State getState();

  void setState(State state);

  void onHicnServiceAvailable(bool flag);

  void enableCheckRoutesTimer();

  void createFaceAndRoutes(const std::vector<RouteInfoPtr> &routes_info);

  void createFaceAndRoute(const RouteInfoPtr &route_info);

  void deleteFaceAndRoutes(const std::vector<RouteInfoPtr> &routes_info);

  void deleteFaceAndRoute(const RouteInfoPtr &route_info);

  void setStrategy(std::string prefix, uint32_t prefix_len,
                   std::string strategy);

  void close();

  uint16_t getHicnListenerPort() { return hicn_listen_port_; }

 private:
  ForwarderInterface &operator=(const ForwarderInterface &other) = delete;

  int connectToForwarder();

  int checkListener();

  void internalCreateFaceAndRoutes(const std::vector<RouteInfoPtr> &route_info,
                                   uint8_t max_try, asio::steady_timer *timer);

  void internalDeleteFaceAndRoute(const RouteInfoPtr &routes_info);

  int tryToCreateFace(RouteInfo *RouteInfo, uint32_t *face_id);
  int tryToCreateRoute(RouteInfo *RouteInfo, uint32_t face_id);

  void checkRoutesLoop();

  void checkRoutes();

  asio::io_service &external_ioservice_;
  asio::io_service internal_ioservice_;
  ICallback *forwarder_interface_callback_;
  std::unique_ptr<asio::io_service::work> work_;
  hc_sock_t *sock_;
  std::unique_ptr<std::thread> thread_;
  //  SetRouteCallback set_route_callback_;
  // std::unordered_multimap<ProtocolPtr, RouteInfoPtr> route_status_;
  std::unique_ptr<asio::steady_timer> check_routes_timer_;
  uint32_t pending_add_route_counter_;
  uint16_t hicn_listen_port_;

  State state_;

  forwarder_type_t fwd_type_;

  /* Reattempt timer */
  asio::steady_timer timer_;
  unsigned num_reattempts;
};

}  // namespace hiperf
