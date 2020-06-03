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

#pragma once

#include <hicn/transport/portability/c_portability.h>
#include <hicn/transport/utils/branch_prediction.h>
#include <hicn/transport/utils/log.h>
#include <hicn/transport/utils/string_utils.h>

#include <asio.hpp>
#include <chrono>
#include <sstream>
#include <string>

#include "forwarder_interface.h"


#define RETRY_INTERVAL 300

namespace transport {

static constexpr char server_header[] = "server";
static constexpr char prefix_header[] = "prefix";
static constexpr char port_header[] = "port";

using OnForwarderConfiguredCallback = std::function<void(bool)>;

class ForwarderConfig {
 public:
  using ListenerRetrievedCallback = std::function<void(std::error_code)>;

  template <typename Callback>
  ForwarderConfig(asio::io_service& io_service, Callback&& callback)
      : forwarder_interface_(io_service),
        resolver_(io_service),
        retx_count_(0),
        timer_(io_service),
        hicn_listen_port_(~0),
        listener_retrieved_callback_(std::forward<Callback>(callback)) {}

  void close() {
    timer_.cancel();
    resolver_.cancel();
    forwarder_interface_.close();
  }

  void tryToConnectToForwarder() {
    doTryToConnectToForwarder(std::make_error_code(std::errc(0)));
  }

  void doTryToConnectToForwarder(std::error_code ec) {
    if (!ec) {
      // ec == 0 --> timer expired
      int ret = forwarder_interface_.connectToForwarder();
      if (ret < 0) {
        // We were not able to connect to the local forwarder. Do not give up
        // and retry.
        TRANSPORT_LOGE("Could not connect to local forwarder. Retrying.");

        timer_.expires_from_now(std::chrono::milliseconds(RETRY_INTERVAL));
        timer_.async_wait(std::bind(&ForwarderConfig::doTryToConnectToForwarder,
                                    this, std::placeholders::_1));
      } else {
        timer_.cancel();
        retx_count_ = 0;
        doGetMainListener(std::make_error_code(std::errc(0)));
      }
    } else {
      TRANSPORT_LOGD("Timer for re-trying forwarder connection canceled.");
    }
  }

  void doGetMainListener(std::error_code ec) {
    if (!ec) {
      // ec == 0 --> timer expired
      int ret = forwarder_interface_.getMainListenerPort();
      if (ret <= 0) {
        // Since without the main listener of the forwarder the proxy cannot
        // work, we can stop the program here until we get the listener port.
        TRANSPORT_LOGE(
            "Could not retrieve main listener port from the forwarder. "
            "Retrying.");

        timer_.expires_from_now(std::chrono::milliseconds(RETRY_INTERVAL));
        timer_.async_wait(std::bind(&ForwarderConfig::doGetMainListener, this,
                                    std::placeholders::_1));
      } else {
        timer_.cancel();
        retx_count_ = 0;
        hicn_listen_port_ = uint16_t(ret);
        listener_retrieved_callback_(std::make_error_code(std::errc(0)));
      }
    } else {
      TRANSPORT_LOGI("Timer for retrieving main hicn listener canceled.");
    }
  }

  template <typename Callback>
  TRANSPORT_ALWAYS_INLINE bool parseHicnHeader(std::string& header,
                                               Callback&& callback) {
    std::stringstream ss(header);
    route_info_t* ret = new route_info_t();
    std::string port_string;

    while (ss.good()) {
      std::string substr;
      getline(ss, substr, ',');

      if (TRANSPORT_EXPECT_FALSE(substr.empty())) {
        continue;
      }

      utils::trim(substr);
      auto it = std::find_if(substr.begin(), substr.end(),
                             [](int ch) { return ch == '='; });
      if (it != std::end(substr)) {
        auto key = std::string(substr.begin(), it);
        auto value = std::string(it + 1, substr.end());

        if (key == server_header) {
          ret->remote_addr = value;
        } else if (key == prefix_header) {
          auto it = std::find_if(value.begin(), value.end(),
                                 [](int ch) { return ch == '/'; });

          if (it != std::end(value)) {
            ret->route_addr = std::string(value.begin(), it);
            ret->route_len = std::stoul(std::string(it + 1, value.end()));
          } else {
            return false;
          }
        } else if (key == port_header) {
          ret->remote_port = std::stoul(value);
          port_string = value;
        } else {
          // Header not recognized
          return false;
        }
      }
    }

    /*
     * Resolve server address
     */
    auto results =
        resolver_.resolve({ret->remote_addr, port_string,
                           asio::ip::resolver_query_base::numeric_service});

#if ((ASIO_VERSION / 100 % 1000) < 12)
    asio::ip::udp::resolver::iterator end;
    auto& it = results;
    while (it != end) {
#else
    for (auto it = results.begin(); it != results.end(); it++) {
#endif
      if (it->endpoint().address().is_v4()) {
        // Use this v4 address to configure the forwarder.
        ret->remote_addr = it->endpoint().address().to_string();
        ret->family = AF_INET;
        std::string _prefix = ret->route_addr;
        forwarder_interface_.createFaceAndRoute(
            RouteInfoPtr(ret), [callback = std::forward<Callback>(callback),
                                configured_prefix = std::move(_prefix)](
                                   uint32_t route_id, bool result) {
              callback(result, configured_prefix);
            });

        return true;
      }
#if ((ASIO_VERSION / 100 % 1000) < 12)
      it++;
#endif
    }

    return false;
  }

 private:
  ForwarderInterface forwarder_interface_;
  asio::ip::udp::resolver resolver_;
  std::uint32_t retx_count_;
  asio::steady_timer timer_;
  uint16_t hicn_listen_port_;
  ListenerRetrievedCallback listener_retrieved_callback_;
};  // namespace transport

}  // namespace transport