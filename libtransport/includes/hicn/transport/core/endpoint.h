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

#include <hicn/transport/core/asio_wrapper.h>

namespace transport {

namespace core {

const uint16_t INVALID_PORT = 0xffff;

class Endpoint {
 public:
  Endpoint() : address_(), port_(INVALID_PORT) {}

  Endpoint(const Endpoint &other)
      : address_(other.address_), port_(other.port_) {}

  Endpoint(Endpoint &&other)
      : address_(std::move(other.address_)), port_(other.port_) {}

  Endpoint(std::string ip_address, uint32_t port)
      : address_(asio::ip::address::from_string(ip_address)), port_(port) {}

  Endpoint(asio::ip::udp::endpoint endpoint)
      : address_(endpoint.address()), port_(endpoint.port()) {}

  ~Endpoint() = default;

  Endpoint &operator=(const Endpoint &other) {
    if (this != &other) {
      address_ = other.address_;
      port_ = other.port_;
    }

    return *this;
  }

  Endpoint &operator=(Endpoint &&other) {
    if (this != &other) {
      address_ = std::move(other.address_);
      port_ = std::move(other.port_);
    }

    return *this;
  }

#if 0
  template <typename Ip, typename Port>
  Endpoint(Ip &&ip_address, Port &&port)
      : address_(std::forward<Ip &&>(ip_address)),
        port_(std::forward<Port &&>(port)) {}
#endif

  asio::ip::address getAddress() { return address_; }
  uint16_t getPort() { return port_; }

  void setAddress(uint32_t address) {
    address_ = asio::ip::address(asio::ip::address_v4(address));
  }

  void setPort(uint16_t port) { port_ = port; }

 private:
  asio::ip::address address_;
  uint16_t port_;
};
}  // namespace core
}  // namespace transport
