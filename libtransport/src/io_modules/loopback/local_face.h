/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

#include <hicn/transport/core/connector.h>
#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/utils/move_wrapper.h>

#include <hicn/transport/core/asio_wrapper.h>

namespace transport {
namespace core {

class Face {
 public:
  Face(Connector::PacketReceivedCallback &&receive_callback,
       asio::io_service &io_service, const std::string &app_name);

  Face(const Face &other);
  Face(Face &&other);
  void onPacket(const Packet &packet);
  Face &operator=(Face &&other);
  Face &operator=(const Face &other);

 private:
  template <typename T>
  void rescheduleOnIoService(const Packet &packet) {
    auto p = core::PacketManager<T>::getInstance().getPacket();
    p->replace(packet.data(), packet.length());
    io_service_.get().post([this, p]() mutable {
      receive_callback_(nullptr, *p, make_error_code(0));
    });
  }

  Connector::PacketReceivedCallback receive_callback_;
  std::reference_wrapper<asio::io_service> io_service_;
  std::string name_;
};

}  // namespace core
}  // namespace transport
