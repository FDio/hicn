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
#include <hicn/transport/utils/shared_ptr_utils.h>
#include <io_modules/forwarder/errors.h>

#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#endif
#include <asio/io_service.hpp>

namespace transport {
namespace core {

class LocalConnector : public Connector {
 public:
  template <typename ReceiveCallback, typename SentCallback, typename OnClose,
            typename OnReconnect>
  LocalConnector(asio::io_service &io_service,
                 ReceiveCallback &&receive_callback, SentCallback &&packet_sent,
                 OnClose &&close_callback, OnReconnect &&on_reconnect)
      : Connector(receive_callback, packet_sent, close_callback, on_reconnect),
        io_service_(io_service),
        io_service_work_(io_service_.get()) {
    state_ = State::CONNECTED;
  }

  ~LocalConnector() override;

  void send(Packet &packet) override;

  void send(const uint8_t *packet, std::size_t len) override;

  void close() override;

  auto shared_from_this() { return utils::shared_from(this); }

 private:
  std::reference_wrapper<asio::io_service> io_service_;
  asio::io_service::work io_service_work_;
  std::string name_;
};

}  // namespace core
}  // namespace transport
