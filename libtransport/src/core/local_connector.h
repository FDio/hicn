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

#include <core/errors.h>
#include <hicn/transport/core/asio_wrapper.h>
#include <hicn/transport/core/connector.h>
#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/errors/not_implemented_exception.h>
#include <hicn/transport/utils/move_wrapper.h>
#include <hicn/transport/utils/shared_ptr_utils.h>
#include <io_modules/forwarder/errors.h>

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
        io_service_work_(io_service_.get()) {}

  ~LocalConnector() override = default;

  auto shared_from_this() { return utils::shared_from(this); }

  void send(Packet &packet) override { send(packet.shared_from_this()); }

  void send(const utils::MemBuf::Ptr &buffer) override {
    throw errors::NotImplementedException();
  }

  void receive(const std::vector<utils::MemBuf::Ptr> &buffers) override {
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Sending packet to local socket.";
    std::weak_ptr<LocalConnector> self = shared_from_this();
    io_service_.get().post([self, _buffers{std::move(buffers)}]() mutable {
      if (auto ptr = self.lock()) {
        ptr->receive_callback_(ptr.get(), _buffers,
                               make_error_code(core_error::success));
      }
    });
  }

  void reconnect() override {
    state_ = State::CONNECTED;
    std::weak_ptr<LocalConnector> self = shared_from_this();
    io_service_.get().post([self]() {
      if (auto ptr = self.lock()) {
        ptr->on_reconnect_callback_(ptr.get(),
                                    make_error_code(core_error::success));
      }
    });
  }

  void close() override {
    std::weak_ptr<LocalConnector> self = shared_from_this();
    io_service_.get().post([self]() mutable {
      if (auto ptr = self.lock()) {
        ptr->on_close_callback_(ptr.get());
      }
    });
  }

 private:
  std::reference_wrapper<asio::io_service> io_service_;
  asio::io_service::work io_service_work_;
  std::string name_;
};

}  // namespace core
}  // namespace transport
