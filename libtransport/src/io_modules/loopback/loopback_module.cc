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

#include <glog/logging.h>
#include <hicn/transport/errors/not_implemented_exception.h>
#include <io_modules/loopback/loopback_module.h>

namespace transport {

namespace core {

std::vector<std::unique_ptr<LocalConnector>> LoopbackModule::local_faces_;
std::atomic<uint32_t> LoopbackModule::global_counter_(0);

LoopbackModule::LoopbackModule() : IoModule(), local_id_(~0) {}

LoopbackModule::~LoopbackModule() {}

void LoopbackModule::connect(bool is_consumer) {}

bool LoopbackModule::isConnected() { return true; }

void LoopbackModule::send(Packet &packet) {
  IoModule::send(packet);

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "LoopbackModule: sending from " << local_id_
                               << " to " << 1 - local_id_;

  local_faces_.at(1 - local_id_)->send(packet);
}

void LoopbackModule::send(const utils::MemBuf::Ptr &buffer) {
  // not supported
  throw errors::NotImplementedException();
}

void LoopbackModule::registerRoute(const Prefix &prefix) {
  // For the moment we route packets from one socket to the other.
  // Next step will be to introduce a FIB
  return;
}

void LoopbackModule::closeConnection() {
  local_faces_.erase(local_faces_.begin() + local_id_);
}

void LoopbackModule::init(Connector::PacketReceivedCallback &&receive_callback,
                          Connector::PacketSentCallback &&sent_callback,
                          Connector::OnCloseCallback &&close_callback,
                          Connector::OnReconnectCallback &&reconnect_callback,
                          asio::io_service &io_service,
                          const std::string &app_name) {
  if (local_id_ == uint32_t(~0) && global_counter_ < 2) {
    local_id_ = global_counter_++;
    local_faces_.emplace(
        local_faces_.begin() + local_id_,
        new LocalConnector(io_service, std::move(receive_callback),
                           std::move(sent_callback), std::move(close_callback),
                           std::move(reconnect_callback)));
  }
}

void LoopbackModule::processControlMessageReply(utils::MemBuf &packet_buffer) {
  return;
}

std::uint32_t LoopbackModule::getMtu() { return interface_mtu; }

bool LoopbackModule::isControlMessage(utils::MemBuf &packet_buffer) {
  return false;
}

extern "C" IoModule *create_module(void) { return new LoopbackModule(); }

}  // namespace core

}  // namespace transport
