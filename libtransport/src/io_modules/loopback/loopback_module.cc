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

#include <hicn/transport/errors/not_implemented_exception.h>
#include <hicn/transport/utils/log.h>
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

  TRANSPORT_LOGD("LoopbackModule: sending from %u to %d", local_id_,
                 1 - local_id_);

  local_faces_.at(1 - local_id_)->send(packet);
}

void LoopbackModule::send(const uint8_t *packet, std::size_t len) {
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
                          Connector::OnReconnectCallback &&reconnect_callback,
                          asio::io_service &io_service,
                          const std::string &app_name) {
  if (local_id_ == uint32_t(~0) && global_counter_ < 2) {
    local_id_ = global_counter_++;
    local_faces_.emplace(
        local_faces_.begin() + local_id_,
        new LocalConnector(io_service, std::move(receive_callback), nullptr,
                           nullptr, std::move(reconnect_callback)));
  }
}

void LoopbackModule::processControlMessageReply(utils::MemBuf &packet_buffer) {
  return;
}

std::uint32_t LoopbackModule::getMtu() { return interface_mtu; }

bool LoopbackModule::isControlMessage(const uint8_t *message) { return false; }

extern "C" IoModule *create_module(void) { return new LoopbackModule(); }

}  // namespace core

}  // namespace transport
