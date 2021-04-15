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
#include <io_modules/forwarder/forwarder_module.h>

namespace transport {

namespace core {

ForwarderModule::ForwarderModule()
    : IoModule(),
      name_(""),
      connector_id_(Connector::invalid_connector),
      forwarder_(Forwarder::getInstance()) {}

ForwarderModule::~ForwarderModule() {
  forwarder_.deleteConnector(connector_id_);
}

bool ForwarderModule::isConnected() { return true; }

void ForwarderModule::send(Packet &packet) {
  IoModule::send(packet);
  forwarder_.send(packet);
  // TRANSPORT_LOGD("ForwarderModule: sending from %u to %d", local_id_,
  //                1 - local_id_);

  // local_faces_.at(1 - local_id_).onPacket(packet);
}

void ForwarderModule::send(const uint8_t *packet, std::size_t len) {
  // not supported
  throw errors::NotImplementedException();
}

void ForwarderModule::registerRoute(const Prefix &prefix) {
  // For the moment we route packets from one socket to the other.
  // Next step will be to introduce a FIB
  return;
}

void ForwarderModule::closeConnection() {
  forwarder_.deleteConnector(connector_id_);
}

void ForwarderModule::init(Connector::PacketReceivedCallback &&receive_callback,
                           Connector::OnReconnectCallback &&reconnect_callback,
                           asio::io_service &io_service,
                           const std::string &app_name) {
  connector_id_ = forwarder_.registerLocalConnector(
      io_service, std::move(receive_callback), std::move(reconnect_callback));
  name_ = app_name;
}

void ForwarderModule::processControlMessageReply(utils::MemBuf &packet_buffer) {
  return;
}

void ForwarderModule::connect(bool is_consumer) {
  forwarder_.getConnector(connector_id_)
      ->setRole(is_consumer ? Connector::Role::CONSUMER
                            : Connector::Role::PRODUCER);
}

std::uint32_t ForwarderModule::getMtu() { return interface_mtu; }

bool ForwarderModule::isControlMessage(const uint8_t *message) { return false; }

extern "C" IoModule *create_module(void) { return new ForwarderModule(); }

}  // namespace core

}  // namespace transport
