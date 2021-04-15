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

#include <io_modules/udp/hicn_forwarder_module.h>
#include <io_modules/udp/udp_socket_connector.h>

union AddressLight {
  uint32_t ipv4;
  struct in6_addr ipv6;
};

typedef struct {
  uint8_t message_type;
  uint8_t command_id;
  uint16_t length;
  uint32_t seq_num;
} CommandHeader;

typedef struct {
  uint8_t message_type;
  uint8_t command_id;
  uint16_t length;
  uint32_t seq_num;
  char symbolic_or_connid[16];
  union AddressLight address;
  uint16_t cost;
  uint8_t address_type;
  uint8_t len;
} RouteToSelfCommand;

typedef struct {
  uint8_t message_type;
  uint8_t command_id;
  uint16_t length;
  uint32_t seq_num;
  char symbolic_or_connid[16];
} DeleteSelfConnectionCommand;

namespace {
static constexpr uint8_t addr_inet = 1;
static constexpr uint8_t addr_inet6 = 2;
static constexpr uint8_t add_route_command = 3;
static constexpr uint8_t delete_connection_command = 5;
static constexpr uint8_t request_light = 0xc0;
static constexpr char identifier[] = "SELF";

void fillCommandHeader(CommandHeader *header) {
  // Allocate and fill the header
  header->message_type = request_light;
  header->length = 1;
}

RouteToSelfCommand createCommandRoute(std::unique_ptr<sockaddr> &&addr,
                                      uint8_t prefix_length) {
  RouteToSelfCommand command = {0};

  // check and set IP address
  if (addr->sa_family == AF_INET) {
    command.address_type = addr_inet;
    command.address.ipv4 = ((sockaddr_in *)addr.get())->sin_addr.s_addr;
  } else if (addr->sa_family == AF_INET6) {
    command.address_type = addr_inet6;
    command.address.ipv6 = ((sockaddr_in6 *)addr.get())->sin6_addr;
  }

  // Fill remaining payload fields
#ifndef _WIN32
  strcpy(command.symbolic_or_connid, identifier);
#else
  strcpy_s(command.symbolic_or_connid, 16, identifier);
#endif
  command.cost = 1;
  command.len = (uint8_t)prefix_length;

  // Allocate and fill the header
  command.command_id = add_route_command;
  fillCommandHeader((CommandHeader *)&command);

  return command;
}

DeleteSelfConnectionCommand createCommandDeleteConnection() {
  DeleteSelfConnectionCommand command = {0};
  fillCommandHeader((CommandHeader *)&command);
  command.command_id = delete_connection_command;

#ifndef _WIN32
  strcpy(command.symbolic_or_connid, identifier);
#else
  strcpy_s(command.symbolic_or_connid, 16, identifier);
#endif

  return command;
}

}  // namespace

namespace transport {

namespace core {

HicnForwarderModule::HicnForwarderModule() : IoModule(), connector_(nullptr) {}

HicnForwarderModule::~HicnForwarderModule() {}

void HicnForwarderModule::connect(bool is_consumer) {
  connector_->connect();
  connector_->setRole(is_consumer ? Connector::Role::CONSUMER
                                  : Connector::Role::PRODUCER);
}

bool HicnForwarderModule::isConnected() { return connector_->isConnected(); }

void HicnForwarderModule::send(Packet &packet) {
  IoModule::send(packet);
  packet.setChecksum();
  connector_->send(packet);
}

void HicnForwarderModule::send(const uint8_t *packet, std::size_t len) {
  counters_.tx_packets++;
  counters_.tx_bytes += len;

  // Perfect forwarding
  connector_->send(packet, len);
}

void HicnForwarderModule::registerRoute(const Prefix &prefix) {
  auto command = createCommandRoute(prefix.toSockaddr(),
                                    (uint8_t)prefix.getPrefixLength());
  send((uint8_t *)&command, sizeof(RouteToSelfCommand));
}

void HicnForwarderModule::closeConnection() {
  auto command = createCommandDeleteConnection();
  send((uint8_t *)&command, sizeof(DeleteSelfConnectionCommand));
  connector_->close();
}

void HicnForwarderModule::init(
    Connector::PacketReceivedCallback &&receive_callback,
    Connector::OnReconnectCallback &&reconnect_callback,
    asio::io_service &io_service, const std::string &app_name) {
  if (!connector_) {
    connector_ = new UdpSocketConnector(std::move(receive_callback), nullptr,
                                        nullptr, std::move(reconnect_callback),
                                        io_service, app_name);
  }
}

void HicnForwarderModule::processControlMessageReply(
    utils::MemBuf &packet_buffer) {
  if (packet_buffer.data()[0] == nack_code) {
    throw errors::RuntimeException(
        "Received Nack message from hicn light forwarder.");
  }
}

std::uint32_t HicnForwarderModule::getMtu() { return interface_mtu; }

bool HicnForwarderModule::isControlMessage(const uint8_t *message) {
  return message[0] == ack_code || message[0] == nack_code;
}

extern "C" IoModule *create_module(void) { return new HicnForwarderModule(); }

}  // namespace core

}  // namespace transport
