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

#include <core/udp_connector.h>
#include <io_modules/hicn-light-ng/hicn_forwarder_module.h>

extern "C" {
#include <hicn/ctrl/hicn-light-ng.h>
}

namespace transport {

namespace core {

HicnForwarderModule::HicnForwarderModule()
    : IoModule(), connector_(nullptr), seq_(0) {}

HicnForwarderModule::~HicnForwarderModule() {}

void HicnForwarderModule::connect(bool is_consumer) {
  connector_->connect("localhost", 9695);
  connector_->setRole(is_consumer ? Connector::Role::CONSUMER
                                  : Connector::Role::PRODUCER);
}

bool HicnForwarderModule::isConnected() { return connector_->isConnected(); }

void HicnForwarderModule::send(Packet &packet) {
  IoModule::send(packet);
  packet.setChecksum();
  connector_->send(packet);
}

void HicnForwarderModule::send(const utils::MemBuf::Ptr &packet) {
  counters_.tx_packets++;
  counters_.tx_bytes += packet->length();

  // Perfect forwarding
  connector_->send(packet);
}

void HicnForwarderModule::registerRoute(const Prefix &prefix) {
  auto command = createCommandRoute(prefix.toSockaddr(),
                                    (uint8_t)prefix.getPrefixLength());
  if (!command) {
    // TODO error
    return;
  }
  send(command);
}

void HicnForwarderModule::sendMapme() {
  auto command = createCommandMapmeSendUpdate();
  if (!command) {
    // TODO error
    return;
  }
  send(command);
}

void HicnForwarderModule::setForwardingStrategy(const Prefix &prefix,
                                                std::string &strategy) {
  auto command = createCommandSetForwardingStrategy(
      prefix.toSockaddr(), (uint8_t)prefix.getPrefixLength(), strategy);
  if (!command) {
    // TODO error
    return;
  }
  send(command);
}

void HicnForwarderModule::closeConnection() {
  auto command = createCommandDeleteConnection();
  if (!command) {
    // TODO error
    return;
  }

  connector_->setSentCallback([](Connector *c, const std::error_code &ec) {
    if (!ec) {
      c->close();
    }
  });

  send(command);
}

void HicnForwarderModule::init(
    Connector::PacketReceivedCallback &&receive_callback,
    Connector::PacketSentCallback &&sent_callback,
    Connector::OnCloseCallback &&close_callback,
    Connector::OnReconnectCallback &&reconnect_callback,
    asio::io_service &io_service, const std::string &app_name) {
  if (!connector_) {
    connector_.reset(new UdpTunnelConnector(
        io_service, std::move(receive_callback), std::move(sent_callback),
        std::move(close_callback), std::move(reconnect_callback)));
  }
}

void HicnForwarderModule::processControlMessageReply(
    utils::MemBuf &packet_buffer) {
  if (packet_buffer.data()[0] == NACK_LIGHT) {
    throw errors::RuntimeException(
        "Received Nack message from hicn light forwarder.");
  }
}

std::uint32_t HicnForwarderModule::getMtu() { return interface_mtu; }

bool HicnForwarderModule::isControlMessage(utils::MemBuf &packet_buffer) {
  return packet_buffer.data()[0] == ACK_LIGHT ||
         packet_buffer.data()[0] == NACK_LIGHT;
}

/**
 * @return A valid msg_route_add_t structure if the command was successful, or
 * with .command_id == COMMAND_TYPE_UNDEFINED in case of error.
 */
utils::MemBuf::Ptr HicnForwarderModule::createCommandRoute(
    std::unique_ptr<sockaddr> &&addr, uint8_t prefix_length) {
  auto ret = PacketManager<>::getInstance().getMemBuf();
  auto command = reinterpret_cast<msg_route_add_t *>(ret->writableData());
  ret->append(sizeof(msg_route_add_t));
  std::memset(command, 0, sizeof(*command));

  if (!IS_VALID_FAMILY(addr->sa_family)) return nullptr;

  *command = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_ROUTE_ADD,
              .length = 1,
              .seq_num = 0,
          },
      .payload =
          {
              .cost = 1,
              .family = (uint8_t)addr->sa_family,
              .len = prefix_length,
          },
  };

  switch (addr->sa_family) {
    case AF_INET:
      command->payload.address.v4.as_inaddr =
          ((sockaddr_in *)addr.get())->sin_addr;
      break;
    case AF_INET6:
      command->payload.address.v6.as_in6addr =
          ((sockaddr_in6 *)addr.get())->sin6_addr;
      break;
  }
  snprintf(command->payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
           "SELF");

  return ret;
}

utils::MemBuf::Ptr HicnForwarderModule::createCommandDeleteConnection() {
  auto ret = PacketManager<>::getInstance().getMemBuf();
  auto command =
      reinterpret_cast<msg_connection_remove_t *>(ret->writableData());
  ret->append(sizeof(msg_connection_remove_t));
  std::memset(command, 0, sizeof(*command));

  *command = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_REMOVE,
              .length = 1,
              .seq_num = 0,
          },
  };

  snprintf(command->payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
           "SELF");

  return ret;
}

utils::MemBuf::Ptr HicnForwarderModule::createCommandMapmeSendUpdate() {
  auto ret = PacketManager<>::getInstance().getMemBuf();
  auto command =
      reinterpret_cast<msg_mapme_send_update_t *>(ret->writableData());
  ret->append(sizeof(msg_mapme_send_update_t));
  std::memset(command, 0, sizeof(*command));

  *command = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_MAPME_SEND_UPDATE,
              .length = 1,
              .seq_num = seq_++,
          },
  };

  return ret;
}

utils::MemBuf::Ptr HicnForwarderModule::createCommandSetForwardingStrategy(
    std::unique_ptr<sockaddr> &&addr, uint32_t prefix_len,
    std::string strategy) {
  auto ret = PacketManager<>::getInstance().getMemBuf();
  auto command = reinterpret_cast<msg_strategy_set_t *>(ret->writableData());
  ret->append(sizeof(msg_strategy_set_t));
  std::memset(command, 0, sizeof(*command));

  if (!IS_VALID_FAMILY(addr->sa_family)) return nullptr;

  strategy_type_t strategy_type = strategy_type_from_str(strategy.c_str());
  if (strategy_type == STRATEGY_TYPE_UNDEFINED) return nullptr;

  *command = {
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_STRATEGY_SET,
              .length = 1,
              .seq_num = seq_++,
          },
      .payload =
          {
              .family = (uint8_t)addr->sa_family,
              .len = (uint8_t)prefix_len,
              .type = (uint8_t)strategy_type,
          },
  };

  switch (addr->sa_family) {
    case AF_INET:
      command->payload.address.v4.as_inaddr =
          ((sockaddr_in *)addr.get())->sin_addr;
      break;
    case AF_INET6:
      command->payload.address.v6.as_in6addr =
          ((sockaddr_in6 *)addr.get())->sin6_addr;
      break;
  }

  return ret;
}

extern "C" IoModule *create_module(void) { return new HicnForwarderModule(); }

}  // namespace core

}  // namespace transport
