/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <hicn/transport/core/hicn_forwarder_interface.h>

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
//static constexpr uint8_t delete_connection_command = 5;
static constexpr uint8_t request_light = 0xc0;
static constexpr char identifier[] = "SELF";

void fillCommandHeader(CommandHeader *header) {
  // Allocate and fill the header
  header->message_type = request_light;
  header->length = 1;
}

std::unique_ptr<RouteToSelfCommand> createCommandRoute(
    std::unique_ptr<sockaddr> &&addr, uint8_t prefix_length) {
  auto command = std::make_unique<RouteToSelfCommand>();

  // check and set IP address
  if (addr->sa_family == AF_INET) {
    command->address_type = addr_inet;
    command->address.ipv4 = ((sockaddr_in *)addr.get())->sin_addr.s_addr;
  } else if (addr->sa_family == AF_INET6) {
    command->address_type = addr_inet6;
    command->address.ipv6 = ((sockaddr_in6 *)addr.get())->sin6_addr;
  }

  // Fill remaining payload fields
#ifndef _WIN32
  strcpy(command->symbolic_or_connid, identifier);
#else
  strcpy_s(route_to_self->symbolic_or_connid,
           strlen(route_to_self->symbolic_or_connid), identifier);
#endif
  command->cost = 1;
  command->len = (uint8_t)prefix_length;

  // Allocate and fill the header
  command->command_id = add_route_command;
  fillCommandHeader((CommandHeader *)command.get());

  return command;
}

/*std::unique_ptr<DeleteSelfConnectionCommand> createCommandDeleteConnection() {
  auto command = std::make_unique<DeleteSelfConnectionCommand>();
  fillCommandHeader((CommandHeader *)command.get());
  command->command_id = delete_connection_command;

#ifndef _WIN32
  strcpy(command->symbolic_or_connid, identifier);
#else
  strcpy_s(route_to_self->symbolic_or_connid,
           strlen(route_to_self->symbolic_or_connid), identifier);
#endif

  return command;
}*/

}  // namespace

namespace transport {

namespace core {

HicnForwarderInterface::HicnForwarderInterface(ConnectorType &connector)
    : ForwarderInterface<HicnForwarderInterface, ConnectorType>(
          connector) {}

HicnForwarderInterface::~HicnForwarderInterface() {}

void HicnForwarderInterface::connect(bool is_consumer) { connector_.connect(); }

void HicnForwarderInterface::registerRoute(Prefix &prefix) {
  auto command =
      createCommandRoute(prefix.toSockaddr(), prefix.getPrefixLength())
          .release();
  send((uint8_t *)command, sizeof(RouteToSelfCommand),
       [command]() { delete command; });
}

void HicnForwarderInterface::closeConnection() {
  connector_.close();
  /*auto command = createCommandDeleteConnection().release();
  send((uint8_t *)command, sizeof(DeleteSelfConnectionCommand),
       [this, command]() {
         delete command;
         connector_.close();
       });*/
}

}  // namespace core

}  // namespace transport
