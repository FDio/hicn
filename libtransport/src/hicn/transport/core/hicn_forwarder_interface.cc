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

#define ADDR_INET 1
#define ADDR_INET6 2
#define ADD_ROUTE 3
#define REQUEST_LIGHT 0xc0

union AddressLight {
  uint32_t ipv4;
  struct in6_addr ipv6;
};

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

namespace transport {

namespace core {

HicnForwarderInterface::HicnForwarderInterface(UdpSocketConnector &connector)
    : ForwarderInterface<HicnForwarderInterface, UdpSocketConnector>(connector) {}

HicnForwarderInterface::~HicnForwarderInterface() {}

void HicnForwarderInterface::connect(bool is_consumer) { connector_.connect(); }

void HicnForwarderInterface::registerRoute(Prefix &prefix) {
  auto addr = prefix.toSockaddr();
  const char *identifier = {"SELF_ROUTE"};

  // allocate command payload
  RouteToSelfCommand *route_to_self = new RouteToSelfCommand();

  // check and set IP address
  if (addr->sa_family == AF_INET) {
    route_to_self->address_type = ADDR_INET;
    route_to_self->address.ipv4 = ((Sockaddr4 *)addr.get())->sin_addr.s_addr;
  } else if (addr->sa_family == AF_INET6) {
    route_to_self->address_type = ADDR_INET6;
    route_to_self->address.ipv6 = ((Sockaddr6 *)addr.get())->sin6_addr;
  }

  // Fill remaining payload fields
#ifndef _WIN32
  strcpy(route_to_self->symbolic_or_connid, identifier);
#else
  strcpy_s(route_to_self->symbolic_or_connid, strlen(route_to_self->symbolic_or_connid), identifier);
#endif
  route_to_self->cost = 1;
  route_to_self->len = (uint8_t) prefix.getPrefixLength();

  // Allocate and fill the header
  route_to_self->command_id = ADD_ROUTE;
  route_to_self->message_type = REQUEST_LIGHT;
  route_to_self->length = 1;

  send((uint8_t *)route_to_self, sizeof(RouteToSelfCommand),
       [route_to_self]() { delete route_to_self; });
}

}  // namespace core

}  // namespace transport
