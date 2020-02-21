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

#include <hicn/transport/core/raw_socket_connector.h>
#include <hicn/transport/utils/conversions.h>
#include <hicn/transport/utils/log.h>

#include <net/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define MY_DEST_MAC0 0x0a
#define MY_DEST_MAC1 0x7b
#define MY_DEST_MAC2 0x7c
#define MY_DEST_MAC3 0x1c
#define MY_DEST_MAC4 0x4a
#define MY_DEST_MAC5 0x14

namespace transport {

namespace core {

RawSocketConnector::RawSocketConnector(
    PacketReceivedCallback &&receive_callback,
    OnReconnect &&on_reconnect_callback, asio::io_service &io_service,
    std::string app_name)
    : Connector(std::move(receive_callback), std::move(on_reconnect_callback)),
      io_service_(io_service),
      socket_(io_service_, raw_protocol(PF_PACKET, SOCK_RAW)),
      // resolver_(io_service_),
      timer_(io_service_),
      read_msg_(packet_pool_.makePtr(nullptr)),
      data_available_(false),
      app_name_(app_name) {
  memset(&link_layer_address_, 0, sizeof(link_layer_address_));
}

RawSocketConnector::~RawSocketConnector() {}

void RawSocketConnector::connect(const std::string &interface_name,
                                 const std::string &mac_address_str) {
  state_ = ConnectorState::CONNECTING;
  memset(&ethernet_header_, 0, sizeof(ethernet_header_));
  struct ifreq ifr;
  struct ifreq if_mac;
  uint8_t mac_address[6];

  utils::convertStringToMacAddress(mac_address_str, mac_address);

  // Get interface mac address
  int fd = static_cast<int>(socket_.native_handle());

  /* Get the index of the interface to send on */
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, interface_name.c_str(), interface_name.size());

  // if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
  //     perror("SIOCGIFINDEX");
  // }

  /* Get the MAC address of the interface to send on */
  memset(&if_mac, 0, sizeof(struct ifreq));
  strncpy(if_mac.ifr_name, interface_name.c_str(), interface_name.size());
  if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
    perror("SIOCGIFHWADDR");
    throw errors::RuntimeException("Interface does not exist");
  }

  /* Ethernet header */
  for (int i = 0; i < 6; i++) {
    ethernet_header_.ether_shost[i] =
        ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[i];
    ethernet_header_.ether_dhost[i] = mac_address[i];
  }

  /* Ethertype field */
  ethernet_header_.ether_type = htons(ETH_P_IPV6);

  strcpy(ifr.ifr_name, interface_name.c_str());

  if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
    memcpy(link_layer_address_.sll_addr, ifr.ifr_hwaddr.sa_data, 6);
  }

  // memset(&ifr, 0, sizeof(ifr));
  // ioctl(fd, SIOCGIFFLAGS, &ifr);
  // ifr.ifr_flags |= IFF_PROMISC;
  // ioctl(fd, SIOCSIFFLAGS, &ifr);

  link_layer_address_.sll_family = AF_PACKET;
  link_layer_address_.sll_protocol = htons(ETH_P_ALL);
  link_layer_address_.sll_ifindex = if_nametoindex(interface_name.c_str());
  link_layer_address_.sll_hatype = 1;
  link_layer_address_.sll_halen = 6;

  // startConnectionTimer();
  doConnect();
  doRecvPacket();
}

void RawSocketConnector::send(const uint8_t *packet, std::size_t len,
                              const PacketSentCallback &packet_sent) {
  if (packet_sent != 0) {
    socket_.async_send(
        asio::buffer(packet, len),
        [packet_sent](std::error_code ec, std::size_t /*length*/) {
          packet_sent();
        });
  } else {
    if (state_ == ConnectorState::CONNECTED) {
      socket_.send(asio::buffer(packet, len));
    }
  }
}

void RawSocketConnector::send(const Packet::MemBufPtr &packet) {
  io_service_.post([this, packet]() {
    bool write_in_progress = !output_buffer_.empty();
    output_buffer_.push_back(std::move(packet));
    if (TRANSPORT_EXPECT_TRUE(state_ == ConnectorState::CONNECTED)) {
      if (!write_in_progress) {
        doSendPacket();
      } else {
        // Tell the handle connect it has data to write
        data_available_ = true;
      }
    }
  });
}

void RawSocketConnector::close() {
  io_service_.post([this]() { socket_.close(); });
}

void RawSocketConnector::doSendPacket() {
  auto packet = output_buffer_.front().get();
  auto array = std::vector<asio::const_buffer>();

  const utils::MemBuf *current = packet;
  do {
    array.push_back(asio::const_buffer(current->data(), current->length()));
    current = current->next();
  } while (current != packet);

  socket_.async_send(
      std::move(array),
      [this /*, packet*/](std::error_code ec, std::size_t bytes_transferred) {
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          output_buffer_.pop_front();
          if (!output_buffer_.empty()) {
            doSendPacket();
          }
        } else {
          TRANSPORT_LOGE("%d %s", ec.value(), ec.message().c_str());
        }
      });
}

void RawSocketConnector::doRecvPacket() {
  read_msg_ = getPacket();
  socket_.async_receive(
      asio::buffer(read_msg_->writableData(), packet_size),
      [this](std::error_code ec, std::size_t bytes_transferred) mutable {
        if (!ec) {
          // Ignore packets that are not for us
          uint8_t *dst_mac_address = const_cast<uint8_t *>(read_msg_->data());
          if (!std::memcmp(dst_mac_address, ethernet_header_.ether_shost,
                           ETHER_ADDR_LEN)) {
            read_msg_->append(bytes_transferred);
            read_msg_->trimStart(sizeof(struct ether_header));
            receive_callback_(std::move(read_msg_));
          }
        } else {
          TRANSPORT_LOGE("%d %s", ec.value(), ec.message().c_str());
        }
        doRecvPacket();
      });
}

void RawSocketConnector::doConnect() {
  state_ = ConnectorState::CONNECTED;
  socket_.bind(raw_endpoint(&link_layer_address_, sizeof(link_layer_address_)));
}

}  // end namespace core

}  // end namespace transport
