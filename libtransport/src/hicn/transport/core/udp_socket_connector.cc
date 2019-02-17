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

#ifdef _WIN32
#include <hicn/transport/portability/win_portability.h>
#endif
#include <hicn/transport/core/udp_socket_connector.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/utils/log.h>
#include <hicn/transport/utils/object_pool.h>

#include <vector>

namespace transport {

namespace core {

UdpSocketConnector::UdpSocketConnector(
    PacketReceivedCallback &&receive_callback,
    OnReconnect &&on_reconnect_callback, asio::io_service &io_service,
    std::string app_name)
    : Connector(std::move(receive_callback), std::move(on_reconnect_callback)),
      io_service_(io_service),
      socket_(io_service_),
      resolver_(io_service_),
      connection_timer_(io_service_),
      connection_timeout_(io_service_),
      read_msg_(packet_pool_.makePtr(nullptr)),
      is_connecting_(false),
      is_reconnection_(false),
      data_available_(false),
      is_closed_(false),
      app_name_(app_name) {}

UdpSocketConnector::~UdpSocketConnector() {}

void UdpSocketConnector::connect(std::string ip_address, std::string port) {
  endpoint_iterator_ = resolver_.resolve(
      {ip_address, port, asio::ip::resolver_query_base::numeric_service});

  doConnect();
}

void UdpSocketConnector::state() { return; }

void UdpSocketConnector::send(const uint8_t *packet, std::size_t len,
                              const PacketSentCallback &packet_sent) {
  socket_.async_send(asio::buffer(packet, len),
                     [packet_sent](std::error_code ec, std::size_t /*length*/) {
                       packet_sent();
                     });
}

void UdpSocketConnector::send(const Packet::MemBufPtr &packet) {
  io_service_.post([this, packet]() {
    bool write_in_progress = !output_buffer_.empty();
    output_buffer_.push_back(std::move(packet));
    if (TRANSPORT_EXPECT_FALSE(!is_connecting_)) {
      if (!write_in_progress) {
        doWrite();
      }
    } else {
      // Tell the handle connect it has data to write
      data_available_ = true;
    }
  });
}

void UdpSocketConnector::close() {
  io_service_.dispatch([this]() {
    is_closed_ = true;
    socket_.shutdown(asio::ip::udp::socket::shutdown_type::shutdown_both);
    socket_.close();
  });
}

void UdpSocketConnector::doWrite() {
  // TODO improve this piece of code for sending many buffers togethers
  // if list contains more than one packet
  auto packet = output_buffer_.front().get();
  auto array = std::vector<asio::const_buffer>();

  const utils::MemBuf *current = packet;
  do {
    array.push_back(asio::const_buffer(current->data(), current->length()));
    current = current->next();
  } while (current != packet);

  socket_.async_send(std::move(array), [this /*, packet*/](std::error_code ec,
                                                           std::size_t length) {
    if (TRANSPORT_EXPECT_TRUE(!ec)) {
      output_buffer_.pop_front();
      if (!output_buffer_.empty()) {
        doWrite();
      }
    } else if (ec.value() == static_cast<int>(std::errc::operation_canceled)) {
      // The connection has been closed by the application.
      return;
    } else {
      TRANSPORT_LOGE("%d %s", ec.value(), ec.message().c_str());
      tryReconnect();
    }
  });
}

void UdpSocketConnector::doRead() {
  read_msg_ = getPacket();
  socket_.async_receive(
      asio::buffer(read_msg_->writableData(), Connector::packet_size),
      [this](std::error_code ec, std::size_t length) {
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          read_msg_->append(length);
          receive_callback_(std::move(read_msg_));
          doRead();
        } else if (ec.value() ==
                   static_cast<int>(std::errc::operation_canceled)) {
          // The connection has been closed by the application.
          return;
        } else {
          TRANSPORT_LOGE("%d %s", ec.value(), ec.message().c_str());
          tryReconnect();
        }
      });
}

void UdpSocketConnector::tryReconnect() {
  if (!is_connecting_ && !is_closed_) {
    TRANSPORT_LOGE("Connection lost. Trying to reconnect...\n");
    is_connecting_ = true;
    is_reconnection_ = true;
    connection_timer_.expires_from_now(std::chrono::seconds(1));
    connection_timer_.async_wait([this](const std::error_code &ec) {
      if (!ec) {
        socket_.shutdown(asio::ip::udp::socket::shutdown_type::shutdown_both);
        socket_.close();
        startConnectionTimer();
        doConnect();
      }
    });
  }
}

void UdpSocketConnector::doConnect() {
  asio::async_connect(socket_, endpoint_iterator_,
                      [this](std::error_code ec, udp::resolver::iterator) {
                        if (!ec) {
                          connection_timeout_.cancel();
                          is_connecting_ = false;
                          doRead();

                          if (data_available_) {
                            data_available_ = false;
                            doWrite();
                          }

                          if (is_reconnection_) {
                            is_reconnection_ = false;
                            on_reconnect_callback_();
                          }
                        } else {
                          sleep(1);
                          doConnect();
                        }
                      });
}

bool UdpSocketConnector::checkConnected() { return !is_connecting_; }

void UdpSocketConnector::enableBurst() { return; }

void UdpSocketConnector::startConnectionTimer() {
  connection_timeout_.expires_from_now(std::chrono::seconds(60));
  connection_timeout_.async_wait(std::bind(&UdpSocketConnector::handleDeadline,
                                           this, std::placeholders::_1));
}

void UdpSocketConnector::handleDeadline(const std::error_code &ec) {
  if (!ec) {
    io_service_.post([this]() {
      socket_.close();
      TRANSPORT_LOGE("Error connecting. Is the forwarder running?\n");
      io_service_.stop();
    });
  }
}

}  // end namespace core

}  // end namespace transport
