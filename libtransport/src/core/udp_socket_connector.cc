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

#include <hicn/transport/errors/errors.h>
#include <hicn/transport/utils/log.h>
#include <hicn/transport/utils/object_pool.h>

#include <core/udp_socket_connector.h>

#include <thread>
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
      read_msg_(packet_pool_.makePtr(nullptr)),
      is_reconnection_(false),
      data_available_(false),
      app_name_(app_name) {}

UdpSocketConnector::~UdpSocketConnector() {}

void UdpSocketConnector::connect(std::string ip_address, std::string port) {
  endpoint_iterator_ = resolver_.resolve(
      {ip_address, port, asio::ip::resolver_query_base::numeric_service});

  state_ = ConnectorState::CONNECTING;
  doConnect();
}

void UdpSocketConnector::send(const uint8_t *packet, std::size_t len,
                              const PacketSentCallback &packet_sent) {
  if (packet_sent != 0) {
    socket_.async_send(
        asio::buffer(packet, len),
        [packet_sent](std::error_code ec, std::size_t /*length*/) {
          packet_sent();
        });
  } else {
    if (state_ == ConnectorState::CONNECTED) {
      try {
        socket_.send(asio::buffer(packet, len));
      } catch (std::system_error &err) {
        TRANSPORT_LOGE(
            "Sending of disconnect message to forwarder failed. Reason: %s",
            err.what());
      }
    }
  }
}

void UdpSocketConnector::send(const Packet::MemBufPtr &packet) {
  io_service_.post([this, packet]() {
    bool write_in_progress = !output_buffer_.empty();
    output_buffer_.push_back(std::move(packet));
    if (TRANSPORT_EXPECT_TRUE(state_ == ConnectorState::CONNECTED)) {
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
  if (io_service_.stopped()) {
    doClose();
  } else {
    io_service_.dispatch(std::bind(&UdpSocketConnector::doClose, this));
  }
}

void UdpSocketConnector::doClose() {
  if (state_ != ConnectorState::CLOSED) {
    state_ = ConnectorState::CLOSED;
    if (socket_.is_open()) {
      socket_.shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both);
      socket_.close();
    }
  }
}

void UdpSocketConnector::doWrite() {
  auto packet = output_buffer_.front().get();
  auto array = std::vector<asio::const_buffer>();

  const utils::MemBuf *current = packet;
  do {
    array.push_back(asio::const_buffer(current->data(), current->length()));
    current = current->next();
  } while (current != packet);

  socket_.async_send(std::move(array), [this](std::error_code ec,
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
  if (state_ == ConnectorState::CONNECTED) {
    TRANSPORT_LOGE("Connection lost. Trying to reconnect...\n");
    state_ = ConnectorState::CONNECTING;
    is_reconnection_ = true;
    io_service_.post([this]() {
      if (socket_.is_open()) {
        socket_.shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both);
        socket_.close();
      }

      doConnect();
      startConnectionTimer();
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    });
  }
}

void UdpSocketConnector::doConnect() {
  asio::async_connect(
      socket_, endpoint_iterator_,
      [this](std::error_code ec, udp::resolver::iterator) {
        if (!ec) {
          connection_timer_.cancel();
          state_ = ConnectorState::CONNECTED;
          doRead();

          if (data_available_) {
            data_available_ = false;
            doWrite();
          }

          if (is_reconnection_) {
            is_reconnection_ = false;
          }

          on_reconnect_callback_();
        } else {
          doConnect();
          std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
      });
}

bool UdpSocketConnector::checkConnected() {
  return state_ == ConnectorState::CONNECTED;
}

void UdpSocketConnector::startConnectionTimer() {
  connection_timer_.expires_from_now(std::chrono::seconds(60));
  connection_timer_.async_wait(std::bind(&UdpSocketConnector::handleDeadline,
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
