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
#include <hicn/transport/core/tcp_socket_connector.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/utils/log.h>
#include <hicn/transport/utils/object_pool.h>

#include <vector>

namespace transport {

namespace core {

namespace {
class NetworkMessage {
 public:
  static constexpr std::size_t fixed_header_length = 10;

  static std::size_t decodeHeader(const uint8_t *packet) {
    // General checks
    // CCNX Control packet format
    uint8_t first_byte = packet[0];
    uint8_t ip_format = (packet[0] & 0xf0) >> 4;

    if (TRANSPORT_EXPECT_FALSE(first_byte == 102)) {
      // Get packet length
      return 44;
    } else if (TRANSPORT_EXPECT_TRUE(ip_format == 6 || ip_format == 4)) {
      Packet::Format format = Packet::getFormatFromBuffer(packet);
      return Packet::getHeaderSizeFromBuffer(format, packet) +
             Packet::getPayloadSizeFromBuffer(format, packet);
    }

    return 0;
  }
};
}  // namespace

TcpSocketConnector::TcpSocketConnector(PacketReceivedCallback &&receive_callback,
                                 OnReconnect &&on_reconnect_callback,
                                 asio::io_service &io_service,
                                 std::string app_name)
    : Connector(),
      io_service_(io_service),
      socket_(io_service_),
      resolver_(io_service_),
      timer_(io_service_),
      read_msg_(packet_pool_.makePtr(nullptr)),
      is_connecting_(false),
      is_reconnection_(false),
      data_available_(false),
      is_closed_(false),
      receive_callback_(receive_callback),
      on_reconnect_callback_(on_reconnect_callback),
      app_name_(app_name) {}

TcpSocketConnector::~TcpSocketConnector() {}

void TcpSocketConnector::connect(std::string ip_address, std::string port) {
  endpoint_iterator_ = resolver_.resolve(
      {ip_address, port, asio::ip::resolver_query_base::numeric_service});

  doConnect();
}

void TcpSocketConnector::state() { return; }

void TcpSocketConnector::send(const uint8_t *packet, std::size_t len,
                           const PacketSentCallback &packet_sent) {
  asio::async_write(socket_, asio::buffer(packet, len),
                    [packet_sent](std::error_code ec, std::size_t /*length*/) {
                      packet_sent();
                    });
}

void TcpSocketConnector::send(const Packet::MemBufPtr &packet) {
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

void TcpSocketConnector::close() {
  io_service_.dispatch([this]() {
    is_closed_ = true;
    socket_.shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both);
    socket_.close();
  });
}

void TcpSocketConnector::doWrite() {
  // TODO improve this piece of code for sending many buffers togethers
  // if list contains more than one packet
  auto packet = output_buffer_.front().get();
  auto array = std::vector<asio::const_buffer>();

  const utils::MemBuf *current = packet;
  do {
    array.push_back(asio::const_buffer(current->data(), current->length()));
    current = current->next();
  } while (current != packet);

  asio::async_write(
      socket_, std::move(array),
      [this /*, packet*/](std::error_code ec, std::size_t length) {
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          output_buffer_.pop_front();
          if (!output_buffer_.empty()) {
            doWrite();
          }
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

void TcpSocketConnector::doReadBody(std::size_t body_length) {
  asio::async_read(
      socket_, asio::buffer(read_msg_->writableTail(), body_length),
      asio::transfer_exactly(body_length),
      [this](std::error_code ec, std::size_t length) {
        read_msg_->append(length);
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          receive_callback_(std::move(read_msg_));
          doReadHeader();
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

void TcpSocketConnector::doReadHeader() {
  read_msg_ = getPacket();
  asio::async_read(
      socket_,
      asio::buffer(read_msg_->writableData(),
                   NetworkMessage::fixed_header_length),
      asio::transfer_exactly(NetworkMessage::fixed_header_length),
      [this](std::error_code ec, std::size_t length) {
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          read_msg_->append(NetworkMessage::fixed_header_length);
          std::size_t body_length = 0;
          if ((body_length = NetworkMessage::decodeHeader(read_msg_->data())) >
              0) {
            doReadBody(body_length - length);
          } else {
            TRANSPORT_LOGE("Decoding error. Ignoring packet.");
          }
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

void TcpSocketConnector::tryReconnect() {
  if (!is_connecting_ && !is_closed_) {
    TRANSPORT_LOGE("Connection lost. Trying to reconnect...\n");
    is_connecting_ = true;
    is_reconnection_ = true;
    io_service_.post([this]() {
      socket_.shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both);
      socket_.close();
      startConnectionTimer();
      doConnect();
    });
  }
}

void TcpSocketConnector::doConnect() {
  asio::async_connect(socket_, endpoint_iterator_,
                      [this](std::error_code ec, tcp::resolver::iterator) {
                        if (!ec) {
                          timer_.cancel();
                          is_connecting_ = false;
                          asio::ip::tcp::no_delay noDelayOption(true);
                          socket_.set_option(noDelayOption);
                          doReadHeader();

                          if (data_available_) {
                            data_available_ = false;
                            doWrite();
                          }

                          if (is_reconnection_) {
                            is_reconnection_ = false;
                            TRANSPORT_LOGI("Connection recovered!\n");
                            on_reconnect_callback_();
                          }
                        } else {
                          sleep(1);
                          doConnect();
                        }
                      });
}

bool TcpSocketConnector::checkConnected() { return !is_connecting_; }

void TcpSocketConnector::enableBurst() { return; }

void TcpSocketConnector::startConnectionTimer() {
  timer_.expires_from_now(std::chrono::seconds(60));
  timer_.async_wait(
      std::bind(&TcpSocketConnector::handleDeadline, this, std::placeholders::_1));
}

void TcpSocketConnector::handleDeadline(const std::error_code &ec) {
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
