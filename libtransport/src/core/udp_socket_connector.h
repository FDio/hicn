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

#pragma once

#include <core/connector.h>
#include <hicn/transport/config.h>
#include <hicn/transport/utils/branch_prediction.h>
#include <hicn/transport/utils/log.h>

#include <asio.hpp>
#include <asio/steady_timer.hpp>
#include <deque>
#include <thread>

namespace transport {
namespace core {

using asio::ip::udp;

template <typename PacketHandler>
class UdpSocketConnector
    : public ConnectorBase<PacketHandler, UdpSocketConnector<PacketHandler>> {
  using Connector = ConnectorBase<PacketHandler, UdpSocketConnector<PacketHandler>>;
  using Connector::Connector;

 public:
  UdpSocketConnector(PacketHandler &handler, asio::io_service &io_service,
                     std::string app_name = "Libtransport")
      : Connector(handler),
        io_service_(io_service),
        socket_(io_service_),
        resolver_(io_service_),
        connection_timer_(io_service_),
        read_msg_(Connector::packet_pool_.makePtr(nullptr)),
        is_reconnection_(false),
        data_available_(false),
        app_name_(app_name) {}

  ~UdpSocketConnector() = default;

  TRANSPORT_ALWAYS_INLINE void send(const Packet::MemBufPtr &packet) {
    io_service_.post([this, packet]() {
      bool write_in_progress = !Connector::output_buffer_.empty();
      Connector::output_buffer_.push_back(std::move(packet));
      if (TRANSPORT_EXPECT_TRUE(Connector::state_ ==
                                Connector::ConnectorState::CONNECTED)) {
        if (!write_in_progress) {
          doWrite();
        }
      } else {
        // Tell the handle connect it has data to write
        data_available_ = true;
      }
    });
  }

  TRANSPORT_ALWAYS_INLINE void send(
      const uint8_t *packet, std::size_t len,
      const typename Connector::PacketSentCallback &packet_sent = 0) {
    if (packet_sent != 0) {
      socket_.async_send(
          asio::buffer(packet, len),
          [packet_sent](std::error_code ec, std::size_t /*length*/) {
            packet_sent();
          });
    } else {
      if (Connector::state_ == Connector::ConnectorState::CONNECTED) {
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

  TRANSPORT_ALWAYS_INLINE void close() {
    if (io_service_.stopped()) {
      doClose();
    } else {
      io_service_.dispatch(std::bind(&UdpSocketConnector::doClose, this));
    }
  }

  TRANSPORT_ALWAYS_INLINE void connect(std::string ip_address = "127.0.0.1",
                                       std::string port = "9695") {
    endpoint_iterator_ = resolver_.resolve(
        {ip_address, port, asio::ip::resolver_query_base::numeric_service});

    Connector::state_ = Connector::ConnectorState::CONNECTING;
    doConnect();
  }

 private:
  TRANSPORT_ALWAYS_INLINE void doConnect() {
    asio::async_connect(
        socket_, endpoint_iterator_,
        [this](std::error_code ec, udp::resolver::iterator) {
          if (!ec) {
            connection_timer_.cancel();
            Connector::state_ = Connector::ConnectorState::CONNECTED;
            doRead();

            if (data_available_) {
              data_available_ = false;
              doWrite();
            }

            if (is_reconnection_) {
              is_reconnection_ = false;
            }

            // on_reconnect_callback_();
          } else {
            doConnect();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
          }
        });
  }

  TRANSPORT_ALWAYS_INLINE void doRead() {
    read_msg_ = Connector::getPacket();
    socket_.async_receive(
        asio::buffer(read_msg_->writableData(), Connector::packet_size),
        [this](std::error_code ec, std::size_t length) {
          if (TRANSPORT_EXPECT_TRUE(!ec)) {
            read_msg_->append(length);
            Connector::packet_handler_.processIncomingMessages(
                std::move(read_msg_));
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

  TRANSPORT_ALWAYS_INLINE void doWrite() {
    auto packet = Connector::output_buffer_.front().get();
    auto array = std::vector<asio::const_buffer>();

    const utils::MemBuf *current = packet;
    do {
      array.push_back(asio::const_buffer(current->data(), current->length()));
      current = current->next();
    } while (current != packet);

    socket_.async_send(
        std::move(array), [this](std::error_code ec, std::size_t length) {
          if (TRANSPORT_EXPECT_TRUE(!ec)) {
            Connector::output_buffer_.pop_front();
            if (!Connector::output_buffer_.empty()) {
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

  TRANSPORT_ALWAYS_INLINE void doClose() {
    if (Connector::state_ != Connector::ConnectorState::CLOSED) {
      Connector::state_ = Connector::ConnectorState::CLOSED;
      if (socket_.is_open()) {
        socket_.shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both);
        socket_.close();
      }
    }
  }

  TRANSPORT_ALWAYS_INLINE void handleDeadline(const std::error_code &ec) {
    if (!ec) {
      io_service_.post([this]() {
        socket_.close();
        TRANSPORT_LOGE("Error connecting. Is the forwarder running?\n");
        io_service_.stop();
      });
    }
  }

  TRANSPORT_ALWAYS_INLINE void startConnectionTimer() {
    connection_timer_.expires_from_now(std::chrono::seconds(60));
    connection_timer_.async_wait(std::bind(&UdpSocketConnector::handleDeadline,
                                           this, std::placeholders::_1));
  }

  TRANSPORT_ALWAYS_INLINE void tryReconnect() {
    if (Connector::state_ == Connector::ConnectorState::CONNECTED) {
      TRANSPORT_LOGE("Connection lost. Trying to reconnect...\n");
      Connector::state_ = Connector::ConnectorState::CONNECTING;
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

 private:
  asio::io_service &io_service_;
  asio::ip::udp::socket socket_;
  asio::ip::udp::resolver resolver_;
  asio::ip::udp::resolver::iterator endpoint_iterator_;
  asio::steady_timer connection_timer_;

  utils::ObjectPool<utils::MemBuf>::Ptr read_msg_;

  bool is_reconnection_;
  bool data_available_;

  std::string app_name_;
};

}  // end namespace core

}  // end namespace transport
