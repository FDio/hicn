/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "ATSConnector.h"
#include "HTTP1.xMessageFastParser.h"

#include <hicn/transport/utils/branch_prediction.h>
#include <hicn/transport/utils/log.h>
#include <iostream>

namespace transport {

ATSConnector::ATSConnector(asio::io_service &io_service,
                           std::string &ip_address, std::string &port,
                           ContentReceivedCallback receive_callback,
                           OnReconnect on_reconnect_callback)
    : io_service_(io_service),
      socket_(io_service_),
      resolver_(io_service_),
      endpoint_iterator_(resolver_.resolve({ip_address, port})),
      timer_(io_service),
      is_reconnection_(false),
      data_available_(false),
      receive_callback_(receive_callback),
      on_reconnect_callback_(on_reconnect_callback) {
  input_buffer_.prepare(buffer_size + 2048);
  state_ = ConnectorState::CONNECTING;
  doConnect();
}

ATSConnector::~ATSConnector() {}

void ATSConnector::send(const uint8_t *packet, std::size_t len,
                        ContentSentCallback &&content_sent) {
  asio::async_write(
      socket_, asio::buffer(packet, len),
      [content_sent = std::move(content_sent)](
          std::error_code ec, std::size_t /*length*/) { content_sent(); });
}

void ATSConnector::send(utils::MemBuf *buffer,
                        ContentSentCallback &&content_sent) {
  io_service_.dispatch([this, buffer, callback = std::move(content_sent)]() {
    bool write_in_progress = !write_msgs_.empty();
    write_msgs_.emplace_back(std::unique_ptr<utils::MemBuf>(buffer),
                             std::move(callback));
    if (TRANSPORT_EXPECT_TRUE(state_ == ConnectorState::CONNECTED)) {
      if (!write_in_progress) {
        doWrite();
      }
    } else {
      TRANSPORT_LOGD("Tell the handle connect it has data to write");
      data_available_ = true;
    }
  });
}

void ATSConnector::close() {
  if (state_ != ConnectorState::CLOSED) {
    state_ = ConnectorState::CLOSED;
    if (socket_.is_open()) {
      socket_.shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both);
      socket_.close();
      // on_disconnect_callback_();
    }
  }
}

void ATSConnector::doWrite() {
  auto &buffer = write_msgs_.front().first;

  asio::async_write(socket_, asio::buffer(buffer->data(), buffer->length()),
                    [this](std::error_code ec, std::size_t length) {
                      if (TRANSPORT_EXPECT_FALSE(!ec)) {
                        TRANSPORT_LOGD("Content successfully sent!");
                        write_msgs_.front().second();
                        write_msgs_.pop_front();
                        if (!write_msgs_.empty()) {
                          doWrite();
                        }
                      } else {
                        TRANSPORT_LOGD("Content NOT sent!");
                      }
                    });
}  // namespace transport

void ATSConnector::handleRead(std::error_code ec, std::size_t length,
                              std::size_t size) {
  if (TRANSPORT_EXPECT_TRUE(!ec)) {
    size -= length;
    const uint8_t *buffer =
        asio::buffer_cast<const uint8_t *>(input_buffer_.data());
    receive_callback_(buffer, input_buffer_.size(), !size, false);
    input_buffer_.consume(input_buffer_.size());

    if (!size) {
      doReadHeader();
    } else {
      auto to_read = size >= buffer_size ? buffer_size : size;
      asio::async_read(
          socket_, input_buffer_, asio::transfer_exactly(to_read),
          std::bind(&ATSConnector::handleRead, this, std::placeholders::_1,
                    std::placeholders::_2, size));
    }
  } else if (ec == asio::error::eof) {
    input_buffer_.consume(input_buffer_.size());
    tryReconnection();
  }
}

void ATSConnector::doReadBody(std::size_t size) {
  auto to_read =
      size >= buffer_size ? (buffer_size - input_buffer_.size()) : size;
  asio::async_read(
      socket_, input_buffer_, asio::transfer_exactly(to_read),
      std::bind(&ATSConnector::handleRead, this, std::placeholders::_1,
                std::placeholders::_2, size));
}

void ATSConnector::doReadHeader() {
  asio::async_read_until(
      socket_, input_buffer_, "\r\n\r\n",
      [this](std::error_code ec, std::size_t length) {
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          const uint8_t *buffer =
              asio::buffer_cast<const uint8_t *>(input_buffer_.data());
          std::size_t size = HTTPMessageFastParser::hasBody(buffer, length);

          auto additional_bytes = input_buffer_.size() - length;
          auto bytes_to_read =
              size >= additional_bytes ? (size - additional_bytes) : size;

          receive_callback_(buffer, length, !size, true);
          input_buffer_.consume(length);

          doReadBody(bytes_to_read);
        } else {
          input_buffer_.consume(input_buffer_.size());
          tryReconnection();
        }
      });
}

void ATSConnector::tryReconnection() {
  TRANSPORT_LOGD("Connection lost. Trying to reconnect...\n");
  if (state_ == ConnectorState::CONNECTED) {
    state_ = ConnectorState::CONNECTING;
    is_reconnection_ = true;
    io_service_.post([this]() {
      if (socket_.is_open()) {
        // socket_.shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both);
        socket_.close();
      }
      startConnectionTimer();
      doConnect();
    });
  }
}

void ATSConnector::doConnect() {
  asio::async_connect(socket_, endpoint_iterator_,
                      [this](std::error_code ec, tcp::resolver::iterator) {
                        if (!ec) {
                          timer_.cancel();
                          state_ = ConnectorState::CONNECTED;

                          asio::ip::tcp::no_delay noDelayOption(true);
                          socket_.set_option(noDelayOption);

                          // on_reconnect_callback_();

                          doReadHeader();

                          if (data_available_ && !write_msgs_.empty()) {
                            data_available_ = false;
                            doWrite();
                          }

                          if (is_reconnection_) {
                            is_reconnection_ = false;
                            TRANSPORT_LOGD("Connection recovered!");
                          }

                        } else {
                          TRANSPORT_LOGE("Impossible to reconnect: %s",
                                         ec.message().c_str());
                          close();
                        }
                      });
}

bool ATSConnector::checkConnected() {
  return state_ == ConnectorState::CONNECTED;
}

void ATSConnector::startConnectionTimer() {
  timer_.expires_from_now(std::chrono::seconds(10));
  timer_.async_wait(
      std::bind(&ATSConnector::handleDeadline, this, std::placeholders::_1));
}

void ATSConnector::handleDeadline(const std::error_code &ec) {
  if (!ec) {
    io_service_.post([this]() {
      socket_.close();
      TRANSPORT_LOGE("Error connecting. Is the server running?\n");
      io_service_.stop();
    });
  }
}

}  // namespace transport
