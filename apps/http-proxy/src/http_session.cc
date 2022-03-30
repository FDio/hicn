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

#include <hicn/http-proxy/http_proxy.h>
#include <hicn/transport/utils/branch_prediction.h>
#include <hicn/transport/utils/log.h>

#include <iostream>

namespace transport {

HTTPSession::HTTPSession(asio::io_service &io_service, std::string &ip_address,
                         std::string &port,
                         ContentReceivedCallback receive_callback,
                         OnConnectionClosed on_connection_closed_callback,
                         bool client)
    : io_service_(io_service),
      socket_(io_service_),
      resolver_(io_service_),
      endpoint_iterator_(resolver_.resolve({ip_address, port})),
      timer_(io_service),
      reverse_(client),
      is_reconnection_(false),
      data_available_(false),
      content_length_(0),
      is_last_chunk_(false),
      chunked_(false),
      receive_callback_(receive_callback),
      on_connection_closed_callback_(on_connection_closed_callback) {
  input_buffer_.prepare(buffer_size + 2048);
  state_ = ConnectorState::CONNECTING;

  if (reverse_) {
    header_info_ = std::make_unique<RequestMetadata>();
  } else {
    header_info_ = std::make_unique<ResponseMetadata>();
  }

  doConnect();
}

HTTPSession::HTTPSession(asio::ip::tcp::socket socket,
                         ContentReceivedCallback receive_callback,
                         OnConnectionClosed on_connection_closed_callback,
                         bool client)
    :
#if ((ASIO_VERSION / 100 % 1000) < 12)
      io_service_(socket.get_io_service()),
#else
      io_service_((asio::io_context &)(socket.get_executor().context())),
#endif
      socket_(std::move(socket)),
      resolver_(io_service_),
      timer_(io_service_),
      reverse_(client),
      is_reconnection_(false),
      data_available_(false),
      content_length_(0),
      is_last_chunk_(false),
      chunked_(false),
      receive_callback_(receive_callback),
      on_connection_closed_callback_(on_connection_closed_callback) {
  input_buffer_.prepare(buffer_size + 2048);
  state_ = ConnectorState::CONNECTED;
  asio::ip::tcp::no_delay noDelayOption(true);
  socket_.set_option(noDelayOption);

  if (reverse_) {
    header_info_ = std::make_unique<RequestMetadata>();
  } else {
    header_info_ = std::make_unique<ResponseMetadata>();
  }
  doReadHeader();
}

HTTPSession::~HTTPSession() {}

void HTTPSession::send(const uint8_t *packet, std::size_t len,
                       ContentSentCallback &&content_sent) {
  io_service_.dispatch([this, packet, len, content_sent]() {
    asio::async_write(socket_, asio::buffer(packet, len),
                      [content_sent = std::move(content_sent)](
                          const std::error_code &ec, std::size_t /*length*/) {
                        if (!ec) {
                          content_sent();
                        }
                      });
  });
}

void HTTPSession::send(utils::MemBuf *buffer,
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
      data_available_ = true;
    }
  });
}

void HTTPSession::close() {
  if (state_ != ConnectorState::CLOSED) {
    state_ = ConnectorState::CLOSED;
    if (socket_.is_open()) {
      // socket_.shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both);
      socket_.close();
      // on_disconnect_callback_();
    }
  }
}

void HTTPSession::doWrite() {
  auto &buffer = write_msgs_.front().first;

  asio::async_write(socket_, asio::buffer(buffer->data(), buffer->length()),
                    [this](const std::error_code &ec, std::size_t length) {
                      if (TRANSPORT_EXPECT_FALSE(!ec)) {
                        write_msgs_.front().second();
                        write_msgs_.pop_front();
                        if (!write_msgs_.empty()) {
                          doWrite();
                        }
                      }
                    });
}  // namespace transport

void HTTPSession::handleRead(const std::error_code &ec, std::size_t length) {
  if (TRANSPORT_EXPECT_TRUE(!ec)) {
    content_length_ -= length;
    const uint8_t *buffer =
        asio::buffer_cast<const uint8_t *>(input_buffer_.data());
    bool is_last = chunked_ ? (is_last_chunk_ ? !content_length_ : false)
                            : !content_length_;
    receive_callback_(buffer, input_buffer_.size(), is_last, false, nullptr);
    input_buffer_.consume(input_buffer_.size());

    if (!content_length_) {
      if (!chunked_ || is_last_chunk_) {
        doReadHeader();
      } else {
        doReadChunkedHeader();
      }
    } else {
      auto to_read =
          content_length_ >= buffer_size ? buffer_size : content_length_;
      asio::async_read(socket_, input_buffer_, asio::transfer_exactly(to_read),
                       std::bind(&HTTPSession::handleRead, this,
                                 std::placeholders::_1, std::placeholders::_2));
    }
  } else if (ec == asio::error::eof) {
    input_buffer_.consume(input_buffer_.size());
    tryReconnection();
  }
}

void HTTPSession::doReadBody(std::size_t body_size,
                             std::size_t additional_bytes) {
  auto bytes_to_read =
      body_size > additional_bytes ? (body_size - additional_bytes) : 0;

  auto to_read = bytes_to_read >= buffer_size
                     ? (buffer_size - input_buffer_.size())
                     : bytes_to_read;

  is_last_chunk_ = chunked_ && body_size == 5;

  if (to_read > 0) {
    content_length_ = bytes_to_read;
    asio::async_read(socket_, input_buffer_, asio::transfer_exactly(to_read),
                     std::bind(&HTTPSession::handleRead, this,
                               std::placeholders::_1, std::placeholders::_2));
  } else {
    if (body_size) {
      const uint8_t *buffer =
          asio::buffer_cast<const uint8_t *>(input_buffer_.data());
      receive_callback_(buffer, body_size, chunked_ ? is_last_chunk_ : !to_read,
                        false, nullptr);
      input_buffer_.consume(body_size);
    }

    if (!chunked_ || is_last_chunk_) {
      doReadHeader();
    } else {
      doReadChunkedHeader();
    }
  }
}

void HTTPSession::doReadChunkedHeader() {
  asio::async_read_until(
      socket_, input_buffer_, "\r\n",
      [this](const std::error_code &ec, std::size_t length) {
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          const uint8_t *buffer =
              asio::buffer_cast<const uint8_t *>(input_buffer_.data());
          std::size_t chunk_size =
              std::stoul(reinterpret_cast<const char *>(buffer), 0, 16) + 2 +
              length;
          auto additional_bytes = input_buffer_.size();
          doReadBody(chunk_size, additional_bytes);
        } else {
          input_buffer_.consume(input_buffer_.size());
          tryReconnection();
        }
      });
}

void HTTPSession::doReadHeader() {
  asio::async_read_until(
      socket_, input_buffer_, "\r\n\r\n",
      [this](const std::error_code &ec, std::size_t length) {
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          const uint8_t *buffer =
              asio::buffer_cast<const uint8_t *>(input_buffer_.data());
          HTTPMessageFastParser::getHeaders(buffer, length, reverse_,
                                            header_info_.get());

          auto &headers = header_info_->headers;

          // Try to get content length, if available
          auto it = headers.find(HTTPMessageFastParser::content_length);
          std::size_t size = 0;
          if (it != headers.end()) {
            size = std::stoull(it->second);
            chunked_ = false;
          } else {
            it = headers.find(HTTPMessageFastParser::transfer_encoding);
            if (it != headers.end() &&
                it->second.compare(HTTPMessageFastParser::chunked) == 0) {
              chunked_ = true;
            }
          }

          receive_callback_(buffer, length, !size && !chunked_, true,
                            header_info_.get());
          auto additional_bytes = input_buffer_.size() - length;
          input_buffer_.consume(length);

          if (!chunked_) {
            doReadBody(size, additional_bytes);
          } else {
            doReadChunkedHeader();
          }
        } else {
          input_buffer_.consume(input_buffer_.size());
          tryReconnection();
        }
      });
}

void HTTPSession::tryReconnection() {
  if (on_connection_closed_callback_(socket_)) {
    if (state_ == ConnectorState::CONNECTED) {
      TRANSPORT_LOG_ERROR << "Connection lost. Trying to reconnect...";
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
}

void HTTPSession::doConnect() {
  asio::async_connect(
      socket_, endpoint_iterator_,
      [this](const std::error_code &ec, tcp::resolver::iterator) {
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
            TRANSPORT_LOG_INFO << "Connection recovered!";
          }

        } else {
          TRANSPORT_LOG_ERROR << "Impossible to reconnect: " << ec.message();
          close();
        }
      });
}

bool HTTPSession::checkConnected() {
  return state_ == ConnectorState::CONNECTED;
}

void HTTPSession::startConnectionTimer() {
  timer_.expires_from_now(std::chrono::seconds(10));
  timer_.async_wait(
      std::bind(&HTTPSession::handleDeadline, this, std::placeholders::_1));
}

void HTTPSession::handleDeadline(const std::error_code &ec) {
  if (!ec) {
    io_service_.post([this]() {
      socket_.close();
      TRANSPORT_LOG_ERROR << "Error connecting. Is the server running?";
      io_service_.stop();
    });
  }
}

}  // namespace transport
