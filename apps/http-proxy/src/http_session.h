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

#pragma once

#include <hicn/transport/core/packet.h>

#define ASIO_STANDALONE
#include <asio.hpp>
#include <deque>
#include <functional>

namespace transport {

using asio::ip::tcp;

typedef std::function<void(const uint8_t *data, std::size_t size, bool is_last,
                           bool headers)>
    ContentReceivedCallback;
typedef std::function<bool(asio::ip::tcp::socket &socket)> OnConnectionClosed;
typedef std::function<void()> ContentSentCallback;
typedef std::deque<
    std::pair<std::unique_ptr<utils::MemBuf>, ContentSentCallback>>
    BufferQueue;

class HTTPSession {
  static constexpr uint32_t buffer_size = 1024 * 512;

  enum class ConnectorState {
    CLOSED,
    CONNECTING,
    CONNECTED,
  };

 public:
  HTTPSession(asio::io_service &io_service, std::string &ip_address,
              std::string &port, ContentReceivedCallback receive_callback,
              OnConnectionClosed on_reconnect_callback, bool reverse = false);

  HTTPSession(asio::ip::tcp::socket socket,
              ContentReceivedCallback receive_callback,
              OnConnectionClosed on_reconnect_callback, bool reverse = true);

  ~HTTPSession();

  void send(const uint8_t *buffer, std::size_t len,
            ContentSentCallback &&content_sent = 0);

  void send(utils::MemBuf *buffer, ContentSentCallback &&content_sent);

  void close();

 private:
  void doConnect();

  void doReadHeader();

  void doReadBody(std::size_t body_size, std::size_t additional_bytes);

  void doReadChunkedHeader();

  void doWrite();

  bool checkConnected();

 private:
  void handleRead(std::error_code ec, std::size_t length);
  void tryReconnection();
  void startConnectionTimer();
  void handleDeadline(const std::error_code &ec);

  asio::io_service &io_service_;
  asio::ip::tcp::socket socket_;
  asio::ip::tcp::resolver resolver_;
  asio::ip::tcp::resolver::iterator endpoint_iterator_;
  asio::steady_timer timer_;

  BufferQueue write_msgs_;

  asio::streambuf input_buffer_;

  bool reverse_;
  bool is_reconnection_;
  bool data_available_;

  std::size_t content_length_;

  // Chunked encoding
  bool is_last_chunk_;
  bool chunked_;

  ContentReceivedCallback receive_callback_;
  OnConnectionClosed on_connection_closed_callback_;

  // Connector state
  ConnectorState state_;
};

}  // namespace transport
