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

#include "socket_response.h"

namespace icn_httpserver {

SocketResponse::SocketResponse(std::shared_ptr<asio::ip::tcp::socket> socket)
    : socket_(socket) {}

SocketResponse::~SocketResponse(){};

void SocketResponse::send(const SendCallback &callback) {
  asio::async_write(
      *this->socket_, this->streambuf_,
      [callback](const std::error_code &ec, size_t /*bytes_transferred*/) {
        if (callback) {
          callback(ec);
        }
      });
}

const std::shared_ptr<socket_type> &SocketResponse::getSocket() const {
  return socket_;
}

void SocketResponse::setSocket(const std::shared_ptr<socket_type> &socket) {
  SocketResponse::socket_ = socket;
}

}  // end namespace icn_httpserver
