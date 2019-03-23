/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Ole Christian Eidheim
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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

} // end namespace icn_httpserver
