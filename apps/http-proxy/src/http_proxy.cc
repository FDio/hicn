/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include "http_proxy.h"

#include "utils.h"

namespace transport {

using core::Name;
using interface::ConsumerSocket;
using interface::TransportProtocolAlgorithms;

class HTTPClientConnectionCallback : interface::ConsumerSocket::ReadCallback {
 public:
  HTTPClientConnectionCallback(TcpReceiver& tcp_receiver,
                               utils::EventThread& thread,
                               const std::string& prefix,
                               const std::string& ipv6_first_word)
      : tcp_receiver_(tcp_receiver),
        thread_(thread),
        prefix_hash_(generatePrefix(prefix, ipv6_first_word)),
        consumer_(TransportProtocolAlgorithms::RAAQM, thread_.getIoService()),
        session_(nullptr) {}

  void setHttpSession(asio::ip::tcp::socket&& socket) {
    session_ = std::make_unique<HTTPSession>(
        std::move(socket),
        std::bind(&HTTPClientConnectionCallback::readDataFromTcp, this,
                  std::placeholders::_1, std::placeholders::_2,
                  std::placeholders::_3, std::placeholders::_4),
        [this]() -> bool {
          tcp_receiver_.onClientDisconnect(this);
          return false;
        });
  }

 private:
  // tcp callbacks

  void readDataFromTcp(const uint8_t* data, std::size_t size, bool is_last,
                       bool headers) {
    if (!is_last || size > 1400) {
      throw std::runtime_error("Request not yet supported.");
    }

    std::memcpy(request_buffer_.data(), data, size);
    request_buffer_size_ = size;

    uint64_t request_hash = utils::hash::fnv64_buf(data, size);

    std::stringstream name;
    name << prefix_hash_.substr(0, prefix_hash_.length() - 2);

    for (uint16_t* word = (uint16_t*)&request_hash;
         std::size_t(word) <
         (std::size_t(&request_hash) + sizeof(request_hash));
         word++) {
      name << ":" << std::hex << *word;
    }

    name << "|0";

    // Non blocking consume :)
    consumer_.consume(Name(name.str()));
  }

  // hicn callbacks
  bool isBufferMovable() noexcept { return true; }
  void getReadBuffer(uint8_t** application_buffer, size_t* max_length) {}
  void readDataAvailable(size_t length) noexcept {}
  size_t maxBufferSize() const { return 64 * 1024; }

  void readBufferAvailable(std::unique_ptr<utils::MemBuf>&& buffer) noexcept {
    // Response received. Send it back to client
    session_->send(buffer.release(), []() {});
  }

  void readError(const std::error_code ec) noexcept {}
  void readSuccess(std::size_t total_size) noexcept {}

 private:
  TcpReceiver& tcp_receiver_;
  utils::EventThread& thread_;
  std::string prefix_hash_;
  ConsumerSocket consumer_;
  std::unique_ptr<HTTPSession> session_;
  std::array<uint8_t, 1400> request_buffer_;
  std::size_t request_buffer_size_;
};

TcpReceiver::TcpReceiver(std::uint16_t port, const std::string& prefix,
                         const std::string& ipv6_first_word)
    : Receiver(),
      listener_(thread_.getIoService(), port,
                std::bind(&TcpReceiver::onNewConnection, this,
                          std::placeholders::_1)),
      prefix_(prefix),
      ipv6_first_word_(ipv6_first_word) {
  for (int i = 0; i < 10; i++) {
    http_clients_.emplace_back(new HTTPClientConnectionCallback(
        *this, thread_, prefix, ipv6_first_word));
  }
}

void TcpReceiver::onClientDisconnect(HTTPClientConnectionCallback* client) {
  http_clients_.emplace_back(client);
  used_http_clients_.erase(client);
}

void TcpReceiver::onNewConnection(asio::ip::tcp::socket&& socket) {
  if (http_clients_.size() == 0) {
    // Create new HTTPClientConnectionCallback
    http_clients_.emplace_back(new HTTPClientConnectionCallback(
        *this, thread_, prefix_, ipv6_first_word_));
  }

  // Get new HTTPClientConnectionCallback
  HTTPClientConnectionCallback* c = http_clients_.front();
  http_clients_.pop_front();

  // Set http session
  c->setHttpSession(std::move(socket));

  // Move it to used clients
  used_http_clients_.insert(c);
}

HTTPProxy::HTTPProxy(AsyncConsumerProducer::Params& icn_params, short tcp_port,
                     std::size_t n_thread) {
  for (int i = 0; i < n_thread; i++) {
    icn_receivers_.emplace_back(std::make_unique<IcnReceiver>(icn_params));
    tcp_receivers_.emplace_back(std::make_unique<TcpReceiver>(
        tcp_port, icn_params.prefix, icn_params.first_ipv6_word));
  }
}

}  // namespace transport
