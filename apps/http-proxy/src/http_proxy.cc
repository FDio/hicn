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

#include <hicn/transport/core/interest.h>
#include <hicn/transport/utils/log.h>

#include "utils.h"

namespace transport {

using core::Interest;
using core::Name;
using interface::ConsumerCallbacksOptions;
using interface::ConsumerInterestCallback;
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
        session_(nullptr),
        current_size_(0) {
    consumer_.setSocketOption(ConsumerCallbacksOptions::READ_CALLBACK, this);
    consumer_.setSocketOption(
        ConsumerCallbacksOptions::INTEREST_OUTPUT,
        (ConsumerInterestCallback)std::bind(
            &HTTPClientConnectionCallback::processLeavingInterest, this,
            std::placeholders::_1, std::placeholders::_2));
    consumer_.connect();
  }

  void setHttpSession(asio::ip::tcp::socket&& socket) {
    session_ = std::make_unique<HTTPSession>(
        std::move(socket),
        std::bind(&HTTPClientConnectionCallback::readDataFromTcp, this,
                  std::placeholders::_1, std::placeholders::_2,
                  std::placeholders::_3, std::placeholders::_4),
        [this](asio::ip::tcp::socket& socket) -> bool {
          try {
            std::string remote_address =
                socket.remote_endpoint().address().to_string();
            std::uint16_t remote_port = socket.remote_endpoint().port();
            TRANSPORT_LOGD("Client %s:%d disconnected.", remote_address.c_str(),
                           remote_port);
          } catch (std::system_error& e) {
            // Do nothing
          }

          consumer_.stop();
          tcp_receiver_.onClientDisconnect(this);
          return false;
        });

    current_size_ = 0;
  }

 private:
  void consumeNextRequest() {
    if (request_buffer_queue_.size() == 0) {
      // No additiona requests to process.
      return;
    }

    auto& buffer = request_buffer_queue_.front();
    uint64_t request_hash =
        utils::hash::fnv64_buf(buffer->data(), buffer->length());

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

  // tcp callbacks

  void readDataFromTcp(const uint8_t* data, std::size_t size, bool is_last,
                       bool headers) {
    if (headers) {
      // Add the request to the request queue
      tmp_buffer_ = utils::MemBuf::copyBuffer(data, size);
    } else {
      // Append payload chunk to last request added. Here we are assuming
      // HTTP/1.1.
      tmp_buffer_->prependChain(utils::MemBuf::copyBuffer(data, size));
    }

    current_size_ += size;

    if (is_last) {
      TRANSPORT_LOGD(
          "Request received: %s",
          std::string((const char*)tmp_buffer_->data(), tmp_buffer_->length())
              .c_str());
      if (current_size_ < 1400) {
        request_buffer_queue_.emplace_back(std::move(tmp_buffer_));
      } else {
        TRANSPORT_LOGE("Ignoring client request due to size (%zu) > 1400.",
                       current_size_);
        session_->close();
        current_size_ = 0;
        return;
      }

      if (!consumer_.isRunning()) {
        TRANSPORT_LOGD(
            "Consumer stopped, triggering consume from TCP session handler..");
        consumeNextRequest();
      }

      current_size_ = 0;
    }
  }

  // hicn callbacks

  void processLeavingInterest(interface::ConsumerSocket& c,
                              const core::Interest& interest) {
    if (interest.payloadSize() == 0) {
      Interest& int2 = const_cast<Interest&>(interest);
      int2.appendPayload(request_buffer_queue_.front()->clone());
    }
  }

  bool isBufferMovable() noexcept { return true; }
  void getReadBuffer(uint8_t** application_buffer, size_t* max_length) {}
  void readDataAvailable(size_t length) noexcept {}
  size_t maxBufferSize() const { return 64 * 1024; }

  void readBufferAvailable(std::unique_ptr<utils::MemBuf>&& buffer) noexcept {
    // Response received. Send it back to client
    auto _buffer = buffer.release();
    TRANSPORT_LOGD("From hicn: %zu bytes.", _buffer->length());
    session_->send(_buffer, []() {});
  }

  void readError(const std::error_code ec) noexcept {
    TRANSPORT_LOGE("Error reading from hicn consumer socket. Closing session.");
    session_->close();
  }

  void readSuccess(std::size_t total_size) noexcept {
    request_buffer_queue_.pop_front();
    consumeNextRequest();
  }

 private:
  TcpReceiver& tcp_receiver_;
  utils::EventThread& thread_;
  std::string prefix_hash_;
  ConsumerSocket consumer_;
  std::unique_ptr<HTTPSession> session_;
  std::deque<std::unique_ptr<utils::MemBuf>> request_buffer_queue_;
  std::unique_ptr<utils::MemBuf> tmp_buffer_;
  std::size_t current_size_;
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
  http_clients_.emplace_front(client);
  used_http_clients_.erase(client);
}

void TcpReceiver::onNewConnection(asio::ip::tcp::socket&& socket) {
  if (http_clients_.size() == 0) {
    // Create new HTTPClientConnectionCallback
    TRANSPORT_LOGD("Creating new HTTPClientConnectionCallback.");
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

HTTPProxy::HTTPProxy(ClientParams& params, std::size_t n_thread) {
  for (uint16_t i = 0; i < n_thread; i++) {
    // icn_receivers_.emplace_back(std::make_unique<IcnReceiver>(icn_params));
    receivers_.emplace_back(std::make_unique<TcpReceiver>(
        params.tcp_listen_port, params.prefix, params.first_ipv6_word));
  }
}

HTTPProxy::HTTPProxy(ServerParams& params, std::size_t n_thread) {
  for (uint16_t i = 0; i < n_thread; i++) {
    receivers_.emplace_back(std::make_unique<IcnReceiver>(
        params.prefix, params.first_ipv6_word, params.origin_address,
        params.origin_port, params.cache_size, params.mtu,
        params.content_lifetime, params.manifest));
  }
}

}  // namespace transport
