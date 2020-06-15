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

#include <hicn/http-proxy/http_proxy.h>
#include <hicn/http-proxy/http_session.h>
#include <hicn/http-proxy/utils.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/utils/log.h>
#include <hicn/transport/utils/string_utils.h>

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
                               utils::EventThread& thread)
      : tcp_receiver_(tcp_receiver),
        thread_(thread),
        prefix_hash_(tcp_receiver_.prefix_hash_),
        consumer_(TransportProtocolAlgorithms::RAAQM, thread_.getIoService()),
        session_(nullptr),
        current_size_(0) {
    consumer_.setSocketOption(ConsumerCallbacksOptions::READ_CALLBACK, this);
    consumer_.setSocketOption(
        ConsumerCallbacksOptions::INTEREST_OUTPUT,
        (ConsumerInterestCallback)std::bind(
            &HTTPClientConnectionCallback::processLeavingInterest, this,
            std::placeholders::_1, std::placeholders::_2));
    consumer_.setSocketOption(
        ConsumerCallbacksOptions::INTEREST_RETRANSMISSION,
        (ConsumerInterestCallback)std::bind(
            &HTTPClientConnectionCallback::processInterestRetx, this,
            std::placeholders::_1, std::placeholders::_2));
    consumer_.connect();
  }

  void stop() { session_->close(); }

  void setHttpSession(asio::ip::tcp::socket&& socket) {
    session_ = std::make_unique<HTTPSession>(
        std::move(socket),
        std::bind(&HTTPClientConnectionCallback::readDataFromTcp, this,
                  std::placeholders::_1, std::placeholders::_2,
                  std::placeholders::_3, std::placeholders::_4,
                  std::placeholders::_5),
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
          request_buffer_queue_.clear();
          tcp_receiver_.onClientDisconnect(this);
          return false;
        });

    current_size_ = 0;
  }

 private:
  void consumeNextRequest() {
    if (request_buffer_queue_.size() == 0) {
      TRANSPORT_LOGD("No additional requests to process.");
      return;
    }

    auto& buffer = request_buffer_queue_.front().second;
    uint64_t request_hash =
        utils::hash::fnv64_buf(buffer.data(), buffer.size());

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
                       bool headers, Metadata* metadata) {
    if (headers) {
      // Add the request to the request queue
      RequestMetadata* _metadata = reinterpret_cast<RequestMetadata*>(metadata);
      tmp_buffer_ = std::make_pair(utils::MemBuf::copyBuffer(data, size),
                                   _metadata->path);
      if (TRANSPORT_EXPECT_FALSE(
              _metadata->path.compare("/isHicnProxyOn") == 0 && is_last)) {
        /**
         * It seems this request is for us.
         * Get hicn parameters.
         */
        processClientRequest(_metadata);
        return;
      }
    } else {
      // Append payload chunk to last request added. Here we are assuming
      // HTTP/1.1.
      tmp_buffer_.first->prependChain(utils::MemBuf::copyBuffer(data, size));
    }

    current_size_ += size;

    if (is_last) {
      TRANSPORT_LOGD("Request received: %s",
                     std::string((const char*)tmp_buffer_.first->data(),
                                 tmp_buffer_.first->length())
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
            "Consumer stopped, triggering consume from TCP session "
            "handler..");
        consumeNextRequest();
      }

      current_size_ = 0;
    }
  }

  // hicn callbacks

  void processLeavingInterest(interface::ConsumerSocket& c,
                              const core::Interest& interest) {
    if (interest.getName().getSuffix() == 0 && interest.payloadSize() == 0) {
      Interest& int2 = const_cast<Interest&>(interest);
      int2.appendPayload(request_buffer_queue_.front().first->clone());
    }
  }

  void processInterestRetx(interface::ConsumerSocket& c,
                           const core::Interest& interest) {
    if (interest.payloadSize() == 0) {
      Interest& int2 = const_cast<Interest&>(interest);
      int2.appendPayload(request_buffer_queue_.front().first->clone());
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

  void processClientRequest(RequestMetadata* metadata) {
    auto it = metadata->headers.find("hicn");
    if (it == metadata->headers.end()) {
      /*
       * Probably it is an OPTION message for access control.
       * Let's grant it!
       */
      if (metadata->method == "OPTIONS") {
        session_->send(
            (const uint8_t*)HTTPMessageFastParser::http_cors,
            std::strlen(HTTPMessageFastParser::http_cors), [this]() {
              auto& socket = session_->socket_;
              TRANSPORT_LOGI(
                  "Sent OPTIONS to client %s:%d",
                  socket.remote_endpoint().address().to_string().c_str(),
                  socket.remote_endpoint().port());
            });
      }
    } else {
      tcp_receiver_.parseHicnHeader(
          it->second, [this](bool result, std::string configured_prefix) {
            const char* reply = nullptr;
            if (result) {
              reply = HTTPMessageFastParser::http_ok;
              prefix_hash_ = configured_prefix;
            } else {
              reply = HTTPMessageFastParser::http_failed;
            }

            /* Route created. Send back a 200 OK to client */
            session_->send(
                (const uint8_t*)reply, std::strlen(reply), [this, result]() {
                  auto& socket = session_->socket_;
                  TRANSPORT_LOGI(
                      "Sent %d response to client %s:%d", result,
                      socket.remote_endpoint().address().to_string().c_str(),
                      socket.remote_endpoint().port());
                });
          });
    }
  }

 private:
  TcpReceiver& tcp_receiver_;
  utils::EventThread& thread_;
  std::string& prefix_hash_;
  ConsumerSocket consumer_;
  std::unique_ptr<HTTPSession> session_;
  std::deque<std::pair<std::unique_ptr<utils::MemBuf>, std::string>>
      request_buffer_queue_;
  std::pair<std::unique_ptr<utils::MemBuf>, std::string> tmp_buffer_;
  std::size_t current_size_;
};

TcpReceiver::TcpReceiver(std::uint16_t port, const std::string& prefix,
                         const std::string& ipv6_first_word)
    : Receiver(),
      listener_(thread_.getIoService(), port,
                std::bind(&TcpReceiver::onNewConnection, this,
                          std::placeholders::_1)),
      prefix_(prefix),
      ipv6_first_word_(ipv6_first_word),
      prefix_hash_(generatePrefix(prefix_, ipv6_first_word_)),
      forwarder_config_(
          thread_.getIoService(),
          [this](std::error_code ec) {
            if (!ec) {
              listener_.doAccept();
              for (int i = 0; i < 10; i++) {
                http_clients_.emplace_back(
                    new HTTPClientConnectionCallback(*this, thread_));
              }
            }
          }),
      stopped_(false) {
  forwarder_config_.tryToConnectToForwarder();
}

void TcpReceiver::stop() {
  thread_.add([this]() {
    stopped_ = true;

    /* Stop the listener */
    listener_.stop();

    /* Close connection with forwarder */
    forwarder_config_.close();

    /* Stop the used http clients */
    for (auto& client : used_http_clients_) {
      client->stop();
    }

    /* Delete unused clients */
    for (auto& client : http_clients_) {
      delete client;
    }
  });
}

void TcpReceiver::onClientDisconnect(HTTPClientConnectionCallback* client) {
  if (stopped_) {
    delete client;
    return;
  }

  http_clients_.emplace_front(client);
  used_http_clients_.erase(client);
}

void TcpReceiver::onNewConnection(asio::ip::tcp::socket&& socket) {
  if (http_clients_.size() == 0) {
    // Create new HTTPClientConnectionCallback
    TRANSPORT_LOGD("Creating new HTTPClientConnectionCallback.");
    http_clients_.emplace_back(
        new HTTPClientConnectionCallback(*this, thread_));
  }

  // Get new HTTPClientConnectionCallback
  HTTPClientConnectionCallback* c = http_clients_.front();
  http_clients_.pop_front();

  // Set http session
  c->setHttpSession(std::move(socket));

  // Move it to used clients
  used_http_clients_.insert(c);
}

void HTTPProxy::setupSignalHandler() {
  signals_.async_wait([this](const std::error_code& ec, int signal_number) {
    if (!ec) {
      TRANSPORT_LOGI("Received signal %d. Stopping gracefully.", signal_number);
      stop();
    }
  });
}

void HTTPProxy::stop() {
  for (auto& receiver : receivers_) {
    receiver->stop();
  }

  for (auto& receiver : receivers_) {
    receiver->stopAndJoinThread();
  }

  signals_.cancel();
}

HTTPProxy::HTTPProxy(ClientParams& params, std::size_t n_thread)
    : signals_(main_io_context_, SIGINT, SIGQUIT) {
  for (uint16_t i = 0; i < n_thread; i++) {
    // icn_receivers_.emplace_back(std::make_unique<IcnReceiver>(icn_params));
    receivers_.emplace_back(std::make_unique<TcpReceiver>(
        params.tcp_listen_port, params.prefix, params.first_ipv6_word));
  }

  setupSignalHandler();
}

HTTPProxy::HTTPProxy(ServerParams& params, std::size_t n_thread)
    : signals_(main_io_context_, SIGINT, SIGQUIT) {
  for (uint16_t i = 0; i < n_thread; i++) {
    receivers_.emplace_back(std::make_unique<IcnReceiver>(
        params.prefix, params.first_ipv6_word, params.origin_address,
        params.origin_port, params.cache_size, params.mtu,
        params.content_lifetime, params.manifest));
  }

  setupSignalHandler();
}

}  // namespace transport
