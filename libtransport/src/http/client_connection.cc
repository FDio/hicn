/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/http/client_connection.h>
#include <hicn/transport/utils/hash.h>
#include <hicn/transport/utils/log.h>

#include <asio.hpp>
#include <asio/steady_timer.hpp>

#define DEFAULT_BETA 0.99
#define DEFAULT_GAMMA 0.07

namespace transport {

namespace http {

using namespace transport;

class HTTPClientConnection::Implementation
    : public ConsumerSocket::ReadCallback {
  static constexpr uint32_t max_buffer_capacity = 64 * 1024;

 public:
  Implementation(HTTPClientConnection *http_client)
      : http_client_(http_client),
        consumer_(TransportProtocolAlgorithms::RAAQM),
        read_bytes_callback_(nullptr),
        read_buffer_(nullptr),
        response_(std::make_shared<HTTPResponse>()),
        timer_(nullptr) {
    consumer_.setSocketOption(
        ConsumerCallbacksOptions::CONTENT_OBJECT_TO_VERIFY,
        (ConsumerContentObjectVerificationCallback)std::bind(
            &Implementation::verifyData, this, std::placeholders::_1,
            std::placeholders::_2));

    consumer_.setSocketOption(ConsumerCallbacksOptions::READ_CALLBACK, this);

    consumer_.connect();
    timer_ = std::make_unique<asio::steady_timer>(consumer_.getIoService());
  }

  RC get(const std::string &url, HTTPHeaders headers = {},
         HTTPPayload &&payload = nullptr,
         std::shared_ptr<HTTPResponse> response = nullptr,
         ReadBytesCallback *callback = nullptr,
         std::string ipv6_first_word = "b001") {
    return sendRequest(url, HTTPMethod::GET, headers, std::move(payload),
                       response, callback, ipv6_first_word);
  }

  RC sendRequest(const std::string &url, HTTPMethod method,
                 HTTPHeaders headers = {}, HTTPPayload &&payload = nullptr,
                 std::shared_ptr<HTTPResponse> response = nullptr,
                 ReadBytesCallback *callback = nullptr,
                 std::string ipv6_first_word = "b001") {
    current_url_ = url;
    read_bytes_callback_ = callback;
    if (!response) {
      response_ = std::make_shared<HTTPResponse>();
    } else {
      response_ = response;
    }

    auto start = std::chrono::steady_clock::now();
    request_.init(method, url, headers, std::move(payload));

    success_callback_ = [this, method = std::move(method), url = std::move(url),
                         start = std::move(start)](std::size_t size) -> void {
      auto end = std::chrono::steady_clock::now();
      TRANSPORT_LOGI(
          "%s %s [%s] duration: %llu [usec] %zu [bytes]\n",
          method_map[method].c_str(), url.c_str(), name_.str().c_str(),
          (unsigned long long)
              std::chrono::duration_cast<std::chrono::microseconds>(end - start)
                  .count(),
          size);
    };

    sendRequestGetReply(ipv6_first_word);
    return return_code_;
  }

  std::shared_ptr<HTTPResponse> response() {
    response_->coalescePayloadBuffer();
    return response_;
  }

  HTTPClientConnection &stop() {
    // This is thread safe and can be called from another thread
    consumer_.stop();

    return *http_client_;
  }

  interface::ConsumerSocket &getConsumer() {
    return consumer_;
  }

  HTTPClientConnection &setTimeout(const std::chrono::seconds &timeout) {
    timer_->cancel();
    timer_->expires_from_now(timeout);
    timer_->async_wait([this](std::error_code ec) {
      if (!ec) {
        consumer_.stop();
      }
    });

    return *http_client_;
  }

  HTTPClientConnection &setCertificate(const std::string &cert_path) {
    if (consumer_.setSocketOption(GeneralTransportOptions::CERTIFICATE,
                                  cert_path) == SOCKET_OPTION_NOT_SET) {
      throw errors::RuntimeException("Error setting the certificate.");
    }

    return *http_client_;
  }

 private:
  void sendRequestGetReply(std::string &ipv6_first_word) {
    const std::string &request_string = request_.getRequestString();
    const std::string &locator = request_.getLocator();

    // Hash it

    uint32_t locator_hash =
        utils::hash::fnv32_buf(locator.c_str(), locator.size());
    uint64_t request_hash =
        utils::hash::fnv64_buf(request_string.c_str(), request_string.size());

    consumer_.setSocketOption(
        ConsumerCallbacksOptions::INTEREST_OUTPUT,
        (ConsumerInterestCallback)std::bind(
            &Implementation::processLeavingInterest, this,
            std::placeholders::_1, std::placeholders::_2));

    // Factor hicn name using hash
    name_.str("");

    name_ << ipv6_first_word << ":";

    for (uint16_t *word = (uint16_t *)&locator_hash;
         std::size_t(word) <
         (std::size_t(&locator_hash) + sizeof(locator_hash));
         word++) {
      name_ << ":" << std::hex << *word;
    }

    for (uint16_t *word = (uint16_t *)&request_hash;
         std::size_t(word) <
         (std::size_t(&request_hash) + sizeof(request_hash));
         word++) {
      name_ << ":" << std::hex << *word;
    }

    name_ << "|0";

    consumer_.consume(Name(name_.str()));

    consumer_.stop();
  }

  bool verifyData(interface::ConsumerSocket &c,
                  const core::ContentObject &contentObject) {
    if (contentObject.getPayloadType() == PayloadType::CONTENT_OBJECT) {
      TRANSPORT_LOGI("VERIFY CONTENT\n");
    } else if (contentObject.getPayloadType() == PayloadType::MANIFEST) {
      TRANSPORT_LOGI("VERIFY MANIFEST\n");
    }

    return true;
  }

  void processLeavingInterest(interface::ConsumerSocket &c,
                              const core::Interest &interest) {
    if (interest.payloadSize() == 0) {
      Interest &int2 = const_cast<Interest &>(interest);
      auto payload = request_.getRequestString();
      auto payload2 = request_.getPayload();
      int2.appendPayload((uint8_t *)payload.data(), payload.size());
      if (payload2)
        int2.appendPayload((uint8_t *)payload2->data(), payload2->length());
    }
  }

  // Read callback
  bool isBufferMovable() noexcept override { return true; }

  void getReadBuffer(uint8_t **application_buffer,
                     size_t *max_length) override {}

  void readDataAvailable(size_t length) noexcept override {}

  size_t maxBufferSize() const override { return max_buffer_capacity; }

  void readBufferAvailable(
      std::unique_ptr<utils::MemBuf> &&buffer) noexcept override {
    if (!read_bytes_callback_) {
      response_->appendResponseChunk(std::move(buffer));
    } else {
      read_bytes_callback_->onBytesReceived(std::move(buffer));
    }
  }

  void readError(const std::error_code ec) noexcept override {
    TRANSPORT_LOGE("Error %s during download of %s", ec.message().c_str(),
                   current_url_.c_str());
    if (read_bytes_callback_) {
      read_bytes_callback_->onError(ec);
    }

    return_code_ = HTTPClientConnection::RC::DOWNLOAD_FAILED;
  }

  void readSuccess(std::size_t total_size) noexcept override {
    success_callback_(total_size);
    if (read_bytes_callback_) {
      read_bytes_callback_->onSuccess(total_size);
    }

    return_code_ = HTTPClientConnection::RC::DOWNLOAD_SUCCESS;
  }

  HTTPClientConnection *http_client_;

  // The consumer socket
  ConsumerSocket consumer_;

  // The current url provided by the application
  std::string current_url_;
  // The current hICN name used for downloading
  std::stringstream name_;
  // Function to be called when the read is successful
  std::function<void(std::size_t)> success_callback_;
  // Return code for current download
  RC return_code_;

  // Application provided callback for saving the received content during
  // the download. If this callback is used, the HTTPClient will NOT save
  // any byte internally.
  ReadBytesCallback *read_bytes_callback_;

  HTTPRequest request_;

  // Internal read buffer and HTTP response, to be used if the application does
  // not provide any read_bytes_callback
  std::unique_ptr<utils::MemBuf> read_buffer_;
  std::shared_ptr<HTTPResponse> response_;

  // Timer
  std::unique_ptr<asio::steady_timer> timer_;
};

HTTPClientConnection::HTTPClientConnection() {
  implementation_ = new Implementation(this);
}

HTTPClientConnection::~HTTPClientConnection() { delete implementation_; }

HTTPClientConnection::RC HTTPClientConnection::get(
    const std::string &url, HTTPHeaders headers, HTTPPayload &&payload,
    std::shared_ptr<HTTPResponse> response, ReadBytesCallback *callback,
    std::string ipv6_first_word) {
  return implementation_->get(url, headers, std::move(payload), response,
                              callback, ipv6_first_word);
}

HTTPClientConnection::RC HTTPClientConnection::sendRequest(
    const std::string &url, HTTPMethod method, HTTPHeaders headers,
    HTTPPayload &&payload, std::shared_ptr<HTTPResponse> response,
    ReadBytesCallback *callback, std::string ipv6_first_word) {
  return implementation_->sendRequest(url, method, headers, std::move(payload),
                                      response, callback, ipv6_first_word);
}

std::shared_ptr<HTTPResponse> HTTPClientConnection::response() {
  return implementation_->response();
}

ConsumerSocket &HTTPClientConnection::getConsumer() {
  return implementation_->getConsumer();
}

HTTPClientConnection &HTTPClientConnection::stop() {
  return implementation_->stop();
}

HTTPClientConnection &HTTPClientConnection::setTimeout(
    const std::chrono::seconds &timeout) {
  return implementation_->setTimeout(timeout);
}

HTTPClientConnection &HTTPClientConnection::setCertificate(
    const std::string &cert_path) {
  return implementation_->setCertificate(cert_path);
}

}  // namespace http

}  // namespace transport
