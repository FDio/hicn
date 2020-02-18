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

#include <hicn/transport/http/client_connection.h>
#include <hicn/transport/utils/hash.h>

#define DEFAULT_BETA 0.99
#define DEFAULT_GAMMA 0.07

namespace transport {

namespace http {

using namespace transport;

HTTPClientConnection::HTTPClientConnection()
    : consumer_(TransportProtocolAlgorithms::RAAQM),
      read_bytes_callback_(nullptr),
      read_buffer_(nullptr),
      response_(std::make_shared<HTTPResponse>()),
      timer_(nullptr) {
  consumer_.setSocketOption(
      ConsumerCallbacksOptions::CONTENT_OBJECT_TO_VERIFY,
      (ConsumerContentObjectVerificationCallback)std::bind(
          &HTTPClientConnection::verifyData, this, std::placeholders::_1,
          std::placeholders::_2));

  consumer_.setSocketOption(ConsumerCallbacksOptions::READ_CALLBACK, this);

  consumer_.connect();
  std::shared_ptr<typename ConsumerSocket::Portal> portal;
  consumer_.getSocketOption(GeneralTransportOptions::PORTAL, portal);
  timer_ = std::make_unique<asio::steady_timer>(portal->getIoService());
}

HTTPClientConnection::RC HTTPClientConnection::get(
    const std::string &url, HTTPHeaders headers, HTTPPayload &&payload,
    std::shared_ptr<HTTPResponse> response, ReadBytesCallback *callback,
    std::string ipv6_first_word) {
  return sendRequest(url, HTTPMethod::GET, headers, std::move(payload),
                     response, callback, ipv6_first_word);
}

HTTPClientConnection::RC HTTPClientConnection::sendRequest(
    const std::string &url, HTTPMethod method, HTTPHeaders headers,
    HTTPPayload &&payload, std::shared_ptr<HTTPResponse> response,
    ReadBytesCallback *callback, std::string ipv6_first_word) {
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

void HTTPClientConnection::sendRequestGetReply(std::string &ipv6_first_word) {
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
          &HTTPClientConnection::processLeavingInterest, this,
          std::placeholders::_1, std::placeholders::_2));

  // Factor hicn name using hash
  name_.str("");

  name_ << ipv6_first_word << ":";

  for (uint16_t *word = (uint16_t *)&locator_hash;
       std::size_t(word) < (std::size_t(&locator_hash) + sizeof(locator_hash));
       word++) {
    name_ << ":" << std::hex << *word;
  }

  for (uint16_t *word = (uint16_t *)&request_hash;
       std::size_t(word) < (std::size_t(&request_hash) + sizeof(request_hash));
       word++) {
    name_ << ":" << std::hex << *word;
  }

  name_ << "|0";

  consumer_.consume(Name(name_.str()));

  consumer_.stop();
}

std::shared_ptr<HTTPResponse> HTTPClientConnection::response() {
  response_->coalescePayloadBuffer();
  return response_;
}

bool HTTPClientConnection::verifyData(
    ConsumerSocket &c, const core::ContentObject &contentObject) {
  if (contentObject.getPayloadType() == PayloadType::CONTENT_OBJECT) {
    TRANSPORT_LOGI("VERIFY CONTENT\n");
  } else if (contentObject.getPayloadType() == PayloadType::MANIFEST) {
    TRANSPORT_LOGI("VERIFY MANIFEST\n");
  }

  return true;
}

void HTTPClientConnection::processLeavingInterest(
    ConsumerSocket &c, const core::Interest &interest) {
  if (interest.payloadSize() == 0) {
    Interest &int2 = const_cast<Interest &>(interest);
    auto payload = request_.getRequestString();
    auto payload2 = request_.getPayload();
    int2.appendPayload((uint8_t *)payload.data(), payload.size());
    if (payload2)
      int2.appendPayload((uint8_t *)payload2->data(), payload2->length());
  }
}

ConsumerSocket &HTTPClientConnection::getConsumer() { return consumer_; }

HTTPClientConnection &HTTPClientConnection::stop() {
  // This is thread safe and can be called from another thread
  consumer_.stop();

  return *this;
}

HTTPClientConnection &HTTPClientConnection::setTimeout(
    const std::chrono::seconds &timeout) {
  timer_->cancel();
  timer_->expires_from_now(timeout);
  timer_->async_wait([this](std::error_code ec) {
    if (!ec) {
      consumer_.stop();
    }
  });

  return *this;
}

HTTPClientConnection &HTTPClientConnection::setCertificate(
    const std::string &cert_path) {
  if (consumer_.setSocketOption(GeneralTransportOptions::CERTIFICATE,
                                cert_path) == SOCKET_OPTION_NOT_SET) {
    throw errors::RuntimeException("Error setting the certificate.");
  }

  return *this;
}

// Read buffer management
void HTTPClientConnection::readBufferAvailable(
    std::unique_ptr<utils::MemBuf> &&buffer) noexcept {
  if (!read_bytes_callback_) {
    response_->appendResponseChunk(std::move(buffer));
  } else {
    read_bytes_callback_->onBytesReceived(std::move(buffer));
  }
}

// Read buffer management
void HTTPClientConnection::readError(const std::error_code ec) noexcept {
  TRANSPORT_LOGE("Error %s during download of %s", ec.message().c_str(),
                 current_url_.c_str());
  if (read_bytes_callback_) {
    read_bytes_callback_->onError(ec);
  }

  return_code_ = HTTPClientConnection::RC::DOWNLOAD_FAILED;
}

void HTTPClientConnection::readSuccess(std::size_t total_size) noexcept {
  success_callback_(total_size);
  if (read_bytes_callback_) {
    read_bytes_callback_->onSuccess(total_size);
  }

  return_code_ = HTTPClientConnection::RC::DOWNLOAD_SUCCESS;
}

}  // namespace http

}  // namespace transport
