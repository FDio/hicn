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
    : consumer_(TransportProtocolAlgorithms::RAAQM, io_service_),
      response_(std::make_shared<HTTPResponse>()),
      timer_(nullptr) {
  consumer_.setSocketOption(
      ConsumerCallbacksOptions::CONTENT_OBJECT_TO_VERIFY,
      (ConsumerContentObjectVerificationCallback)std::bind(
          &HTTPClientConnection::verifyData, this, std::placeholders::_1,
          std::placeholders::_2));

  consumer_.setSocketOption(
      ConsumerCallbacksOptions::CONTENT_RETRIEVED,
      (ConsumerContentCallback)std::bind(
          &HTTPClientConnection::processPayload, this, std::placeholders::_1,
          std::placeholders::_2, std::placeholders::_3));

  consumer_.connect();
  std::shared_ptr<typename ConsumerSocket::Portal> portal;
  consumer_.getSocketOption(GeneralTransportOptions::PORTAL, portal);
  timer_ = std::make_unique<asio::steady_timer>(portal->getIoService());
}

HTTPClientConnection &HTTPClientConnection::get(
    const std::string &url, HTTPHeaders headers, HTTPPayload payload,
    std::shared_ptr<HTTPResponse> response) {
  return sendRequest(url, HTTPMethod::GET, headers, payload, response);
}

HTTPClientConnection &HTTPClientConnection::sendRequest(
    const std::string &url, HTTPMethod method, HTTPHeaders headers,
    HTTPPayload payload, std::shared_ptr<HTTPResponse> response) {
  if (!response) {
    response = response_;
  }

  auto start = std::chrono::steady_clock::now();
  HTTPRequest request(method, url, headers, payload);
  std::string name = sendRequestGetReply(request, response);
  auto end = std::chrono::steady_clock::now();

  TRANSPORT_LOGI(
      "%s %s [%s] duration: %llu [usec] %zu [bytes]\n",
      method_map[method].c_str(), url.c_str(), name.c_str(),
      (unsigned long long)std::chrono::duration_cast<std::chrono::microseconds>(
          end - start)
          .count(),
      response->size());

  return *this;
}

std::string HTTPClientConnection::sendRequestGetReply(
    const HTTPRequest &request, std::shared_ptr<HTTPResponse> &response) {
  const std::string &request_string = request.getRequestString();
  const std::string &locator = request.getLocator();

  // Hash it

  uint32_t locator_hash =
      utils::hash::fnv32_buf(locator.c_str(), locator.size());
  uint64_t request_hash =
      utils::hash::fnv64_buf(request_string.c_str(), request_string.size());

  consumer_.setSocketOption(
      ConsumerCallbacksOptions::INTEREST_OUTPUT,
      (ConsumerInterestCallback)std::bind(
          &HTTPClientConnection::processLeavingInterest, this,
          std::placeholders::_1, std::placeholders::_2, request_string));

  // Send content to producer piggybacking it through first interest (to fix)

  response->clear();

  // Factor hicn name using hash

  std::stringstream stream;

  stream << std::hex << http::default_values::ipv6_first_word << ":";

  for (uint16_t *word = (uint16_t *)&locator_hash;
       std::size_t(word) < (std::size_t(&locator_hash) + sizeof(locator_hash));
       word++) {
    stream << ":" << std::hex << *word;
  }

  for (uint16_t *word = (uint16_t *)&request_hash;
       std::size_t(word) < (std::size_t(&request_hash) + sizeof(request_hash));
       word++) {
    stream << ":" << std::hex << *word;
  }

  stream << "|0";

  consumer_.consume(Name(stream.str()), *response);

  consumer_.stop();

  return stream.str();
}

HTTPResponse &&HTTPClientConnection::response() {
  // response_->parse();
  return std::move(*response_);
}

void HTTPClientConnection::processPayload(ConsumerSocket &c,
                                          std::size_t bytes_transferred,
                                          const std::error_code &ec) {
  if (ec) {
    TRANSPORT_LOGE("Download failed!!");
  }
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
    ConsumerSocket &c, const core::Interest &interest, std::string &payload) {
  //  if (interest.getName().getSuffix() == 0) {
  Interest &int2 = const_cast<Interest &>(interest);
  int2.appendPayload((uint8_t *)payload.data(), payload.size());
  //  }
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

}  // namespace http

}  // namespace transport
