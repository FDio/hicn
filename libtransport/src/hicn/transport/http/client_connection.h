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

#pragma once

#include <hicn/transport/http/default_values.h>
#include <hicn/transport/http/request.h>
#include <hicn/transport/http/response.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_producer.h>
#include <hicn/transport/utils/uri.h>

#include <vector>

namespace transport {

namespace http {

using namespace interface;
using namespace core;

class HTTPClientConnection : public ConsumerSocket::ReadCallback {
  static constexpr uint32_t max_buffer_capacity = 64 * 1024;

 public:
  class ReadBytesCallback {
   public:
    virtual void onBytesReceived(std::unique_ptr<utils::MemBuf> &&buffer) = 0;
    virtual void onSuccess(std::size_t bytes) = 0;
    virtual void onError(const std::error_code ec) = 0;
  };

  enum class RC : uint32_t { DOWNLOAD_FAILED, DOWNLOAD_SUCCESS };

  HTTPClientConnection();

  RC get(const std::string &url, HTTPHeaders headers = {},
         HTTPPayload &&payload = nullptr,
         std::shared_ptr<HTTPResponse> response = nullptr,
         ReadBytesCallback *callback = nullptr,
         std::string ipv6_first_word = "b001");

  RC sendRequest(const std::string &url, HTTPMethod method,
                 HTTPHeaders headers = {}, HTTPPayload &&payload = nullptr,
                 std::shared_ptr<HTTPResponse> response = nullptr,
                 ReadBytesCallback *callback = nullptr,
                 std::string ipv6_first_word = "b001");

  std::shared_ptr<HTTPResponse> response();

  HTTPClientConnection &stop();

  interface::ConsumerSocket &getConsumer();

  HTTPClientConnection &setTimeout(const std::chrono::seconds &timeout);

  HTTPClientConnection &setCertificate(const std::string &cert_path);

 private:
  void sendRequestGetReply(std::string &ipv6_first_word);

  bool verifyData(interface::ConsumerSocket &c,
                  const core::ContentObject &contentObject);

  void processLeavingInterest(interface::ConsumerSocket &c,
                              const core::Interest &interest);

  // Read callback
  bool isBufferMovable() noexcept override { return true; }
  void getReadBuffer(uint8_t **application_buffer,
                     size_t *max_length) override {}
  void readDataAvailable(size_t length) noexcept override {}
  size_t maxBufferSize() const override { return max_buffer_capacity; }
  void readBufferAvailable(
      std::unique_ptr<utils::MemBuf> &&buffer) noexcept override;
  void readError(const std::error_code ec) noexcept override;
  void readSuccess(std::size_t total_size) noexcept override;

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

}  // end namespace http

}  // end namespace transport