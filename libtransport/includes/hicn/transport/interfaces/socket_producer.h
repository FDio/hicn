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

#pragma once

#include <hicn/transport/config.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/interfaces/callbacks.h>
#include <hicn/transport/interfaces/socket_options_default_values.h>
#include <hicn/transport/interfaces/socket_options_keys.h>
#include <hicn/transport/security/signer.h>

namespace asio {
class io_service;
}  // namespace asio

namespace transport {

namespace implementation {
class ProducerSocket;
}

namespace interface {

using namespace core;

class ProducerSocket {
 public:
  explicit ProducerSocket(int protocol = 0);

  virtual ~ProducerSocket();

  void connect();

  bool isRunning();

  uint32_t produce(Name content_name, const uint8_t *buffer, size_t buffer_size,
                   bool is_last = true, uint32_t start_offset = 0) {
    return produce(content_name, utils::MemBuf::copyBuffer(buffer, buffer_size),
                   is_last, start_offset);
  }

  uint32_t produce(Name content_name, std::unique_ptr<utils::MemBuf> &&buffer,
                   bool is_last = true, uint32_t start_offset = 0);

  void produce(ContentObject &content_object);

  void produce(const uint8_t *buffer, size_t buffer_size) {
    produce(utils::MemBuf::copyBuffer(buffer, buffer_size));
  }

  void produce(std::unique_ptr<utils::MemBuf> &&buffer);

  void asyncProduce(const Name &suffix, const uint8_t *buf, size_t buffer_size,
                    bool is_last = true, uint32_t *start_offset = nullptr);

  void asyncProduce(Name content_name, std::unique_ptr<utils::MemBuf> &&buffer,
                    bool is_last, uint32_t offset,
                    uint32_t **last_segment = nullptr);

  void asyncProduce(ContentObject &content_object);

  void registerPrefix(const Prefix &producer_namespace);

  void serveForever();

  void stop();

  asio::io_service &getIoService();

  int setSocketOption(int socket_option_key, uint32_t socket_option_value);

  int setSocketOption(int socket_option_key,
                      std::nullptr_t socket_option_value);

  int setSocketOption(int socket_option_key, bool socket_option_value);

  int setSocketOption(int socket_option_key, Name *socket_option_value);

  int setSocketOption(int socket_option_key,
                      std::list<Prefix> socket_option_value);

  int setSocketOption(int socket_option_key,
                      ProducerContentObjectCallback socket_option_value);

  int setSocketOption(int socket_option_key,
                      ProducerInterestCallback socket_option_value);

  int setSocketOption(int socket_option_key,
                      ProducerContentCallback socket_option_value);

  int setSocketOption(int socket_option_key, HashAlgorithm socket_option_value);

  int setSocketOption(int socket_option_key,
                      utils::CryptoSuite socket_option_value);

  int setSocketOption(
      int socket_option_key,
      const std::shared_ptr<utils::Signer> &socket_option_value);

  int setSocketOption(int socket_option_key,
                      const std::string &socket_option_value);

  int getSocketOption(int socket_option_key, uint32_t &socket_option_value);

  int getSocketOption(int socket_option_key, bool &socket_option_value);

  int getSocketOption(int socket_option_key,
                      std::list<Prefix> &socket_option_value);

  int getSocketOption(int socket_option_key,
                      ProducerContentObjectCallback **socket_option_value);

  int getSocketOption(int socket_option_key,
                      ProducerContentCallback **socket_option_value);

  int getSocketOption(int socket_option_key,
                      ProducerInterestCallback **socket_option_value);

  int getSocketOption(int socket_option_key,
                      HashAlgorithm &socket_option_value);

  int getSocketOption(int socket_option_key,
                      utils::CryptoSuite &socket_option_value);

  int getSocketOption(int socket_option_key,
                      std::shared_ptr<utils::Signer> &socket_option_value);

  int getSocketOption(int socket_option_key, std::string &socket_option_value);

 protected:
  ProducerSocket(bool);
  std::unique_ptr<implementation::ProducerSocket> socket_;
};

}  // namespace interface

}  // namespace transport
