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

#include <hicn/transport/interfaces/socket_producer.h>
#include <implementation/socket_producer.h>

#include <atomic>
#include <cmath>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

namespace transport {

namespace interface {

using namespace core;

ProducerSocket::ProducerSocket(int protocol) {
  socket_ = std::make_unique<implementation::ProducerSocket>(this, protocol);
}

ProducerSocket::ProducerSocket(int protocol, asio::io_service &io_service) {
  socket_ = std::make_unique<implementation::ProducerSocket>(this, protocol,
                                                             io_service);
}

ProducerSocket::ProducerSocket(bool) {}

ProducerSocket::~ProducerSocket() { socket_->stop(); }

void ProducerSocket::connect() { socket_->connect(); }

bool ProducerSocket::isRunning() { return socket_->isRunning(); }

uint32_t ProducerSocket::produceStream(const Name &content_name,
                                       std::unique_ptr<utils::MemBuf> &&buffer,
                                       bool is_last, uint32_t start_offset) {
  return socket_->produceStream(content_name, std::move(buffer), is_last,
                                start_offset);
}

uint32_t ProducerSocket::produceStream(const Name &content_name,
                                       const uint8_t *buffer,
                                       size_t buffer_size, bool is_last,
                                       uint32_t start_offset) {
  return socket_->produceStream(content_name, buffer, buffer_size, is_last,
                                start_offset);
}

uint32_t ProducerSocket::produceDatagram(
    const Name &content_name, std::unique_ptr<utils::MemBuf> &&buffer) {
  return socket_->produceDatagram(content_name, std::move(buffer));
}

uint32_t ProducerSocket::produceDatagram(const Name &content_name,
                                         const uint8_t *buffer,
                                         size_t buffer_size) {
  return socket_->produceDatagram(content_name, buffer, buffer_size);
}

void ProducerSocket::produce(ContentObject &content_object) {
  return socket_->produce(content_object);
}

void ProducerSocket::asyncProduce(Name content_name,
                                  std::unique_ptr<utils::MemBuf> &&buffer,
                                  bool is_last, uint32_t offset,
                                  uint32_t **last_segment) {
  return socket_->asyncProduce(content_name, std::move(buffer), is_last, offset,
                               last_segment);
}

void ProducerSocket::registerPrefix(const Prefix &producer_namespace) {
  return socket_->registerPrefix(producer_namespace);
}

void ProducerSocket::stop() { return socket_->stop(); }

asio::io_service &ProducerSocket::getIoService() {
  return socket_->getIoService();
};

int ProducerSocket::setSocketOption(int socket_option_key,
                                    uint32_t socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    std::nullptr_t socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    bool socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    Name *socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ProducerContentObjectCallback socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ProducerInterestCallback socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ProducerContentCallback socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    auth::CryptoHashType socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::setSocketOption(
    int socket_option_key,
    const std::shared_ptr<auth::Signer> &socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    uint32_t &socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    const std::string &socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    bool &socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::getSocketOption(
    int socket_option_key,
    ProducerContentObjectCallback **socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::getSocketOption(
    int socket_option_key, ProducerContentCallback **socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::getSocketOption(
    int socket_option_key, ProducerInterestCallback **socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    auth::CryptoHashType &socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::getSocketOption(
    int socket_option_key, std::shared_ptr<auth::Signer> &socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

}  // namespace interface

}  // namespace transport
