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
  if (protocol != 0) {
    throw std::runtime_error("Production protocol must be 0.");
  }

  socket_ = std::make_unique<implementation::ProducerSocket>(this);
}

ProducerSocket::ProducerSocket(bool) {}

ProducerSocket::~ProducerSocket() { socket_->stop(); }

void ProducerSocket::connect() { socket_->connect(); }

bool ProducerSocket::isRunning() { return socket_->isRunning(); }

uint32_t ProducerSocket::produce(Name content_name,
                                 std::unique_ptr<utils::MemBuf> &&buffer,
                                 bool is_last, uint32_t start_offset) {
  return socket_->produce(content_name, std::move(buffer), is_last,
                          start_offset);
}

void ProducerSocket::produce(ContentObject &content_object) {
  return socket_->produce(content_object);
}

void ProducerSocket::produce(std::unique_ptr<utils::MemBuf> &&buffer) {
  socket_->produce(std::move(buffer));
}

void ProducerSocket::asyncProduce(Name content_name,
                                  std::unique_ptr<utils::MemBuf> &&buffer,
                                  bool is_last, uint32_t offset,
                                  uint32_t **last_segment) {
  return socket_->asyncProduce(content_name, std::move(buffer), is_last, offset,
                               last_segment);
}

void ProducerSocket::asyncProduce(ContentObject &content_object) {
  return socket_->asyncProduce(content_object);
}

void ProducerSocket::registerPrefix(const Prefix &producer_namespace) {
  return socket_->registerPrefix(producer_namespace);
}

void ProducerSocket::serveForever() { return socket_->serveForever(); }

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

int ProducerSocket::setSocketOption(int socket_option_key,
                                    std::list<Prefix> socket_option_value) {
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
                                    utils::CryptoHashType socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    utils::CryptoSuite socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::setSocketOption(
    int socket_option_key,
    const std::shared_ptr<utils::Signer> &socket_option_value) {
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

int ProducerSocket::getSocketOption(int socket_option_key,
                                    std::list<Prefix> &socket_option_value) {
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

int ProducerSocket::getSocketOption(
    int socket_option_key, utils::CryptoHashType &socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    utils::CryptoSuite &socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ProducerSocket::getSocketOption(
    int socket_option_key,
    std::shared_ptr<utils::Signer> &socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

}  // namespace interface

}  // namespace transport
