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

#include <hicn/transport/interfaces/socket_consumer.h>

#include <implementation/socket_consumer.h>

namespace transport {
namespace interface {

ConsumerSocket::ConsumerSocket(int protocol) {
  socket_ = std::make_unique<implementation::ConsumerSocket>(this, protocol);
}

ConsumerSocket::ConsumerSocket() {}

ConsumerSocket::~ConsumerSocket() { socket_->stop(); }

void ConsumerSocket::connect() { socket_->connect(); }

bool ConsumerSocket::isRunning() { return socket_->isRunning(); }

int ConsumerSocket::consume(const Name &name) { return socket_->consume(name); }

int ConsumerSocket::asyncConsume(const Name &name) {
  return socket_->asyncConsume(name);
}

void ConsumerSocket::stop() { socket_->stop(); }

void ConsumerSocket::resume() { socket_->resume(); }

bool ConsumerSocket::verifyKeyPackets() { return socket_->verifyKeyPackets(); }

asio::io_service &ConsumerSocket::getIoService() {
  return socket_->getIoService();
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    ReadCallback *socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    ReadCallback **socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    double socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    uint32_t socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    std::nullptr_t socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    bool socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(
    int socket_option_key, ConsumerContentObjectCallback socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(
    int socket_option_key,
    ConsumerContentObjectVerificationCallback socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(
    int socket_option_key, ConsumerInterestCallback socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(
    int socket_option_key,
    ConsumerContentObjectVerificationFailedCallback socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    IcnObserver *socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(
    int socket_option_key,
    const std::shared_ptr<utils::Verifier> &socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    const std::string &socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    ConsumerTimerCallback socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    double &socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    uint32_t &socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    bool &socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    Name **socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(
    int socket_option_key,
    ConsumerContentObjectCallback **socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(
    int socket_option_key,
    ConsumerContentObjectVerificationCallback **socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(
    int socket_option_key, ConsumerInterestCallback **socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(
    int socket_option_key,
    ConsumerContentObjectVerificationFailedCallback **socket_option_value) {
  return socket_->setSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    IcnObserver **socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(
    int socket_option_key,
    std::shared_ptr<utils::Verifier> &socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    std::string &socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(
    int socket_option_key,
    interface::TransportStatistics **socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

int ConsumerSocket::getSocketOption(
    int socket_option_key, ConsumerTimerCallback **socket_option_value) {
  return socket_->getSocketOption(socket_option_key, socket_option_value);
}

}  // namespace interface

}  // namespace transport
