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

#include <hicn/transport/http/server_publisher.h>
#include <hicn/transport/utils/literals.h>

namespace transport {

namespace http {

HTTPServerPublisher::HTTPServerPublisher(const core::Name &content_name)
    : content_name_(content_name, true) {
  std::string identity = "acceptor_producer";
  producer_ = std::make_unique<ProducerSocket>(io_service_);
  //                                                          utils::Identity::generateIdentity(identity));
  core::Prefix publisher_prefix(content_name_, 128);
  producer_->registerPrefix(publisher_prefix);
}

HTTPServerPublisher::~HTTPServerPublisher() {
  if (timer_) {
    this->timer_->cancel();
  }
}

HTTPServerPublisher &HTTPServerPublisher::attachPublisher() {
  // Create a new publisher
  producer_->setSocketOption(GeneralTransportOptions::DATA_PACKET_SIZE,
                             1410_U32);
  producer_->connect();
  return *this;
}

HTTPServerPublisher &HTTPServerPublisher::setTimeout(
    const std::chrono::milliseconds &timeout, bool timeout_renewal) {
  std::shared_ptr<typename ProducerSocket::Portal> portal;
  producer_->getSocketOption(GeneralTransportOptions::PORTAL, portal);
  timer_ =
      std::make_unique<asio::steady_timer>(portal->getIoService(), timeout);

  wait_callback_ = [this](const std::error_code &e) {
    if (!e) {
      producer_->stop();
    }
  };

  if (timeout_renewal) {
    interest_enter_callback_ = [this, timeout](ProducerSocket &p,
                                               const Interest &interest) {
      this->timer_->cancel();
      this->timer_->expires_from_now(timeout);
      this->timer_->async_wait(wait_callback_);
    };

    producer_->setSocketOption(
        ProducerCallbacksOptions::CACHE_HIT,
        (ProducerInterestCallback)interest_enter_callback_);
  }

  timer_->async_wait(wait_callback_);

  return *this;
}

void HTTPServerPublisher::publishContent(
    const uint8_t *buf, size_t buffer_size,
    std::chrono::milliseconds content_lifetime, bool is_last) {
  if (producer_) {
    producer_->setSocketOption(
        GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
        static_cast<uint32_t>(content_lifetime.count()));
    producer_->produce(content_name_, buf, buffer_size, is_last);
    //    producer_->setSocketOption(ProducerCallbacksOptions::CACHE_MISS,
    //                                [this](ProducerSocket &p, const
    //                                core::Interest &interest){
    //                                  producer_->stop();
    //                                });
  }
}

template <typename Handler>
void HTTPServerPublisher::asyncPublishContent(
    const uint8_t *buf, size_t buffer_size,
    std::chrono::milliseconds content_lifetime, Handler &&handler,
    bool is_last) {
  if (producer_) {
    producer_->setSocketOption(
        GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
        static_cast<uint32_t>(content_lifetime.count()));
    producer_->asyncProduce(content_name_, buf, buffer_size,
                            std::forward<Handler>(handler), is_last);
  }
}

void HTTPServerPublisher::serveClients() { producer_->serveForever(); }

void HTTPServerPublisher::stop() {
  std::shared_ptr<typename ProducerSocket::Portal> portal_ptr;
  producer_->getSocketOption(GeneralTransportOptions::PORTAL, portal_ptr);
  portal_ptr->getIoService().stop();
}

ProducerSocket &HTTPServerPublisher::getProducer() { return *producer_; }

void HTTPServerPublisher::setPublisherName(std::string &name,
                                           std::string &mask) {
  // Name represents the last 64 bits of the ipv6 address.
  // It is an ipv6 address with the first 64 bits set to 0
  uint16_t i;
  std::string s = content_name_.toString();
  std::shared_ptr<core::Sockaddr> sockaddr = content_name_.getAddress();
  in6_addr name_ipv6 = ((core::Sockaddr6 *)sockaddr.get())->sin6_addr;

  in6_addr bitmask, new_address, _name;

  if (inet_pton(AF_INET6, mask.c_str(), &bitmask) != 1) {
    throw errors::RuntimeException("Error during conversion to ipv6 address.");
  }

  if (inet_pton(AF_INET6, name.c_str(), &_name) != 1) {
    throw errors::RuntimeException("Error during conversion to ipv6 address.");
  }

  for (i = 0; i < sizeof(new_address.s6_addr); i++) {
    new_address.s6_addr[i] = name_ipv6.s6_addr[i] & bitmask.s6_addr[i];
  }

  for (i = 0; i < sizeof(new_address.s6_addr); i++) {
    new_address.s6_addr[i] |= _name.s6_addr[i] & ~bitmask.s6_addr[i];
  }

  // Effectively change the name
  char str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &new_address, str, INET6_ADDRSTRLEN);
  std::string str2(str);

  core::Name new_name(str2, 0);

  // If the new name differs from the one required by the consumer part, send a
  // manifest
  if (!new_name.equals(content_name_, false)) {
    // Publish manifest pointing to the new name

    auto manifest =
        std::make_shared<ContentObjectManifest>(content_name_.setSuffix(0));

    content_name_ = core::Name(str2, 0);

    //    manifest->setNameList(content_name_);
    manifest->setLifetime(4000 * 1000);
    manifest->encode();
    producer_->produce(*manifest);

    core::Prefix ns(content_name_, 128);
    producer_->registerPrefix(ns);
  }
}

}  // namespace http

}  // namespace transport
