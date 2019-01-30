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

#include <hicn/transport/http/server_acceptor.h>
#include <hicn/transport/utils/hash.h>
#include <hicn/transport/utils/uri.h>

namespace transport {

namespace http {

HTTPServerAcceptor::HTTPServerAcceptor(std::string &&server_locator,
                                       OnHttpRequest callback)
    : HTTPServerAcceptor(server_locator, callback) {}

HTTPServerAcceptor::HTTPServerAcceptor(std::string &server_locator,
                                       OnHttpRequest callback)
    : callback_(callback) {
  utils::Uri uri;

  uri.parseProtocolAndLocator(server_locator);
  std::string protocol = uri.getProtocol();
  std::string locator = uri.getLocator();

  std::transform(locator.begin(), locator.end(), locator.begin(), ::tolower);

  std::transform(protocol.begin(), protocol.end(), protocol.begin(), ::tolower);

  if (protocol != "http") {
    throw errors::RuntimeException(
        "Malformed server_locator. The locator format should be in the form "
        "http://locator");
  }

  uint32_t locator_hash =
      utils::hash::fnv32_buf(locator.c_str(), locator.size());

  std::stringstream stream;
  stream << std::hex << http::default_values::ipv6_first_word << ":0000";

  for (uint16_t *word = (uint16_t *)&locator_hash;
       std::size_t(word) < (std::size_t(&locator_hash) + sizeof(locator_hash));
       word++) {
    stream << ":" << std::hex << *word;
  }

  stream << "::0";

  std::string network = stream.str();

  core::Prefix acceptor_namespace(network, 64);

  std::string producer_identity = "acceptor_producer";
  acceptor_producer_ = std::make_shared<ProducerSocket>(
      io_service_); /*,
                                 utils::Identity::generateIdentity(producer_identity));*/
  acceptor_producer_->registerPrefix(acceptor_namespace);
}

void HTTPServerAcceptor::listen(bool async) {
  acceptor_producer_->setSocketOption(
      ProducerCallbacksOptions::INTEREST_INPUT,
      (ProducerInterestCallback)bind(
          &HTTPServerAcceptor::processIncomingInterest, this,
          std::placeholders::_1, std::placeholders::_2));
  acceptor_producer_->connect();

  if (!async) {
    acceptor_producer_->serveForever();
  }
}

void HTTPServerAcceptor::processIncomingInterest(ProducerSocket &p,
                                                 const Interest &interest) {
  // Temporary solution. With
  utils::Array<uint8_t> payload = interest.getPayload();

  int request_id = utils::hash::fnv32_buf(payload.data(), payload.length());

  if (publishers_.find(request_id) != publishers_.end()) {
    if (publishers_[request_id]) {
      publishers_[request_id]->getProducer().onInterest(interest);
      return;
    }
  }

  publishers_[request_id] =
      std::make_shared<HTTPServerPublisher>(interest.getName());
  callback_(publishers_[request_id], (uint8_t *)payload.data(),
            payload.length(), request_id);
}

std::map<int, std::shared_ptr<HTTPServerPublisher>>
    &HTTPServerAcceptor::getPublishers() {
  return publishers_;
}

}  // namespace http

}  // namespace transport
