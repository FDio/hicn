/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <hicn/transport/interfaces/portal.h>
#include <implementation/socket.h>

namespace transport {
namespace interface {

Portal::Portal() { implementation_ = new core::Portal(); }

Portal::Portal(asio::io_service &io_service) {
  implementation_ = new core::Portal(io_service);
}

Portal::~Portal() { delete reinterpret_cast<core::Portal *>(implementation_); }

void Portal::setConsumerCallback(ConsumerCallback *consumer_callback) {
  reinterpret_cast<core::Portal *>(implementation_)
      ->setConsumerCallback(consumer_callback);
}

void Portal::setProducerCallback(ProducerCallback *producer_callback) {
  reinterpret_cast<core::Portal *>(implementation_)
      ->setProducerCallback(producer_callback);
}

void Portal::connect(bool is_consumer) {
  reinterpret_cast<core::Portal *>(implementation_)->connect(is_consumer);
}

bool Portal::interestIsPending(const core::Name &name) {
  return reinterpret_cast<core::Portal *>(implementation_)
      ->interestIsPending(name);
}

void Portal::sendInterest(
    core::Interest::Ptr &&interest,
    OnContentObjectCallback &&on_content_object_callback,
    OnInterestTimeoutCallback &&on_interest_timeout_callback) {
  reinterpret_cast<core::Portal *>(implementation_)
      ->sendInterest(std::move(interest), std::move(on_content_object_callback),
                     std::move(on_interest_timeout_callback));
}

void Portal::bind(const BindConfig &config) {
  reinterpret_cast<core::Portal *>(implementation_)->bind(config);
}

void Portal::runEventsLoop() {
  reinterpret_cast<core::Portal *>(implementation_)->runEventsLoop();
}

void Portal::runOneEvent() {
  reinterpret_cast<core::Portal *>(implementation_)->runOneEvent();
}

void Portal::sendContentObject(core::ContentObject &content_object) {
  reinterpret_cast<core::Portal *>(implementation_)
      ->sendContentObject(content_object);
}

void Portal::stopEventsLoop() {
  reinterpret_cast<core::Portal *>(implementation_)->stopEventsLoop();
}

void Portal::killConnection() {
  reinterpret_cast<core::Portal *>(implementation_)->killConnection();
}

void Portal::clear() {
  reinterpret_cast<core::Portal *>(implementation_)->clear();
}

asio::io_service &Portal::getIoService() {
  return reinterpret_cast<core::Portal *>(implementation_)->getIoService();
}

void Portal::registerRoute(core::Prefix &prefix) {
  reinterpret_cast<core::Portal *>(implementation_)->registerRoute(prefix);
}

}  // namespace interface

}  // namespace transport