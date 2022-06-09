/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <core/portal.h>
#include <hicn/transport/interfaces/portal.h>

namespace transport {
namespace interface {

class Portal::Impl {
 public:
  Impl() : portal_(core::Portal::createShared()) {}
  Impl(::utils::EventThread &worker)
      : portal_(core::Portal::createShared(worker)) {}

  void registerTransportCallback(TransportCallback *transport_callback) {
    portal_->registerTransportCallback(transport_callback);
  }

  void connect(bool is_consumer) { portal_->connect(is_consumer); }

  bool interestIsPending(const core::Name &name) {
    return portal_->interestIsPending(name);
  }

  void sendInterest(core::Interest::Ptr &interest, uint32_t lifetime,
                    OnContentObjectCallback &&on_content_object_callback,
                    OnInterestTimeoutCallback &&on_interest_timeout_callback) {
    portal_->sendInterest(interest, lifetime,
                          std::move(on_content_object_callback),
                          std::move(on_interest_timeout_callback));
  }

  void sendContentObject(core::ContentObject &content_object) {
    portal_->sendContentObject(content_object);
  }

  void killConnection() { portal_->killConnection(); }

  void clear() { portal_->clear(); }

  utils::EventThread &getThread() { return portal_->getThread(); }

  void registerRoute(core::Prefix &prefix) { portal_->registerRoute(prefix); }

  void sendMapme() { portal_->sendMapme(); }

  void setForwardingStrategy(core::Prefix &prefix, std::string &strategy) {
    portal_->setForwardingStrategy(prefix, strategy);
  }

 private:
  std::shared_ptr<core::Portal> portal_;
};

Portal::Portal() { implementation_ = new Impl(); }

Portal::Portal(::utils::EventThread &worker) {
  implementation_ = new Impl(worker);
}

Portal::~Portal() { delete implementation_; }

void Portal::registerTransportCallback(TransportCallback *transport_callback) {
  implementation_->registerTransportCallback(transport_callback);
}

void Portal::connect(bool is_consumer) {
  implementation_->connect(is_consumer);
}

bool Portal::interestIsPending(const core::Name &name) {
  return implementation_->interestIsPending(name);
}

void Portal::sendInterest(
    core::Interest::Ptr &interest, uint32_t lifetime,
    OnContentObjectCallback &&on_content_object_callback,
    OnInterestTimeoutCallback &&on_interest_timeout_callback) {
  implementation_->sendInterest(interest, lifetime,
                                std::move(on_content_object_callback),
                                std::move(on_interest_timeout_callback));
}

void Portal::sendContentObject(core::ContentObject &content_object) {
  implementation_->sendContentObject(content_object);
}

void Portal::killConnection() { implementation_->killConnection(); }

void Portal::clear() { implementation_->clear(); }

utils::EventThread &Portal::getThread() { return implementation_->getThread(); }

void Portal::registerRoute(core::Prefix &prefix) {
  implementation_->registerRoute(prefix);
}

void Portal::sendMapme() { implementation_->sendMapme(); }

void Portal::setForwardingStrategy(core::Prefix &prefix,
                                   std::string &strategy) {
  implementation_->setForwardingStrategy(prefix, strategy);
}

}  // namespace interface

}  // namespace transport
