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

#pragma once

#include <hicn/transport/core/asio_wrapper.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/utils/event_thread.h>
#include <hicn/transport/utils/noncopyable.h>

#include <functional>

#define UNSET_CALLBACK 0

namespace transport {

namespace interface {

class Portal : private utils::NonCopyable {
 public:
  /**
   * Transport callback is an abstract class containing two methods to be
   * implemented by a consumer/producer application.
   */
  class TransportCallback {
   public:
    virtual void onInterest(core::Interest &i) = 0;
    virtual void onContentObject(core::Interest &i, core::ContentObject &c) = 0;
    virtual void onTimeout(core::Interest::Ptr &i, const core::Name &n) = 0;
    virtual void onError(const std::error_code &ec) = 0;
  };

  using OnContentObjectCallback =
      std::function<void(core::Interest &, core::ContentObject &)>;
  using OnInterestTimeoutCallback =
      std::function<void(core::Interest::Ptr &, const core::Name &)>;

  Portal();

  Portal(::utils::EventThread &worker);

  /**
   * Set the transport protocl callback.
   *
   * @param producer_callback - The pointer to the ProducerCallback object.
   */
  void registerTransportCallback(TransportCallback *transport_callback);

  /**
   * Connect the transport to the local hicn forwarder.
   *
   * @param is_consumer - Boolean specifying if the application on top of portal
   * is a consumer or a producer.
   */
  void connect(bool is_consumer = true);

  /**
   * Destructor.
   */
  ~Portal();

  /**
   * Check if there is already a pending interest for a given name.
   *
   * @param name - The interest name.
   */
  bool interestIsPending(const core::Name &name);

  /**
   * Send an interest through to the local forwarder.
   *
   * @param interest - The pointer to the interest. The ownership of the
   * interest is transferred by the caller to portal.
   *
   * @param on_content_object_callback - If the caller wishes to use a different
   * callback to be called for this interest, it can set this parameter.
   * Otherwise ConsumerCallback::onContentObject will be used.
   *
   * @param on_interest_timeout_callback - If the caller wishes to use a
   * different callback to be called for this interest, it can set this
   * parameter. Otherwise ConsumerCallback::onTimeout will be used.
   */
  void sendInterest(
      core::Interest::Ptr &&interest,
      OnContentObjectCallback &&on_content_object_callback = UNSET_CALLBACK,
      OnInterestTimeoutCallback &&on_interest_timeout_callback =
          UNSET_CALLBACK);

  /**
   * Send a data packet to the local forwarder. As opposite to sendInterest, the
   * ownership of the content object is not transferred to the portal.
   *
   * @param content_object - The data packet.
   */
  void sendContentObject(core::ContentObject &content_object);

  /**
   * Disconnect the transport from the local forwarder.
   */
  void killConnection();

  /**
   * Clear the pending interest hash table.
   */
  void clear();

  /**
   * Get a reference to the io_service object.
   */
  utils::EventThread &getThread();

  /**
   * Register a route to the local forwarder.
   */
  void registerRoute(core::Prefix &prefix);

  /**
   * Send a MAP-Me command to traverse NATs.
   */
  void sendMapme();

  /**
   * Set forwarding strategy
   */
  void setForwardingStrategy(core::Prefix &prefix, std::string &strategy);

 private:
  class Impl;
  Impl *implementation_;
};

}  // namespace interface
}  // namespace transport
