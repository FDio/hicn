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

#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/core/prefix.h>

#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#endif
#include <asio/io_service.hpp>

#define UNSET_CALLBACK 0

namespace transport {

namespace interface {

template <typename PrefixType>
class BasicBindConfig {
  static_assert(std::is_same<core::Prefix, PrefixType>::value,
                "Prefix must be a Prefix type.");

  const uint32_t standard_cs_reserved = 5000;

 public:
  template <typename T>
  BasicBindConfig(T &&prefix)
      : prefix_(std::forward<T &&>(prefix)),
        content_store_reserved_(standard_cs_reserved) {}

  template <typename T>
  BasicBindConfig(T &&prefix, uint32_t cs_reserved)
      : prefix_(std::forward<T &&>(prefix)),
        content_store_reserved_(cs_reserved) {}

  TRANSPORT_ALWAYS_INLINE const PrefixType &prefix() const { return prefix_; }

  TRANSPORT_ALWAYS_INLINE uint32_t csReserved() const {
    return content_store_reserved_;
  }

 private:
  PrefixType prefix_;
  uint32_t content_store_reserved_;
};

using BindConfig = BasicBindConfig<core::Prefix>;

class Portal {
 public:
  /**
   * Consumer callback is an abstract class containing two methods to be
   * implemented by a consumer application.
   */
  class ConsumerCallback {
   public:
    virtual void onContentObject(core::Interest::Ptr &&i,
                                 core::ContentObject::Ptr &&c) = 0;
    virtual void onTimeout(core::Interest::Ptr &&i) = 0;
    virtual void onError(std::error_code ec) = 0;
  };

  /**
   * Producer callback is an abstract class containing two methods to be
   * implemented by a producer application.
   */
  class ProducerCallback {
   public:
    virtual void onInterest(core::Interest::Ptr &&i) = 0;
    virtual void onError(std::error_code ec) = 0;
  };

  using OnContentObjectCallback =
      std::function<void(core::Interest::Ptr &&, core::ContentObject::Ptr &&)>;
  using OnInterestTimeoutCallback = std::function<void(core::Interest::Ptr &&)>;

  Portal();

  Portal(asio::io_service &io_service);

  /**
   * Set the consumer callback.
   *
   * @param consumer_callback - The pointer to the ConsumerCallback object.
   */
  void setConsumerCallback(ConsumerCallback *consumer_callback);

  /**
   * Set the producer callback.
   *
   * @param producer_callback - The pointer to the ProducerCallback object.
   */
  void setProducerCallback(ProducerCallback *producer_callback);

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
   * Register a producer name to the local forwarder and optionally set the
   * content store size in a per-face manner.
   *
   * @param config - The configuration for the local forwarder binding.
   */
  void bind(const BindConfig &config);

  void runEventsLoop();

  /**
   * Run one event and return.
   */
  void runOneEvent();

  /**
   * Send a data packet to the local forwarder. As opposite to sendInterest, the
   * ownership of the content object is not transferred to the portal.
   *
   * @param content_object - The data packet.
   */
  void sendContentObject(core::ContentObject &content_object);
  /**
   * Stop the event loop, canceling all the pending events in the event queue.
   *
   * Beware that stopping the event loop DOES NOT disconnect the transport from
   * the local forwarder, the connector underneath will stay connected.
   */
  void stopEventsLoop();

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
  asio::io_service &getIoService();

  /**
   * Register a route to the local forwarder.
   */
  void registerRoute(core::Prefix &prefix);

 private:
  void *implementation_;
};

}  // namespace interface
}  // namespace transport