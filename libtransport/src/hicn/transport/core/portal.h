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
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/forwarder_interface.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/core/pending_interest.h>
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/core/udp_socket_connector.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/portability/portability.h>
#include <hicn/transport/utils/log.h>

#ifdef __vpp__
#include <hicn/transport/core/memif_connector.h>
#endif

#include <asio.hpp>
#include <asio/steady_timer.hpp>
#include <future>
#include <memory>
#include <unordered_map>

#define UNSET_CALLBACK 0

namespace transport {

namespace core {

using PendingInterestHashTable =
    std::unordered_map<uint32_t, PendingInterest::Ptr>;

template <typename PrefixType>
class BasicBindConfig {
  static_assert(std::is_same<Prefix, PrefixType>::value,
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

using BindConfig = BasicBindConfig<Prefix>;

template <typename ForwarderInt>
class Portal {
  static_assert(
      std::is_base_of<ForwarderInterface<ForwarderInt,
                                         typename ForwarderInt::ConnectorType>,
                      ForwarderInt>::value,
      "ForwarderInt must inherit from ForwarderInterface!");

  static constexpr uint32_t pool_size = 2048;

 public:
  class ConsumerCallback {
   public:
    virtual void onContentObject(Interest::Ptr &&i, ContentObject::Ptr &&c) = 0;
    virtual void onTimeout(Interest::Ptr &&i) = 0;
  };

  class ProducerCallback {
   public:
    virtual void onInterest(Interest::Ptr &&i) = 0;
  };

  Portal() : Portal(internal_io_service_) {}

  Portal(asio::io_service &io_service)
      : io_service_(io_service),
        app_name_("libtransport_application"),
        consumer_callback_(nullptr),
        producer_callback_(nullptr),
        connector_(std::bind(&Portal::processIncomingMessages, this,
                             std::placeholders::_1),
                   std::bind(&Portal::setLocalRoutes, this), io_service_,
                   app_name_),
        forwarder_interface_(connector_) {
    increasePendingInterestPool();
    increaseInterestPool();
    increaseContentObjectPool();
  }

  void setConsumerCallback(ConsumerCallback *consumer_callback) {
    consumer_callback_ = consumer_callback;
  }

  void setProducerCallback(ProducerCallback *producer_callback) {
    producer_callback_ = producer_callback;
  }

  TRANSPORT_ALWAYS_INLINE void setOutputInterface(
      const std::string &output_interface) {
    forwarder_interface_.setOutputInterface(output_interface);
  }

  TRANSPORT_ALWAYS_INLINE void connect(bool is_consumer = true) {
    forwarder_interface_.connect(is_consumer);
  }

  ~Portal() { stopEventsLoop(true); }

  TRANSPORT_ALWAYS_INLINE bool interestIsPending(const Name &name) {
    auto it =
        pending_interest_hash_table_.find(name.getHash32() + name.getSuffix());
    if (it != pending_interest_hash_table_.end()) {
      return true;
    }

    return false;
  }

  TRANSPORT_ALWAYS_INLINE void sendInterest(
      Interest::Ptr &&interest,
      OnContentObjectCallback &&on_content_object_callback = UNSET_CALLBACK,
      OnInterestTimeoutCallback &&on_interest_timeout_callback =
          UNSET_CALLBACK) {
    uint32_t hash =
        interest->getName().getHash32() + interest->getName().getSuffix();
    // Send it
    forwarder_interface_.send(*interest);

    auto pending_interest = getPendingInterest();
    pending_interest->setInterest(std::move(interest));
    pending_interest->setOnContentObjectCallback(
        std::move(on_content_object_callback));
    pending_interest->setOnTimeoutCallback(
        std::move(on_interest_timeout_callback));
    pending_interest->startCountdown(
        std::bind(&Portal<ForwarderInt>::timerHandler, this,
                  std::placeholders::_1, hash));
    pending_interest_hash_table_.emplace(
        std::make_pair(hash, std::move(pending_interest)));
  }

  TRANSPORT_ALWAYS_INLINE void timerHandler(const std::error_code &ec,
                                            uint32_t hash) {
    bool is_stopped = io_service_.stopped();
    if (TRANSPORT_EXPECT_FALSE(is_stopped)) {
      return;
    }

    if (TRANSPORT_EXPECT_TRUE(!ec)) {
      PendingInterestHashTable::iterator it =
          pending_interest_hash_table_.find(hash);
      if (it != pending_interest_hash_table_.end()) {
        PendingInterest::Ptr ptr = std::move(it->second);
        pending_interest_hash_table_.erase(it);

        if (ptr->getOnTimeoutCallback() != UNSET_CALLBACK) {
          ptr->on_interest_timeout_callback_(std::move(ptr->getInterest()));
        } else if (consumer_callback_) {
          consumer_callback_->onTimeout(std::move(ptr->getInterest()));
        }
      }
    }
  }

  TRANSPORT_ALWAYS_INLINE void bind(const BindConfig &config) {
    connector_.enableBurst();
    forwarder_interface_.setContentStoreSize(config.csReserved());
    served_namespaces_.push_back(config.prefix());
    registerRoute(served_namespaces_.back());
  }

  TRANSPORT_ALWAYS_INLINE void runEventsLoop() {
    if (io_service_.stopped()) {
      io_service_.reset();  // ensure that run()/poll() will do some work
    }

    this->io_service_.run();
  }

  TRANSPORT_ALWAYS_INLINE void runOneEvent() {
    if (io_service_.stopped()) {
      io_service_.reset();  // ensure that run()/poll() will do some work
    }

    this->io_service_.run_one();
  }

  TRANSPORT_ALWAYS_INLINE void sendContentObject(
      ContentObject &content_object) {
    forwarder_interface_.send(content_object);
  }

  TRANSPORT_ALWAYS_INLINE void stopEventsLoop(bool kill_connection = false) {
    if (kill_connection) {
      forwarder_interface_.closeConnection();
    }

    io_service_.post([this]() {
      clear();
      io_service_.stop();
    });
  }

  TRANSPORT_ALWAYS_INLINE void killConnection() { connector_.close(); }

  TRANSPORT_ALWAYS_INLINE void clear() {
    for (auto &pend_interest : pending_interest_hash_table_) {
      pend_interest.second->cancelTimer();
    }

    pending_interest_hash_table_.clear();
  }

  TRANSPORT_ALWAYS_INLINE asio::io_service &getIoService() {
    return io_service_;
  }

  TRANSPORT_ALWAYS_INLINE std::size_t getPITSize() {
    connector_.state();
    return pending_interest_hash_table_.size();
  }

  TRANSPORT_ALWAYS_INLINE void registerRoute(Prefix &prefix) {
    forwarder_interface_.registerRoute(prefix);
  }

 private:
  TRANSPORT_ALWAYS_INLINE void processIncomingMessages(
      Packet::MemBufPtr &&packet_buffer) {
    bool is_stopped = io_service_.stopped();
    if (TRANSPORT_EXPECT_FALSE(is_stopped)) {
      return;
    }

    if (TRANSPORT_EXPECT_FALSE(
            ForwarderInt::isControlMessage(packet_buffer->data()))) {
      processControlMessage(std::move(packet_buffer));
      return;
    }

    Packet::Format format = Packet::getFormatFromBuffer(packet_buffer->data());

    if (TRANSPORT_EXPECT_TRUE(_is_tcp(format))) {
      if (!Packet::isInterest(packet_buffer->data())) {
        auto content_object = getContentObject();
        content_object->replace(std::move(packet_buffer));
        processContentObject(std::move(content_object));
      } else {
        auto interest = getInterest();
        interest->replace(std::move(packet_buffer));
        processInterest(std::move(interest));
      }
    } else {
      TRANSPORT_LOGE("Received not supported packet. Ignoring it.");
    }
  }

  TRANSPORT_ALWAYS_INLINE void setLocalRoutes() {
    for (auto &name : served_namespaces_) {
      registerRoute(name);
    }
  }

  TRANSPORT_ALWAYS_INLINE void processInterest(Interest::Ptr &&interest) {
    // Interest for a producer
    if (TRANSPORT_EXPECT_TRUE(producer_callback_ != nullptr)) {
      producer_callback_->onInterest(std::move(interest));
    }
  }

  TRANSPORT_ALWAYS_INLINE void processContentObject(
      ContentObject::Ptr &&content_object) {
    uint32_t hash = content_object->getName().getHash32() +
                    content_object->getName().getSuffix();

    auto it = pending_interest_hash_table_.find(hash);
    if (it != pending_interest_hash_table_.end()) {
      PendingInterest::Ptr interest_ptr = std::move(it->second);
      pending_interest_hash_table_.erase(it);
      interest_ptr->cancelTimer();

      if (interest_ptr->getOnDataCallback() != UNSET_CALLBACK) {
        interest_ptr->on_content_object_callback_(
            std::move(interest_ptr->getInterest()),
            std::move(content_object));
      } else if (consumer_callback_) {
        consumer_callback_->onContentObject(
            std::move(interest_ptr->getInterest()),
            std::move(content_object));
      }
    } else {
      TRANSPORT_LOGW("No pending interests for current content (%s)",
                     content_object->getName().toString().c_str());
    }
  }

  TRANSPORT_ALWAYS_INLINE void processControlMessage(
      Packet::MemBufPtr &&packet_buffer) {
    forwarder_interface_.processControlMessageReply(std::move(packet_buffer));
  }

  TRANSPORT_ALWAYS_INLINE void increasePendingInterestPool() {
    // Create pool of pending interests to reuse
    for (uint32_t i = 0; i < pool_size; i++) {
      pending_interests_pool_.add(new PendingInterest(
          Interest::Ptr(nullptr),
          std::make_unique<asio::steady_timer>(io_service_)));
    }
  }

  TRANSPORT_ALWAYS_INLINE void increaseInterestPool() {
    // Create pool of interests to reuse
    for (uint32_t i = 0; i < pool_size; i++) {
      interest_pool_.add(new Interest());
    }
  }

  TRANSPORT_ALWAYS_INLINE void increaseContentObjectPool() {
    // Create pool of content object to reuse
    for (uint32_t i = 0; i < pool_size; i++) {
      content_object_pool_.add(new ContentObject());
    }
  }

  PendingInterest::Ptr getPendingInterest() {
    auto res = pending_interests_pool_.get();
    while (TRANSPORT_EXPECT_FALSE(!res.first)) {
      increasePendingInterestPool();
      res = pending_interests_pool_.get();
    }

    return std::move(res.second);
  }

  TRANSPORT_ALWAYS_INLINE ContentObject::Ptr getContentObject() {
    auto res = content_object_pool_.get();
    while (TRANSPORT_EXPECT_FALSE(!res.first)) {
      increaseContentObjectPool();
      res = content_object_pool_.get();
    }

    return std::move(res.second);
  }

  TRANSPORT_ALWAYS_INLINE Interest::Ptr getInterest() {
    auto res = interest_pool_.get();
    while (TRANSPORT_EXPECT_FALSE(!res.first)) {
      increaseInterestPool();
      res = interest_pool_.get();
    }

    return std::move(res.second);
  }

 private:
  asio::io_service &io_service_;
  asio::io_service internal_io_service_;

  std::string app_name_;

  PendingInterestHashTable pending_interest_hash_table_;
  utils::ObjectPool<PendingInterest> pending_interests_pool_;

  utils::ObjectPool<ContentObject> content_object_pool_;
  utils::ObjectPool<Interest> interest_pool_;

  ConsumerCallback *consumer_callback_;
  ProducerCallback *producer_callback_;

  typename ForwarderInt::ConnectorType connector_;
  ForwarderInt forwarder_interface_;

  std::list<Prefix> served_namespaces_;
};

}  // end namespace core

}  // end namespace transport
