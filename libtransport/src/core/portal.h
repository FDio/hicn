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

#include <core/pending_interest.h>
#include <glog/logging.h>
#include <hicn/transport/config.h>
#include <hicn/transport/core/asio_wrapper.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/core/io_module.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/interfaces/global_conf_interface.h>
#include <hicn/transport/interfaces/portal.h>
#include <hicn/transport/portability/portability.h>
#include <hicn/transport/utils/fixed_block_allocator.h>

#include <future>
#include <memory>
#include <queue>
#include <unordered_map>

namespace libconfig {
class Setting;
}

namespace transport {
namespace core {

namespace portal_details {

static constexpr uint32_t pit_size = 1024;

class HandlerMemory {
#ifdef __vpp__
 public:
  HandlerMemory() {}

  HandlerMemory(const HandlerMemory &) = delete;
  HandlerMemory &operator=(const HandlerMemory &) = delete;

  TRANSPORT_ALWAYS_INLINE void *allocate(std::size_t size) {
    return utils::FixedBlockAllocator<128, 8192>::getInstance().allocateBlock();
  }

  TRANSPORT_ALWAYS_INLINE void deallocate(void *pointer) {
    utils::FixedBlockAllocator<128, 8192>::getInstance().deallocateBlock(
        pointer);
  }
#else
 public:
  HandlerMemory() {}

  HandlerMemory(const HandlerMemory &) = delete;
  HandlerMemory &operator=(const HandlerMemory &) = delete;

  TRANSPORT_ALWAYS_INLINE void *allocate(std::size_t size) {
    return ::operator new(size);
  }

  TRANSPORT_ALWAYS_INLINE void deallocate(void *pointer) {
    ::operator delete(pointer);
  }
#endif
};

// The allocator to be associated with the handler objects. This allocator only
// needs to satisfy the C++11 minimal allocator requirements.
template <typename T>
class HandlerAllocator {
 public:
  using value_type = T;

  explicit HandlerAllocator(HandlerMemory &mem) : memory_(mem) {}

  template <typename U>
  HandlerAllocator(const HandlerAllocator<U> &other) noexcept
      : memory_(other.memory_) {}

  TRANSPORT_ALWAYS_INLINE bool operator==(
      const HandlerAllocator &other) const noexcept {
    return &memory_ == &other.memory_;
  }

  TRANSPORT_ALWAYS_INLINE bool operator!=(
      const HandlerAllocator &other) const noexcept {
    return &memory_ != &other.memory_;
  }

  TRANSPORT_ALWAYS_INLINE T *allocate(std::size_t n) const {
    return static_cast<T *>(memory_.allocate(sizeof(T) * n));
  }

  TRANSPORT_ALWAYS_INLINE void deallocate(T *p, std::size_t /*n*/) const {
    return memory_.deallocate(p);
  }

 private:
  template <typename>
  friend class HandlerAllocator;

  // The underlying memory.
  HandlerMemory &memory_;
};

// Wrapper class template for handler objects to allow handler memory
// allocation to be customised. The allocator_type type and get_allocator()
// member function are used by the asynchronous operations to obtain the
// allocator. Calls to operator() are forwarded to the encapsulated handler.
template <typename Handler>
class CustomAllocatorHandler {
 public:
  using allocator_type = HandlerAllocator<Handler>;

  CustomAllocatorHandler(HandlerMemory &m, Handler h)
      : memory_(m), handler_(h) {}

  allocator_type get_allocator() const noexcept {
    return allocator_type(memory_);
  }

  template <typename... Args>
  void operator()(Args &&... args) {
    handler_(std::forward<Args>(args)...);
  }

 private:
  HandlerMemory &memory_;
  Handler handler_;
};

// Helper function to wrap a handler object to add custom allocation.
template <typename Handler>
inline CustomAllocatorHandler<Handler> makeCustomAllocatorHandler(
    HandlerMemory &m, Handler h) {
  return CustomAllocatorHandler<Handler>(m, h);
}

class Pool {
 public:
  Pool(asio::io_service &io_service) : io_service_(io_service) {
    increasePendingInterestPool();
  }

  TRANSPORT_ALWAYS_INLINE void increasePendingInterestPool() {
    // Create pool of pending interests to reuse
    for (uint32_t i = 0; i < pit_size; i++) {
      pending_interests_pool_.add(new PendingInterest(
          Interest::Ptr(nullptr),
          std::make_unique<asio::steady_timer>(io_service_)));
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

 private:
  utils::ObjectPool<PendingInterest> pending_interests_pool_;
  asio::io_service &io_service_;
};

}  // namespace portal_details

class PortalConfiguration;

using PendingInterestHashTable =
    std::unordered_map<uint32_t, PendingInterest::Ptr>;

using interface::BindConfig;

/**
 * Portal is a opaque class which is used for sending/receiving interest/data
 * packets over multiple kind of connector. The connector itself is defined by
 * the template ForwarderInt, which is resolved at compile time. It is then not
 * possible to decide at runtime what the connector will be.
 *
 * The tasks performed by portal are the following:
 * - Sending/Receiving Interest packets
 * - Sending/Receiving Data packets
 * - Set timers (one per interest), in order to trigger events if an interest is
 *   not satisfied
 * - Register a producer prefix to the local forwarder
 *
 * The way of working of portal is event-based, which means that data and
 * interests are sent/received in a asynchronous manner, and the notifications
 * are performed through callbacks.
 *
 * The portal class is not thread safe, appropriate locking is required by the
 * users of this class.
 */

class Portal {
 public:
  using ConsumerCallback = interface::Portal::ConsumerCallback;
  using ProducerCallback = interface::Portal::ProducerCallback;

  friend class PortalConfiguration;

  Portal() : Portal(internal_io_service_) {}

  Portal(asio::io_service &io_service)
      : io_module_(nullptr, [](IoModule *module) { IoModule::unload(module); }),
        io_service_(io_service),
        packet_pool_(io_service),
        app_name_("libtransport_application"),
        consumer_callback_(nullptr),
        producer_callback_(nullptr),
        is_consumer_(false) {
    /**
     * This workaroung allows to initialize memory for packet buffers *before*
     * any static variables that may be initialized in the io_modules. In this
     * way static variables in modules will be destroyed before the packet
     * memory.
     */
    PacketManager<>::getInstance();
  }
  /**
   * Set the consumer callback.
   *
   * @param consumer_callback - The pointer to the ConsumerCallback object.
   */
  void setConsumerCallback(ConsumerCallback *consumer_callback) {
    consumer_callback_ = consumer_callback;
  }

  /**
   * Set the producer callback.
   *
   * @param producer_callback - The pointer to the ProducerCallback object.
   */
  void setProducerCallback(ProducerCallback *producer_callback) {
    producer_callback_ = producer_callback;
  }

  /**
   * Specify the output interface to use. This method will be useful in a future
   * scenario where the library will be able to forward packets without
   * connecting to a local forwarder. Now it is not used.
   *
   * @param output_interface - The output interface to use for
   * forwarding/receiving packets.
   */
  TRANSPORT_ALWAYS_INLINE void setOutputInterface(
      const std::string &output_interface) {
    io_module_->setOutputInterface(output_interface);
  }

  /**
   * Connect the transport to the local hicn forwarder.
   *
   * @param is_consumer - Boolean specifying if the application on top of portal
   * is a consumer or a producer.
   */
  TRANSPORT_ALWAYS_INLINE void connect(bool is_consumer = true) {
    if (!io_module_) {
      pending_interest_hash_table_.reserve(portal_details::pit_size);
      io_module_.reset(IoModule::load(io_module_path_.c_str()));

      CHECK(io_module_);

      io_module_->init(std::bind(&Portal::processIncomingMessages, this,
                                 std::placeholders::_1, std::placeholders::_2,
                                 std::placeholders::_3),
                       std::bind(&Portal::setLocalRoutes, this), io_service_,
                       app_name_);
      io_module_->connect(is_consumer);
      is_consumer_ = is_consumer;
    }
  }

  /**
   * Destructor.
   */
  ~Portal() { killConnection(); }

  /**
   * Compute name hash
   */
  TRANSPORT_ALWAYS_INLINE uint32_t getHash(const Name &name) {
    return name.getHash32(false) + name.getSuffix();
  }

  /**
   * Check if there is already a pending interest for a given name.
   *
   * @param name - The interest name.
   */
  TRANSPORT_ALWAYS_INLINE bool interestIsPending(const Name &name) {
    auto it = pending_interest_hash_table_.find(getHash(name));
    if (it != pending_interest_hash_table_.end()) {
      return true;
    }

    return false;
  }

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
  TRANSPORT_ALWAYS_INLINE void sendInterest(
      Interest::Ptr &&interest,
      OnContentObjectCallback &&on_content_object_callback = UNSET_CALLBACK,
      OnInterestTimeoutCallback &&on_interest_timeout_callback =
          UNSET_CALLBACK) {
    // Send it
    interest->encodeSuffixes();
    io_module_->send(*interest);

    uint32_t initial_hash = interest->getName().getHash32(false);
    auto hash = initial_hash + interest->getName().getSuffix();
    uint32_t seq = interest->getName().getSuffix();
    uint32_t *suffix = interest->firstSuffix();
    auto n_suffixes = interest->numberOfSuffixes();
    uint32_t counter = 0;
    // Set timers
    do {
      auto pending_interest = packet_pool_.getPendingInterest();
      pending_interest->setInterest(interest);
      pending_interest->setOnContentObjectCallback(
          std::move(on_content_object_callback));
      pending_interest->setOnTimeoutCallback(
          std::move(on_interest_timeout_callback));

      pending_interest->startCountdown(
          portal_details::makeCustomAllocatorHandler(
              async_callback_memory_,
              std::bind(&Portal::timerHandler, this, std::placeholders::_1,
                        hash, seq)));

      auto it = pending_interest_hash_table_.find(hash);
      if (it != pending_interest_hash_table_.end()) {
        it->second->cancelTimer();

        // Get reference to interest packet in order to have it destroyed.
        auto _int = it->second->getInterest();
        it->second = std::move(pending_interest);
      } else {
        pending_interest_hash_table_[hash] = std::move(pending_interest);
      }

      if (suffix) {
        hash = initial_hash + *suffix;
        seq = *suffix;
        suffix++;
      }

    } while (counter++ < n_suffixes);
  }

  /**
   * Handler fot the timer set when the interest is sent.
   *
   * @param ec - Error code which says whether the timer expired or has been
   * canceled upon data packet reception.
   *
   * @param hash - The index of the interest in the pending interest hash table.
   */
  TRANSPORT_ALWAYS_INLINE void timerHandler(const std::error_code &ec,
                                            uint32_t hash, uint32_t seq) {
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
        auto _int = ptr->getInterest();
        Name &name = const_cast<Name &>(_int->getName());
        name.setSuffix(seq);

        if (ptr->getOnTimeoutCallback() != UNSET_CALLBACK) {
          ptr->on_interest_timeout_callback_(_int, name);
        } else if (consumer_callback_) {
          consumer_callback_->onTimeout(_int, name);
        }
      }
    }
  }

  /**
   * Register a producer name to the local forwarder and optionally set the
   * content store size in a per-face manner.
   *
   * @param config - The configuration for the local forwarder binding.
   */
  TRANSPORT_ALWAYS_INLINE void bind(const BindConfig &config) {
    assert(io_module_);
    io_module_->setContentStoreSize(config.csReserved());
    served_namespaces_.push_back(config.prefix());
    setLocalRoutes();
  }

  /**
   * Start the event loop. This function blocks here and calls the callback set
   * by the application upon interest/data received or timeout.
   */
  TRANSPORT_ALWAYS_INLINE void runEventsLoop() {
    if (io_service_.stopped()) {
      io_service_.reset();  // ensure that run()/poll() will do some work
    }

    io_service_.run();
  }

  /**
   * Run one event and return.
   */
  TRANSPORT_ALWAYS_INLINE void runOneEvent() {
    if (io_service_.stopped()) {
      io_service_.reset();  // ensure that run()/poll() will do some work
    }

    io_service_.run_one();
  }

  /**
   * Send a data packet to the local forwarder. As opposite to sendInterest, the
   * ownership of the content object is not transferred to the portal.
   *
   * @param content_object - The data packet.
   */
  TRANSPORT_ALWAYS_INLINE void sendContentObject(
      ContentObject &content_object) {
    io_module_->send(content_object);
  }

  /**
   * Stop the event loop, canceling all the pending events in the event queue.
   *
   * Beware that stopping the event loop DOES NOT disconnect the transport from
   * the local forwarder, the connector underneath will stay connected.
   */
  TRANSPORT_ALWAYS_INLINE void stopEventsLoop() {
    if (!io_service_.stopped()) {
      io_service_.dispatch([this]() {
        clear();
        io_service_.stop();
      });
    }
  }

  /**
   * Disconnect the transport from the local forwarder.
   */
  TRANSPORT_ALWAYS_INLINE void killConnection() {
    io_module_->closeConnection();
  }

  /**
   * Clear the pending interest hash table.
   */
  TRANSPORT_ALWAYS_INLINE void clear() {
    if (!io_service_.stopped()) {
      io_service_.dispatch(std::bind(&Portal::doClear, this));
    } else {
      doClear();
    }
  }

  /**
   * Remove one pending interest.
   */
  TRANSPORT_ALWAYS_INLINE void clearOne(const Name &name) {
    if (!io_service_.stopped()) {
      io_service_.dispatch(std::bind(&Portal::doClearOne, this, name));
    } else {
      doClearOne(name);
    }
  }

  /**
   * Get a reference to the io_service object.
   */
  TRANSPORT_ALWAYS_INLINE asio::io_service &getIoService() {
    return io_service_;
  }

  /**
   * Register a route to the local forwarder.
   */
  TRANSPORT_ALWAYS_INLINE void registerRoute(Prefix &prefix) {
    served_namespaces_.push_back(prefix);
    if (io_module_->isConnected()) {
      io_module_->registerRoute(prefix);
    }
  }

  /**
   * Check if the transport is connected to a forwarder or not
   */
  TRANSPORT_ALWAYS_INLINE bool isConnectedToFwd() {
    std::string mod = io_module_path_.substr(0, io_module_path_.find("."));
    if (mod == "forwarder_module") return false;
    return true;
  }

 private:
  /**
   * Clear the pending interest hash table.
   */
  TRANSPORT_ALWAYS_INLINE void doClear() {
    for (auto &pend_interest : pending_interest_hash_table_) {
      pend_interest.second->cancelTimer();

      // Get interest packet from pending interest and do nothing with it. It
      // will get destroyed as it goes out of scope.
      auto _int = pend_interest.second->getInterest();
    }

    pending_interest_hash_table_.clear();
  }

  /**
   * Remove one pending interest.
   */
  TRANSPORT_ALWAYS_INLINE void doClearOne(const Name &name) {
    auto it = pending_interest_hash_table_.find(getHash(name));

    if (it != pending_interest_hash_table_.end()) {
      it->second->cancelTimer();

      // Get interest packet from pending interest and do nothing with it. It
      // will get destroyed as it goes out of scope.
      auto _int = it->second->getInterest();

      pending_interest_hash_table_.erase(it);
    }
  }

  /**
   * Callback called by the underlying connector upon reception of a packet from
   * the local forwarder.
   *
   * @param packet_buffer - The bytes of the packet.
   */
  TRANSPORT_ALWAYS_INLINE void processIncomingMessages(
      Connector *c, utils::MemBuf &buffer, const std::error_code &ec) {
    bool is_stopped = io_service_.stopped();
    if (TRANSPORT_EXPECT_FALSE(is_stopped)) {
      return;
    }

    if (TRANSPORT_EXPECT_FALSE(io_module_->isControlMessage(buffer.data()))) {
      processControlMessage(buffer);
      return;
    }

    // The buffer is a base class for an interest or a content object
    Packet &packet_buffer = static_cast<Packet &>(buffer);

    auto format = packet_buffer.getFormat();
    if (TRANSPORT_EXPECT_TRUE(_is_tcp(format))) {
      if (is_consumer_) {
        processContentObject(static_cast<ContentObject &>(packet_buffer));
      } else {
        processInterest(static_cast<Interest &>(packet_buffer));
      }
    } else {
      LOG(ERROR) << "Received not supported packet. Ignoring it.";
    }
  }

  /**
   * Callback called by the transport upon connection to the local forwarder.
   * It register the prefixes in the served_namespaces_ list to the local
   * forwarder.
   */
  TRANSPORT_ALWAYS_INLINE void setLocalRoutes() {
    for (auto &prefix : served_namespaces_) {
      if (io_module_->isConnected()) {
        io_module_->registerRoute(prefix);
      }
    }
  }

  TRANSPORT_ALWAYS_INLINE void processInterest(Interest &interest) {
    // Interest for a producer
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "processInterest " << interest.getName();
    if (TRANSPORT_EXPECT_TRUE(producer_callback_ != nullptr)) {
      producer_callback_->onInterest(interest);
    }
  }

  /**
   * Process a content object:
   * - Check if the data packet was effectively requested by portal
   * - Delete its timer
   * - Pass packet to application
   *
   * @param content_object - The data packet
   */
  TRANSPORT_ALWAYS_INLINE void processContentObject(
      ContentObject &content_object) {
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "processContentObject " << content_object.getName();
    uint32_t hash = getHash(content_object.getName());

    auto it = pending_interest_hash_table_.find(hash);
    if (it != pending_interest_hash_table_.end()) {
      DLOG_IF(INFO, VLOG_IS_ON(3)) << "Found pending interest.";

      PendingInterest::Ptr interest_ptr = std::move(it->second);
      pending_interest_hash_table_.erase(it);
      interest_ptr->cancelTimer();
      auto _int = interest_ptr->getInterest();

      if (interest_ptr->getOnDataCallback() != UNSET_CALLBACK) {
        interest_ptr->on_content_object_callback_(*_int, content_object);
      } else if (consumer_callback_) {
        consumer_callback_->onContentObject(*_int, content_object);
      }
    } else {
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "No interest pending for received content object.";
    }
  }

  /**
   * Process a control message. Control messages are different depending on the
   * connector, then the forwarder_interface will do the job of understanding
   * them.
   */
  TRANSPORT_ALWAYS_INLINE void processControlMessage(
      utils::MemBuf &packet_buffer) {
    io_module_->processControlMessageReply(packet_buffer);
  }

 private:
  portal_details::HandlerMemory async_callback_memory_;
  std::unique_ptr<IoModule, void (*)(IoModule *)> io_module_;

  asio::io_service &io_service_;
  asio::io_service internal_io_service_;
  portal_details::Pool packet_pool_;

  std::string app_name_;

  PendingInterestHashTable pending_interest_hash_table_;
  std::list<Prefix> served_namespaces_;

  ConsumerCallback *consumer_callback_;
  ProducerCallback *producer_callback_;

  bool is_consumer_;

 private:
  static std::string defaultIoModule();
  static void parseIoModuleConfiguration(const libconfig::Setting &io_config,
                                         std::error_code &ec);
  static void getModuleConfiguration(
      interface::global_config::ConfigurationObject &conf, std::error_code &ec);
  static void setModuleConfiguration(
      const interface::global_config::ConfigurationObject &conf,
      std::error_code &ec);
  static interface::global_config::IoModuleConfiguration conf_;
  static std::string io_module_path_;
};

}  // namespace core

}  // end namespace transport
