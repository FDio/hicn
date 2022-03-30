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

#include <core/global_workers.h>
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
#include <hicn/transport/utils/event_thread.h>
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

  void *allocate(std::size_t size) {
    return utils::FixedBlockAllocator<128, 8192>::getInstance().allocateBlock();
  }

  void deallocate(void *pointer) {
    utils::FixedBlockAllocator<128, 8192>::getInstance().deallocateBlock(
        pointer);
  }
#else
 public:
  HandlerMemory() {}

  HandlerMemory(const HandlerMemory &) = delete;
  HandlerMemory &operator=(const HandlerMemory &) = delete;

  void *allocate(std::size_t size) { return ::operator new(size); }

  void deallocate(void *pointer) { ::operator delete(pointer); }
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

  bool operator==(const HandlerAllocator &other) const noexcept {
    return &memory_ == &other.memory_;
  }

  bool operator!=(const HandlerAllocator &other) const noexcept {
    return &memory_ != &other.memory_;
  }

  T *allocate(std::size_t n) const {
    return static_cast<T *>(memory_.allocate(sizeof(T) * n));
  }

  void deallocate(T *p, std::size_t /*n*/) const {
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
  void operator()(Args &&...args) {
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

}  // namespace portal_details

class PortalConfiguration;

using PendingInterestHashTable = std::unordered_map<uint32_t, PendingInterest>;

/**
 * Portal is a opaque class which is used for sending/receiving interest/data
 * packets over multiple kind of io_modules. The io_module itself is an external
 * module loaded at runtime.
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

class Portal : public ::utils::NonCopyable,
               public std::enable_shared_from_this<Portal> {
 private:
  Portal() : Portal(GlobalWorkers::getInstance().getWorker()) {}

  Portal(::utils::EventThread &worker)
      : io_module_(nullptr, [](IoModule *module) { IoModule::unload(module); }),
        worker_(worker),
        app_name_("libtransport_application"),
        transport_callback_(nullptr),
        is_consumer_(false) {
    /**
     * This workaroung allows to initialize memory for packet buffers *before*
     * any static variables that may be initialized in the io_modules. In this
     * way static variables in modules will be destroyed before the packet
     * memory.
     */
    PacketManager<>::getInstance();
  }

 public:
  using TransportCallback = interface::Portal::TransportCallback;
  friend class PortalConfiguration;

  static std::shared_ptr<Portal> createShared() {
    return std::shared_ptr<Portal>(new Portal());
  }

  static std::shared_ptr<Portal> createShared(::utils::EventThread &worker) {
    return std::shared_ptr<Portal>(new Portal(worker));
  }

  bool isConnected() const { return io_module_.get() != nullptr; }

  /**
   * Set the transport callback. Must be called from the same worker thread.
   *
   * @param consumer_callback - The pointer to the TransportCallback object.
   */
  void registerTransportCallback(TransportCallback *transport_callback) {
    DCHECK(std::this_thread::get_id() == worker_.getThreadId());
    transport_callback_ = transport_callback;
  }

  /**
   * Unset the consumer callback. Must be called from the same worker thread.
   */
  void unregisterTransportCallback() {
    DCHECK(std::this_thread::get_id() == worker_.getThreadId());
    transport_callback_ = nullptr;
  }

  /**
   * Specify the output interface to use. This method will be useful in a
   * future scenario where the library will be able to forward packets without
   * connecting to a local forwarder. Now it is not used.
   *
   * @param output_interface - The output interface to use for
   * forwarding/receiving packets.
   */
  void setOutputInterface(const std::string &output_interface) {
    if (io_module_) {
      io_module_->setOutputInterface(output_interface);
    }
  }

  /**
   * Connect the transport to the local hicn forwarder.
   *
   * @param is_consumer - Boolean specifying if the application on top of
   * portal is a consumer or a producer.
   */
  void connect(bool is_consumer = true) {
    if (isConnected()) {
      return;
    }

    worker_.addAndWaitForExecution([this, is_consumer]() {
      if (!io_module_) {
        pending_interest_hash_table_.reserve(portal_details::pit_size);
        io_module_.reset(IoModule::load(io_module_path_.c_str()));

        CHECK(io_module_);

        std::weak_ptr<Portal> self(shared_from_this());

        io_module_->init(
            [self](Connector *c, const std::vector<utils::MemBuf::Ptr> &buffers,
                   const std::error_code &ec) {
              if (auto ptr = self.lock()) {
                ptr->processIncomingMessages(c, buffers, ec);
              }
            },
            [self](Connector *c, const std::error_code &ec) {
              if (!ec) {
                return;
              }
              auto ptr = self.lock();
              if (ptr && ptr->transport_callback_) {
                ptr->transport_callback_->onError(ec);
              }
            },
            [self](Connector *c, const std::error_code &ec) {
              auto ptr = self.lock();
              if (ptr) {
                if (ec && ptr->transport_callback_) {
                  ptr->transport_callback_->onError(ec);
                  return;
                }
                ptr->setLocalRoutes();
              }
            },
            worker_.getIoService(), app_name_);

        io_module_->connect(is_consumer);
        is_consumer_ = is_consumer;
      }
    });
  }

  /**
   * Destructor.
   */
  ~Portal() { killConnection(); }

  /**
   * Check if there is already a pending interest for a given name.
   *
   * @param name - The interest name.
   */
  bool interestIsPending(const Name &name) {
    DCHECK(std::this_thread::get_id() == worker_.getThreadId());

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
   * @param on_content_object_callback - If the caller wishes to use a
   * different callback to be called for this interest, it can set this
   * parameter. Otherwise ConsumerCallback::onContentObject will be used.
   *
   * @param on_interest_timeout_callback - If the caller wishes to use a
   * different callback to be called for this interest, it can set this
   * parameter. Otherwise ConsumerCallback::onTimeout will be used.
   */
  void sendInterest(
      Interest::Ptr &&interest,
      OnContentObjectCallback &&on_content_object_callback = UNSET_CALLBACK,
      OnInterestTimeoutCallback &&on_interest_timeout_callback =
          UNSET_CALLBACK) {
    DCHECK(std::this_thread::get_id() == worker_.getThreadId());

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
      if (suffix) {
        hash = initial_hash + *suffix;
        seq = *suffix;
        suffix++;
      }

      auto it = pending_interest_hash_table_.find(hash);
      PendingInterest *pending_interest = nullptr;
      if (it != pending_interest_hash_table_.end()) {
        it->second.cancelTimer();
        pending_interest = &it->second;
        pending_interest->setInterest(interest);
      } else {
        auto pend_int = pending_interest_hash_table_.try_emplace(
            hash, worker_.getIoService(), interest);
        pending_interest = &pend_int.first->second;
      }

      pending_interest->setOnContentObjectCallback(
          std::move(on_content_object_callback));
      pending_interest->setOnTimeoutCallback(
          std::move(on_interest_timeout_callback));

      auto self = weak_from_this();
      pending_interest->startCountdown(
          portal_details::makeCustomAllocatorHandler(
              async_callback_memory_,
              [self, hash, seq](const std::error_code &ec) {
                if (TRANSPORT_EXPECT_FALSE(ec.operator bool())) {
                  return;
                }

                if (auto ptr = self.lock()) {
                  ptr->timerHandler(hash, seq);
                }
              }));

    } while (counter++ < n_suffixes);
  }

  /**
   * Handler fot the timer set when the interest is sent.
   *
   * @param ec - Error code which says whether the timer expired or has been
   * canceled upon data packet reception.
   *
   * @param hash - The index of the interest in the pending interest hash
   * table.
   */
  void timerHandler(uint32_t hash, uint32_t seq) {
    PendingInterestHashTable::iterator it =
        pending_interest_hash_table_.find(hash);
    if (it != pending_interest_hash_table_.end()) {
      PendingInterest &pend_interest = it->second;
      auto _int = pend_interest.getInterest();
      auto callback = pend_interest.getOnTimeoutCallback();
      pending_interest_hash_table_.erase(it);
      Name &name = const_cast<Name &>(_int->getName());
      name.setSuffix(seq);

      if (callback != UNSET_CALLBACK) {
        callback(_int, name);
      } else if (transport_callback_) {
        transport_callback_->onTimeout(_int, name);
      }
    }
  }

  /**
   * Send a data packet to the local forwarder.
   *
   * @param content_object - The data packet.
   */
  void sendContentObject(ContentObject &content_object) {
    DCHECK(io_module_);
    DCHECK(std::this_thread::get_id() == worker_.getThreadId());

    io_module_->send(content_object);
  }

  /**
   * Disconnect the transport from the local forwarder.
   */
  void killConnection() {
    if (TRANSPORT_EXPECT_TRUE(io_module_ != nullptr)) {
      io_module_->closeConnection();
    }
  }

  /**
   * Clear the pending interest hash table.
   */
  void clear() {
    worker_.tryRunHandlerNow([self{shared_from_this()}]() { self->doClear(); });
  }

  /**
   * Get a reference to the io_service object.
   */
  utils::EventThread &getThread() { return worker_; }

  /**
   * Register a route to the local forwarder.
   */
  void registerRoute(const Prefix &prefix) {
    std::weak_ptr<Portal> self = shared_from_this();
    worker_.tryRunHandlerNow([self, prefix]() {
      if (auto ptr = self.lock()) {
        auto ret = ptr->served_namespaces_.insert(prefix);
        if (ret.second && ptr->io_module_ && ptr->io_module_->isConnected()) {
          ptr->io_module_->registerRoute(prefix);
        }
      }
    });
  }

  /**
   * Send a MAP-Me update to traverse NATs.
   */
  TRANSPORT_ALWAYS_INLINE void sendMapme() {
    if (io_module_->isConnected()) {
      io_module_->sendMapme();
    }
  }

  /**
   * set forwarding strategy
   */
  TRANSPORT_ALWAYS_INLINE void setForwardingStrategy(Prefix &prefix,
                                                     std::string &strategy) {
    if (io_module_->isConnected()) {
      io_module_->setForwardingStrategy(prefix, strategy);
    }
  }

  /**
   * Check if the transport is connected to a forwarder or not
   */
  bool isConnectedToFwd() {
    std::string mod = io_module_path_.substr(0, io_module_path_.find("."));
    if (mod == "forwarder_module") return false;
    return true;
  }

  auto &getServedNamespaces() { return served_namespaces_; }

 private:
  /**
   * Compute name hash
   */
  uint32_t getHash(const Name &name) {
    return name.getHash32(false) + name.getSuffix();
  }

  /**
   * Clear the pending interest hash table.
   */
  void doClear() {
    for (auto &pend_interest : pending_interest_hash_table_) {
      pend_interest.second.cancelTimer();
    }

    pending_interest_hash_table_.clear();
  }

  /**
   * Callback called by the underlying connector upon reception of a packet
   * from the local forwarder.
   *
   * @param packet_buffer - The bytes of the packet.
   */
  void processIncomingMessages(Connector *c,
                               const std::vector<utils::MemBuf::Ptr> &buffers,
                               const std::error_code &ec) {
    if (!transport_callback_) {
      return;
    }

    if (TRANSPORT_EXPECT_FALSE(ec.operator bool())) {
      // Error receiving from underlying infra.
      if (transport_callback_) {
        transport_callback_->onError(ec);
      }

      return;
    }

    for (auto &buffer_ptr : buffers) {
      auto &buffer = *buffer_ptr;

      if (TRANSPORT_EXPECT_FALSE(io_module_->isControlMessage(buffer))) {
        processControlMessage(buffer);
        return;
      }

      auto format = Packet::getFormatFromBuffer(buffer.data(), buffer.length());
      if (TRANSPORT_EXPECT_TRUE(_is_cmpr(format) || _is_tcp(format))) {
        // The buffer is a base class for an interest or a content object
        Packet &packet_buffer = static_cast<Packet &>(buffer);
        if (is_consumer_ && !packet_buffer.isInterest()) {
          processContentObject(static_cast<ContentObject &>(packet_buffer));
        } else if (!is_consumer_ && packet_buffer.isInterest()) {
          processInterest(static_cast<Interest &>(packet_buffer));
        } else {
          auto packet_type =
              packet_buffer.isInterest() ? "Interest" : "ContentObject";
          auto socket_type = is_consumer_ ? "consumer " : "producer ";
          LOG(ERROR) << "Received a " << packet_type << " packet with name "
                     << packet_buffer.getName() << " in a " << socket_type
                     << " transport. Ignoring it.";
        }
      } else {
        LOG(ERROR) << "Received not supported packet. Ignoring it.";
      }
    }
  }

  /**
   * Callback called by the transport upon connection to the local forwarder.
   * It register the prefixes in the served_namespaces_ list to the local
   * forwarder.
   */
  void setLocalRoutes() {
    DCHECK(io_module_);
    DCHECK(io_module_->isConnected());
    DCHECK(std::this_thread::get_id() == worker_.getThreadId());

    for (auto &prefix : served_namespaces_) {
      io_module_->registerRoute(prefix);
    }
  }

  void processInterest(Interest &interest) {
    // Interest for a producer
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "processInterest " << interest.getName();
    if (TRANSPORT_EXPECT_TRUE(transport_callback_ != nullptr)) {
      transport_callback_->onInterest(interest);
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
  void processContentObject(ContentObject &content_object) {
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "processContentObject " << content_object.getName();
    uint32_t hash = getHash(content_object.getName());

    auto it = pending_interest_hash_table_.find(hash);
    if (it != pending_interest_hash_table_.end()) {
      DLOG_IF(INFO, VLOG_IS_ON(3)) << "Found pending interest.";

      PendingInterest &pend_interest = it->second;
      pend_interest.cancelTimer();
      auto _int = pend_interest.getInterest();
      auto callback = pend_interest.getOnDataCallback();
      pending_interest_hash_table_.erase(it);

      if (callback != UNSET_CALLBACK) {
        callback(*_int, content_object);
      } else if (transport_callback_) {
        transport_callback_->onContentObject(*_int, content_object);
      }
    } else {
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "No interest pending for received content object.";
    }
  }

  /**
   * Process a control message. Control messages are different depending on
   * the connector, then the forwarder_interface will do the job of
   * understanding them.
   */
  void processControlMessage(utils::MemBuf &packet_buffer) {
    io_module_->processControlMessageReply(packet_buffer);
  }

 private:
  portal_details::HandlerMemory async_callback_memory_;
  std::unique_ptr<IoModule, void (*)(IoModule *)> io_module_;

  ::utils::EventThread &worker_;

  std::string app_name_;

  PendingInterestHashTable pending_interest_hash_table_;
  std::set<Prefix> served_namespaces_;

  TransportCallback *transport_callback_;

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
