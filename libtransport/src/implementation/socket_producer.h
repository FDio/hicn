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

#include <hicn/transport/auth/signer.h>
#include <hicn/transport/utils/event_thread.h>
#include <implementation/socket.h>
#include <protocols/prod_protocol_bytestream.h>
#include <protocols/prod_protocol_rtc.h>
#include <utils/content_store.h>
#include <utils/suffix_strategy.h>

#include <atomic>
#include <cmath>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

#define REGISTRATION_NOT_ATTEMPTED 0
#define REGISTRATION_SUCCESS 1
#define REGISTRATION_FAILURE 2
#define REGISTRATION_IN_PROGRESS 3

namespace transport {
namespace implementation {

using namespace core;
using namespace interface;

class ProducerSocket : public Socket {
 private:
  ProducerSocket(interface::ProducerSocket *producer_socket, int protocol,
                 std::shared_ptr<core::Portal> &&portal)
      : Socket(std::move(portal)),
        producer_interface_(producer_socket),
        data_packet_size_(default_values::content_object_packet_size),
        content_object_expiry_time_(default_values::content_object_expiry_time),
        async_thread_(),
        making_manifest_(false),
        hash_algorithm_(auth::CryptoHashType::SHA_256),
        suffix_strategy_(core::NextSegmentCalculationStrategy::INCREMENTAL),
        on_interest_input_(VOID_HANDLER),
        on_interest_dropped_input_buffer_(VOID_HANDLER),
        on_interest_inserted_input_buffer_(VOID_HANDLER),
        on_interest_satisfied_output_buffer_(VOID_HANDLER),
        on_interest_process_(VOID_HANDLER),
        on_new_segment_(VOID_HANDLER),
        on_content_object_to_sign_(VOID_HANDLER),
        on_content_object_in_output_buffer_(VOID_HANDLER),
        on_content_object_output_(VOID_HANDLER),
        on_content_object_evicted_from_output_buffer_(VOID_HANDLER),
        on_content_produced_(VOID_HANDLER) {
    switch (protocol) {
      case ProductionProtocolAlgorithms::RTC_PROD:
        production_protocol_ =
            std::make_unique<protocol::RTCProductionProtocol>(this);
        break;
      case ProductionProtocolAlgorithms::BYTE_STREAM:
      default:
        production_protocol_ =
            std::make_unique<protocol::ByteStreamProductionProtocol>(this);
        break;
    }
  }

 public:
  ProducerSocket(interface::ProducerSocket *producer, int protocol)
      : ProducerSocket(producer, protocol, std::make_shared<core::Portal>()) {}

  ProducerSocket(interface::ProducerSocket *producer, int protocol,
                 asio::io_service &io_service)
      : ProducerSocket(producer, protocol,
                       std::make_shared<core::Portal>(io_service)) {
    is_async_ = true;
  }

  virtual ~ProducerSocket() {}

  interface::ProducerSocket *getInterface() {
    return producer_interface_;
  }

  void setInterface(interface::ProducerSocket *producer_socket) {
    producer_interface_ = producer_socket;
  }

  void connect() override {
    portal_->connect(false);
    production_protocol_->start();
  }

  bool isRunning() override { return !production_protocol_->isRunning(); };

  virtual void asyncProduce(Name content_name,
                            std::unique_ptr<utils::MemBuf> &&buffer,
                            bool is_last, uint32_t offset,
                            uint32_t **last_segment = nullptr) {
    if (!async_thread_.stopped()) {
      auto a = buffer.release();
      async_thread_.add([this, content_name, a, is_last, offset,
                         last_segment]() {
        auto buf = std::unique_ptr<utils::MemBuf>(a);
        if (last_segment != NULL) {
          **last_segment = offset + produceStream(content_name, std::move(buf),
                                                  is_last, offset);
        } else {
          produceStream(content_name, std::move(buf), is_last, offset);
        }
      });
    }
  }

  virtual uint32_t produceStream(const Name &content_name,
                                 std::unique_ptr<utils::MemBuf> &&buffer,
                                 bool is_last = true,
                                 uint32_t start_offset = 0) {
    return production_protocol_->produceStream(content_name, std::move(buffer),
                                               is_last, start_offset);
  }

  virtual uint32_t produceStream(const Name &content_name,
                                 const uint8_t *buffer, size_t buffer_size,
                                 bool is_last = true,
                                 uint32_t start_offset = 0) {
    return production_protocol_->produceStream(
        content_name, buffer, buffer_size, is_last, start_offset);
  }

  virtual uint32_t produceDatagram(const Name &content_name,
                                   std::unique_ptr<utils::MemBuf> &&buffer) {
    return production_protocol_->produceDatagram(content_name,
                                                 std::move(buffer));
  }

  virtual uint32_t produceDatagram(const Name &content_name,
                                   const uint8_t *buffer, size_t buffer_size) {
    return production_protocol_->produceDatagram(content_name, buffer,
                                                 buffer_size);
  }

  void produce(ContentObject &content_object) {
    production_protocol_->produce(content_object);
  }

  void registerPrefix(const Prefix &producer_namespace) {
    production_protocol_->registerNamespaceWithNetwork(producer_namespace);
  }

  void stop() { production_protocol_->stop(); }

  virtual int setSocketOption(int socket_option_key,
                              uint32_t socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::DATA_PACKET_SIZE:
        if (socket_option_value <= default_values::max_content_object_size &&
            socket_option_value > 0) {
          data_packet_size_ = socket_option_value;
        }
        break;

      case GeneralTransportOptions::OUTPUT_BUFFER_SIZE:
        production_protocol_->setOutputBufferSize(socket_option_value);
        break;

      case GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME:
        content_object_expiry_time_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  virtual int setSocketOption(int socket_option_key,
                              std::nullptr_t socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in case
    // setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ProducerContentObjectCallback socket_option_value) -> int {
          switch (socket_option_key) {
            case ProducerCallbacksOptions::INTEREST_INPUT:
              if (socket_option_value == VOID_HANDLER) {
                on_interest_input_ = VOID_HANDLER;
                break;
              }

            case ProducerCallbacksOptions::INTEREST_DROP:
              if (socket_option_value == VOID_HANDLER) {
                on_interest_dropped_input_buffer_ = VOID_HANDLER;
                break;
              }

            case ProducerCallbacksOptions::INTEREST_PASS:
              if (socket_option_value == VOID_HANDLER) {
                on_interest_inserted_input_buffer_ = VOID_HANDLER;
                break;
              }

            case ProducerCallbacksOptions::CACHE_HIT:
              if (socket_option_value == VOID_HANDLER) {
                on_interest_satisfied_output_buffer_ = VOID_HANDLER;
                break;
              }

            case ProducerCallbacksOptions::CACHE_MISS:
              if (socket_option_value == VOID_HANDLER) {
                on_interest_process_ = VOID_HANDLER;
                break;
              }

            case ProducerCallbacksOptions::NEW_CONTENT_OBJECT:
              if (socket_option_value == VOID_HANDLER) {
                on_new_segment_ = VOID_HANDLER;
                break;
              }

            case ProducerCallbacksOptions::CONTENT_OBJECT_READY:
              if (socket_option_value == VOID_HANDLER) {
                on_content_object_in_output_buffer_ = VOID_HANDLER;
                break;
              }

            case ProducerCallbacksOptions::CONTENT_OBJECT_OUTPUT:
              if (socket_option_value == VOID_HANDLER) {
                on_content_object_output_ = VOID_HANDLER;
                break;
              }

            case ProducerCallbacksOptions::CONTENT_OBJECT_TO_SIGN:
              if (socket_option_value == VOID_HANDLER) {
                on_content_object_to_sign_ = VOID_HANDLER;
                break;
              }

            default:
              return SOCKET_OPTION_NOT_SET;
          }

          return SOCKET_OPTION_SET;
        });
  }

  virtual int setSocketOption(int socket_option_key, bool socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::MAKE_MANIFEST:
        making_manifest_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  virtual int setSocketOption(int socket_option_key,
                              Name *socket_option_value) {
    return SOCKET_OPTION_NOT_SET;
  }

  virtual int setSocketOption(
      int socket_option_key,
      interface::ProducerContentObjectCallback socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in case
    // setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ProducerContentObjectCallback socket_option_value) -> int {
          switch (socket_option_key) {
            case ProducerCallbacksOptions::NEW_CONTENT_OBJECT:
              on_new_segment_ = socket_option_value;
              break;

            case ProducerCallbacksOptions::CONTENT_OBJECT_READY:
              on_content_object_in_output_buffer_ = socket_option_value;
              break;

            case ProducerCallbacksOptions::CONTENT_OBJECT_OUTPUT:
              on_content_object_output_ = socket_option_value;
              break;

            case ProducerCallbacksOptions::CONTENT_OBJECT_TO_SIGN:
              on_content_object_to_sign_ = socket_option_value;
              break;

            default:
              return SOCKET_OPTION_NOT_SET;
          }

          return SOCKET_OPTION_SET;
        });
  }

  virtual int setSocketOption(
      int socket_option_key,
      interface::ProducerInterestCallback socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in case
    // setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ProducerInterestCallback socket_option_value) -> int {
          switch (socket_option_key) {
            case ProducerCallbacksOptions::INTEREST_INPUT:
              on_interest_input_ = socket_option_value;
              break;

            case ProducerCallbacksOptions::INTEREST_DROP:
              on_interest_dropped_input_buffer_ = socket_option_value;
              break;

            case ProducerCallbacksOptions::INTEREST_PASS:
              on_interest_inserted_input_buffer_ = socket_option_value;
              break;

            case ProducerCallbacksOptions::CACHE_HIT:
              on_interest_satisfied_output_buffer_ = socket_option_value;
              break;

            case ProducerCallbacksOptions::CACHE_MISS:
              on_interest_process_ = socket_option_value;
              break;

            default:
              return SOCKET_OPTION_NOT_SET;
          }

          return SOCKET_OPTION_SET;
        });
  }

  virtual int setSocketOption(
      int socket_option_key,
      interface::ProducerContentCallback socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in case
    // setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ProducerContentCallback socket_option_value) -> int {
          switch (socket_option_key) {
            case ProducerCallbacksOptions::CONTENT_PRODUCED:
              on_content_produced_ = socket_option_value;
              break;

            default:
              return SOCKET_OPTION_NOT_SET;
          }

          return SOCKET_OPTION_SET;
        });
  }

  virtual int setSocketOption(int socket_option_key,
                              auth::CryptoHashType socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::HASH_ALGORITHM:
        hash_algorithm_ = socket_option_value;
        break;
      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  virtual int setSocketOption(
      int socket_option_key,
      core::NextSegmentCalculationStrategy socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::SUFFIX_STRATEGY:
        suffix_strategy_ = socket_option_value;
        break;
      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  virtual int setSocketOption(
      int socket_option_key,
      const std::shared_ptr<auth::Signer> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::SIGNER: {
        utils::SpinLock::Acquire locked(signer_lock_);
        signer_.reset();
        signer_ = socket_option_value;
      } break;
      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  virtual int getSocketOption(int socket_option_key,
                              uint32_t &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::OUTPUT_BUFFER_SIZE:
        socket_option_value = (uint32_t)production_protocol_->getOutputBufferSize();
        break;

      case GeneralTransportOptions::DATA_PACKET_SIZE:
        socket_option_value = (uint32_t)data_packet_size_;
        break;

      case GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME:
        socket_option_value = content_object_expiry_time_;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_GET;
  }

  virtual int getSocketOption(int socket_option_key,
                              bool &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::MAKE_MANIFEST:
        socket_option_value = making_manifest_;
        break;

      case GeneralTransportOptions::ASYNC_MODE:
        socket_option_value = is_async_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  virtual int getSocketOption(
      int socket_option_key,
      interface::ProducerContentObjectCallback **socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in case
    // setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ProducerContentObjectCallback **socket_option_value) -> int {
          switch (socket_option_key) {
            case ProducerCallbacksOptions::NEW_CONTENT_OBJECT:
              *socket_option_value = &on_new_segment_;
              break;

            case ProducerCallbacksOptions::CONTENT_OBJECT_READY:
              *socket_option_value = &on_content_object_in_output_buffer_;
              break;

            case ProducerCallbacksOptions::CONTENT_OBJECT_OUTPUT:
              *socket_option_value = &on_content_object_output_;
              break;

            case ProducerCallbacksOptions::CONTENT_OBJECT_TO_SIGN:
              *socket_option_value = &on_content_object_to_sign_;
              break;

            default:
              return SOCKET_OPTION_NOT_GET;
          }

          return SOCKET_OPTION_GET;
        });
  }

  virtual int getSocketOption(
      int socket_option_key,
      interface::ProducerContentCallback **socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in case
    // setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ProducerContentCallback **socket_option_value) -> int {
          switch (socket_option_key) {
            case ProducerCallbacksOptions::CONTENT_PRODUCED:
              *socket_option_value = &on_content_produced_;
              break;

            default:
              return SOCKET_OPTION_NOT_GET;
          }

          return SOCKET_OPTION_GET;
        });
  }

  virtual int getSocketOption(
      int socket_option_key,
      interface::ProducerInterestCallback **socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in case
    // setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ProducerInterestCallback **socket_option_value) -> int {
          switch (socket_option_key) {
            case ProducerCallbacksOptions::INTEREST_INPUT:
              *socket_option_value = &on_interest_input_;
              break;

            case ProducerCallbacksOptions::INTEREST_DROP:
              *socket_option_value = &on_interest_dropped_input_buffer_;
              break;

            case ProducerCallbacksOptions::INTEREST_PASS:
              *socket_option_value = &on_interest_inserted_input_buffer_;
              break;

            case ProducerCallbacksOptions::CACHE_HIT:
              *socket_option_value = &on_interest_satisfied_output_buffer_;
              break;

            case ProducerCallbacksOptions::CACHE_MISS:
              *socket_option_value = &on_interest_process_;
              break;

            default:
              return SOCKET_OPTION_NOT_GET;
          }

          return SOCKET_OPTION_GET;
        });
  }

  virtual int getSocketOption(
      int socket_option_key,
      std::shared_ptr<core::Portal> &socket_option_value) {
    switch (socket_option_key) {
      case PORTAL:
        socket_option_value = portal_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
        ;
    }

    return SOCKET_OPTION_GET;
  }

  virtual int getSocketOption(int socket_option_key,
                              auth::CryptoHashType &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::HASH_ALGORITHM:
        socket_option_value = hash_algorithm_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  virtual int getSocketOption(
      int socket_option_key,
      core::NextSegmentCalculationStrategy &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::SUFFIX_STRATEGY:
        socket_option_value = suffix_strategy_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }
    return SOCKET_OPTION_GET;
  }

  virtual int getSocketOption(
      int socket_option_key,
      std::shared_ptr<auth::Signer> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::SIGNER: {
        utils::SpinLock::Acquire locked(signer_lock_);
        socket_option_value = signer_;
      } break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  virtual int setSocketOption(int socket_option_key,
                              const std::string &socket_option_value) {
    return SOCKET_OPTION_NOT_SET;
  }

  // If the thread calling lambda_func is not the same of io_service, this
  // function reschedule the function on it
  template <typename Lambda, typename arg2>
  int rescheduleOnIOServiceWithReference(int socket_option_key,
                                         arg2 &socket_option_value,
                                         Lambda lambda_func) {
    // To enforce type check
    std::function<int(int, arg2 &)> func = lambda_func;
    int result = SOCKET_OPTION_SET;
    if (production_protocol_ && production_protocol_->isRunning()) {
      std::mutex mtx;
      /* Condition variable for the wait */
      std::condition_variable cv;

      bool done = false;
      portal_->getIoService().dispatch([&socket_option_key,
                                        &socket_option_value, &mtx, &cv,
                                        &result, &done, &func]() {
        std::unique_lock<std::mutex> lck(mtx);
        done = true;
        result = func(socket_option_key, socket_option_value);
        cv.notify_all();
      });
      std::unique_lock<std::mutex> lck(mtx);
      if (!done) {
        cv.wait(lck);
      }
    } else {
      result = func(socket_option_key, socket_option_value);
    }

    return result;
  }

  // If the thread calling lambda_func is not the same of io_service, this
  // function reschedule the function on it
  template <typename Lambda, typename arg2>
  int rescheduleOnIOService(int socket_option_key, arg2 socket_option_value,
                            Lambda lambda_func) {
    // To enforce type check
    std::function<int(int, arg2)> func = lambda_func;
    int result = SOCKET_OPTION_SET;
    if (production_protocol_ && production_protocol_->isRunning()) {
      std::mutex mtx;
      /* Condition variable for the wait */
      std::condition_variable cv;
      bool done = false;
      portal_->getIoService().dispatch([&socket_option_key,
                                        &socket_option_value, &mtx, &cv,
                                        &result, &done, &func]() {
        std::unique_lock<std::mutex> lck(mtx);
        done = true;
        result = func(socket_option_key, socket_option_value);
        cv.notify_all();
      });
      std::unique_lock<std::mutex> lck(mtx);
      if (!done) {
        cv.wait(lck);
      }
    } else {
      result = func(socket_option_key, socket_option_value);
    }

    return result;
  }

  // Threads
 protected:
  interface::ProducerSocket *producer_interface_;
  asio::io_service io_service_;
  std::atomic<size_t> data_packet_size_;
  std::atomic<uint32_t> content_object_expiry_time_;

  utils::EventThread async_thread_;

  std::atomic<bool> making_manifest_;
  std::atomic<auth::CryptoHashType> hash_algorithm_;
  std::atomic<auth::CryptoSuite> crypto_suite_;
  utils::SpinLock signer_lock_;
  std::shared_ptr<auth::Signer> signer_;
  core::NextSegmentCalculationStrategy suffix_strategy_;

  std::unique_ptr<protocol::ProductionProtocol> production_protocol_;

  // callbacks
  ProducerInterestCallback on_interest_input_;
  ProducerInterestCallback on_interest_dropped_input_buffer_;
  ProducerInterestCallback on_interest_inserted_input_buffer_;
  ProducerInterestCallback on_interest_satisfied_output_buffer_;
  ProducerInterestCallback on_interest_process_;

  ProducerContentObjectCallback on_new_segment_;
  ProducerContentObjectCallback on_content_object_to_sign_;
  ProducerContentObjectCallback on_content_object_in_output_buffer_;
  ProducerContentObjectCallback on_content_object_output_;
  ProducerContentObjectCallback on_content_object_evicted_from_output_buffer_;

  ProducerContentCallback on_content_produced_;
};

}  // namespace implementation

}  // namespace transport
