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
using ProducerCallback = interface::ProducerSocket::Callback;

class ProducerSocket : public Socket {
 private:
  ProducerSocket(interface::ProducerSocket *producer_socket, int protocol,
                 std::shared_ptr<core::Portal> &&portal)
      : Socket(std::move(portal)),
        producer_interface_(producer_socket),
        data_packet_size_(default_values::content_object_packet_size),
        max_segment_size_(default_values::content_object_packet_size),
        content_object_expiry_time_(default_values::content_object_expiry_time),
        manifest_max_capacity_(default_values::manifest_max_capacity),
        hash_algorithm_(auth::CryptoHashType::SHA256),
        suffix_strategy_(std::make_shared<utils::IncrementalSuffixStrategy>(0)),
        aggregated_data_(false),
        fec_setting_(""),
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
        on_content_produced_(VOID_HANDLER),
        application_callback_(nullptr) {
    switch (protocol) {
      case ProductionProtocolAlgorithms::RTC_PROD:
        production_protocol_ =
            std::make_shared<protocol::RTCProductionProtocol>(this);
        break;
      case ProductionProtocolAlgorithms::BYTE_STREAM:
      default:
        production_protocol_ =
            std::make_shared<protocol::ByteStreamProductionProtocol>(this);
        break;
    }
  }

 public:
  ProducerSocket(interface::ProducerSocket *producer, int protocol)
      : ProducerSocket(producer, protocol, core::Portal::createShared()) {
    is_async_ = true;
  }

  ProducerSocket(interface::ProducerSocket *producer, int protocol,
                 ::utils::EventThread &worker)
      : ProducerSocket(producer, protocol, core::Portal::createShared(worker)) {
  }

  virtual ~ProducerSocket() {}

  interface::ProducerSocket *getInterface() {
    return producer_interface_;
  }

  void setInterface(interface::ProducerSocket *producer_socket) {
    producer_interface_ = producer_socket;
  }

  void connect() override { portal_->connect(false); }

  bool isRunning() override { return production_protocol_->isRunning(); };

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

  void sendMapme() { production_protocol_->sendMapme(); }

  void registerPrefix(const Prefix &producer_namespace) {
    portal_->registerRoute(producer_namespace);
  }

  void start() { production_protocol_->start(); }
  void stop() { production_protocol_->stop(); }

  using Socket::getSocketOption;
  using Socket::setSocketOption;

  virtual int setSocketOption(int socket_option_key,
                              ProducerCallback *socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ProducerCallback *socket_option_value) -> int {
          switch (socket_option_key) {
            case ProducerCallbacksOptions::PRODUCER_CALLBACK:
              application_callback_ = socket_option_value;
              break;
            default:
              return SOCKET_OPTION_NOT_SET;
          }

          return SOCKET_OPTION_SET;
        });
  }

  virtual int setSocketOption(int socket_option_key,
                              uint32_t socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::DATA_PACKET_SIZE:
        if (socket_option_value <= default_values::max_content_object_size &&
            socket_option_value > 0) {
          data_packet_size_ = socket_option_value;
        }
        break;

      case GeneralTransportOptions::MANIFEST_MAX_CAPACITY:
        manifest_max_capacity_ = socket_option_value;
        break;

      case GeneralTransportOptions::MAX_SEGMENT_SIZE:
        if (socket_option_value <= default_values::max_content_object_size &&
            socket_option_value > 0) {
          max_segment_size_ = socket_option_value;
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
      case RtcTransportOptions::AGGREGATED_DATA:
        aggregated_data_ = socket_option_value;
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
      const std::shared_ptr<utils::SuffixStrategy> &socket_option_value) {
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

  virtual int setSocketOption(
      int socket_option_key,
      const std::shared_ptr<auth::Verifier> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::VERIFIER:
        verifier_.reset();
        verifier_ = socket_option_value;
        return SOCKET_OPTION_SET;

      default:
        return SOCKET_OPTION_NOT_SET;
    }
  }

  int getSocketOption(int socket_option_key,
                      ProducerCallback **socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ProducerCallback **socket_option_value) -> int {
          switch (socket_option_key) {
            case ProducerCallbacksOptions::PRODUCER_CALLBACK:
              *socket_option_value = application_callback_;
              break;
            default:
              return SOCKET_OPTION_NOT_GET;
          }

          return SOCKET_OPTION_GET;
        });
  }

  virtual int getSocketOption(int socket_option_key,
                              uint32_t &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::MANIFEST_MAX_CAPACITY:
        socket_option_value = (uint32_t)manifest_max_capacity_;
        break;

      case GeneralTransportOptions::OUTPUT_BUFFER_SIZE:
        socket_option_value =
            (uint32_t)production_protocol_->getOutputBufferSize();
        break;

      case GeneralTransportOptions::DATA_PACKET_SIZE:
        socket_option_value = (uint32_t)data_packet_size_;
        break;

      case GeneralTransportOptions::MAX_SEGMENT_SIZE:
        socket_option_value = (uint32_t)max_segment_size_;
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
      case GeneralTransportOptions::ASYNC_MODE:
        socket_option_value = is_async_;
        break;

      case RtcTransportOptions::AGGREGATED_DATA:
        socket_option_value = aggregated_data_;
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
      std::shared_ptr<utils::SuffixStrategy> &socket_option_value) {
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

  int getSocketOption(int socket_option_key,
                      std::shared_ptr<auth::Verifier> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::VERIFIER:
        socket_option_value = verifier_;
        return SOCKET_OPTION_GET;

      default:
        return SOCKET_OPTION_NOT_GET;
    }
  }

  int getSocketOption(int socket_option_key, std::string &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::FEC_TYPE:
        socket_option_value = fec_setting_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  virtual int setSocketOption(int socket_option_key,
                              const std::string &socket_option_value) {
    int result = SOCKET_OPTION_NOT_SET;
    switch (socket_option_key) {
      case GeneralTransportOptions::FEC_TYPE:
        fec_setting_ = socket_option_value;
        result = SOCKET_OPTION_SET;
        break;

      default:
        return result;
    }
    return result;
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
      portal_->getThread().tryRunHandlerNow([&socket_option_key,
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
      portal_->getThread().tryRunHandlerNow([&socket_option_key,
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
  std::atomic<size_t> data_packet_size_;
  std::atomic<size_t> max_segment_size_;
  std::atomic<uint32_t> content_object_expiry_time_;

  std::atomic<uint32_t> manifest_max_capacity_;
  std::atomic<auth::CryptoHashType> hash_algorithm_;
  std::atomic<auth::CryptoSuite> crypto_suite_;
  utils::SpinLock signer_lock_;
  std::shared_ptr<utils::SuffixStrategy> suffix_strategy_;

  std::shared_ptr<protocol::ProductionProtocol> production_protocol_;

  // RTC transport
  bool aggregated_data_;

  // FEC setting
  std::string fec_setting_;

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

  ProducerCallback *application_callback_;
};

}  // namespace implementation

}  // namespace transport
