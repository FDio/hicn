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

#include <hicn/transport/interfaces/socket.h>
#include <hicn/transport/utils/content_store.h>
#include <hicn/transport/utils/event_thread.h>

#include <atomic>
#include <cmath>
#include <mutex>
#include <queue>
#include <thread>

#define PUSH_API 1

#define REGISTRATION_NOT_ATTEMPTED 0
#define REGISTRATION_SUCCESS 1
#define REGISTRATION_FAILURE 2
#define REGISTRATION_IN_PROGRESS 3

namespace transport {

namespace interface {

using namespace core;

class ProducerSocket : public Socket<BasePortal>,
                       public BasePortal::ProducerCallback {
 public:
  explicit ProducerSocket();
  explicit ProducerSocket(asio::io_service &io_service);

  ~ProducerSocket();

  void connect() override;

  uint32_t produce(Name content_name, const uint8_t *buffer, size_t buffer_size,
                   bool is_last = true, uint32_t start_offset = 0);

  void produce(ContentObject &content_object);

  void asyncProduce(const Name &suffix, const uint8_t *buf, size_t buffer_size);

  void asyncProduce(const Name &suffix, ContentBuffer &&output_buffer);

  void asyncProduce(ContentObject &content_object);

  void registerPrefix(const Prefix &producer_namespace);

  void serveForever();

  void stop();

  asio::io_service &getIoService() override;

  virtual void onInterest(const Interest &interest);

  virtual void onInterest(Interest::Ptr &&interest) override {
    onInterest(*interest);
  };
  
  TRANSPORT_ALWAYS_INLINE int setSocketOption(int socket_option_key,
                                              uint32_t socket_option_value) {
    switch (socket_option_key) {
     
      case GeneralTransportOptions::DATA_PACKET_SIZE:
        if (socket_option_value < default_values::max_content_object_size &&
            socket_option_value > 0) {
          data_packet_size_ = socket_option_value;
          break;
        }

      case GeneralTransportOptions::INPUT_BUFFER_SIZE:
        if (socket_option_value >= 1) {
          input_buffer_capacity_ = socket_option_value;
          break;
        }

      case GeneralTransportOptions::OUTPUT_BUFFER_SIZE:
        output_buffer_.setLimit(socket_option_value);
        break;

      case GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME:
        content_object_expiry_time_ = socket_option_value;
        break;

      case GeneralTransportOptions::SIGNATURE_TYPE:
        if (socket_option_value == SOCKET_OPTION_DEFAULT) {
          signature_type_ = SHA_256;
        } else {
          signature_type_ = socket_option_value;
        }

        if (signature_type_ == SHA_256 || signature_type_ == RSA_256) {
          signature_size_ = 32;
        }

        break;

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

      case ProducerCallbacksOptions::CONTENT_OBJECT_SIGN:
        if (socket_option_value == VOID_HANDLER) {
          on_content_object_to_sign_ = VOID_HANDLER;
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

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(int socket_option_key,
                                              bool socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::MAKE_MANIFEST:
        making_manifest_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(int socket_option_key,
                                              Name *socket_option_value) {
    return SOCKET_OPTION_NOT_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key, std::list<Prefix> socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::NETWORK_NAME:
        served_namespaces_ = socket_option_value;
        break;
      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key,
      ProducerContentObjectCallback socket_option_value) {
    switch (socket_option_key) {
      case ProducerCallbacksOptions::NEW_CONTENT_OBJECT:
        on_new_segment_ = socket_option_value;
        break;

      case ProducerCallbacksOptions::CONTENT_OBJECT_SIGN:
        on_content_object_to_sign_ = socket_option_value;
        break;

      case ProducerCallbacksOptions::CONTENT_OBJECT_READY:
        on_content_object_in_output_buffer_ = socket_option_value;
        break;

      case ProducerCallbacksOptions::CONTENT_OBJECT_OUTPUT:
        on_content_object_output_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key,
      ProducerInterestCallback socket_option_value) {
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
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key,
      ProducerContentCallback socket_option_value) {
    switch (socket_option_key) {
      case ProducerCallbacksOptions::CONTENT_PRODUCED:
        on_content_produced_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key, HashAlgorithm socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::HASH_ALGORITHM:
        hash_algorithm_ = socket_option_value;
        break;
      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key, utils::CryptoSuite socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::CRYPTO_SUITE:
        crypto_suite_ = socket_option_value;
        break;
      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key,
      const std::shared_ptr<utils::Identity> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::IDENTITY:
        identity_ = socket_option_value;
        break;
      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key, const std::string &socket_option_value) {
    switch (socket_option_key) {
      case DataLinkOptions::OUTPUT_INTERFACE:
        output_interface_ = socket_option_value;
        portal_->setOutputInterface(output_interface_);
        break;
      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
    ;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(int socket_option_key,
                                              uint32_t &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::INPUT_BUFFER_SIZE:
        socket_option_value = input_buffer_capacity_;
        break;

      case GeneralTransportOptions::OUTPUT_BUFFER_SIZE:
        socket_option_value = output_buffer_.getLimit();
        break;

      case GeneralTransportOptions::DATA_PACKET_SIZE:
        socket_option_value = data_packet_size_;
        break;

      case GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME:
        socket_option_value = content_object_expiry_time_;
        break;

      case GeneralTransportOptions::SIGNATURE_TYPE:
        socket_option_value = signature_type_;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(int socket_option_key,
                                              bool &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::MAKE_MANIFEST:
        socket_option_value = making_manifest_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key, std::list<Prefix> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::NETWORK_NAME:
        socket_option_value = served_namespaces_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key,
      ProducerContentObjectCallback **socket_option_value) {
    switch (socket_option_key) {
      case ProducerCallbacksOptions::NEW_CONTENT_OBJECT:
        *socket_option_value = &on_new_segment_;
        break;

      case ProducerCallbacksOptions::CONTENT_OBJECT_SIGN:
        *socket_option_value = &on_content_object_to_sign_;
        break;

      case ProducerCallbacksOptions::CONTENT_OBJECT_READY:
        *socket_option_value = &on_content_object_in_output_buffer_;
        break;

      case ProducerCallbacksOptions::CONTENT_OBJECT_OUTPUT:
        *socket_option_value = &on_content_object_output_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key,
      ProducerContentCallback **socket_option_value) {
    switch (socket_option_key) {
      case ProducerCallbacksOptions::CONTENT_PRODUCED:
        *socket_option_value = &on_content_produced_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key, ProducerInterestCallback **socket_option_value) {
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

      case CACHE_HIT:
        *socket_option_value = &on_interest_satisfied_output_buffer_;
        break;

      case CACHE_MISS:
        *socket_option_value = &on_interest_process_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key,
      std::shared_ptr<Portal> &socket_option_value) {
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

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key, HashAlgorithm &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::HASH_ALGORITHM:
        socket_option_value = hash_algorithm_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key, utils::CryptoSuite &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::HASH_ALGORITHM:
        socket_option_value = crypto_suite_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key,
      std::shared_ptr<utils::Identity> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::IDENTITY:
        if (identity_) {
          socket_option_value = identity_;
          break;
        }
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key, std::string &socket_option_value) {
    switch (socket_option_key) {
      case DataLinkOptions::OUTPUT_INTERFACE:
        socket_option_value = output_interface_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

 protected:
  asio::io_service internal_io_service_;
  asio::io_service &io_service_;
  std::shared_ptr<Portal> portal_;
  std::size_t data_packet_size_;
  std::list<Prefix> served_namespaces_;
  uint32_t content_object_expiry_time_;

  // buffers
  utils::ContentStore output_buffer_;

 private:
  utils::EventThread async_thread_;

  int registration_status_;

  bool making_manifest_;

  // map for storing sequence numbers for several calls of the publish
  // function
  std::unordered_map<Name, std::unordered_map<int, uint32_t>> seq_number_map_;

  int signature_type_;
  int signature_size_;

  HashAlgorithm hash_algorithm_;
  utils::CryptoSuite crypto_suite_;
  std::shared_ptr<utils::Identity> identity_;
  // utils::Signer& signer_;

  // buffers

  std::queue<std::shared_ptr<const Interest>> input_buffer_;
  std::atomic_size_t input_buffer_capacity_;
  std::atomic_size_t input_buffer_size_;

#ifndef PUSH_API
  std::mutex pending_interests_mtx_;
  std::unordered_map<Name, std::shared_ptr<const Interest>> pending_interests_;
#endif

  // threads
  std::thread listening_thread_;
  std::thread processing_thread_;
  volatile bool processing_thread_stop_;
  volatile bool listening_thread_stop_;

  // callbacks
 protected:
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

 private:
  void listen();

  void passContentObjectToCallbacks(
      const std::shared_ptr<ContentObject> &content_object);
};

}  // namespace interface

}  // namespace transport
