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

#include <hicn/transport/interfaces/socket_producer.h>
#include <hicn/transport/utils/identity.h>

#include <functional>

namespace transport {

namespace interface {

namespace details {}

typedef std::chrono::time_point<std::chrono::steady_clock> Time;
typedef std::chrono::microseconds TimeDuration;

ProducerSocket::ProducerSocket() : ProducerSocket(internal_io_service_) {}

ProducerSocket::ProducerSocket(asio::io_service &io_service)
    : io_service_(io_service),
      portal_(std::make_shared<Portal>(io_service_)),
      data_packet_size_(default_values::content_object_packet_size),
      content_object_expiry_time_(default_values::content_object_expiry_time),
      output_buffer_(default_values::producer_socket_output_buffer_size),
      registration_status_(REGISTRATION_NOT_ATTEMPTED),
      making_manifest_(false),
      hash_algorithm_(HashAlgorithm::SHA_256),
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
      on_content_produced_(VOID_HANDLER) {}

ProducerSocket::~ProducerSocket() {
  stop();
  if (listening_thread_.joinable()) {
    listening_thread_.join();
  }
}

void ProducerSocket::connect() {
  portal_->connect(false);
  listening_thread_ = std::thread(std::bind(&ProducerSocket::listen, this));
}

void ProducerSocket::serveForever() {
  if (listening_thread_.joinable()) {
    listening_thread_.join();
  }
}

void ProducerSocket::stop() { portal_->stopEventsLoop(); }

void ProducerSocket::registerPrefix(const Prefix &producer_namespace) {
  served_namespaces_.push_back(producer_namespace);
}

void ProducerSocket::listen() {
  registration_status_ = REGISTRATION_IN_PROGRESS;
  bool first = true;

  for (core::Prefix &producer_namespace : served_namespaces_) {
    if (first) {
      core::BindConfig bind_config(producer_namespace, 1000);
      portal_->bind(bind_config);
      portal_->setProducerCallback(this);
      first = !first;
    } else {
      portal_->registerRoute(producer_namespace);
    }
  }

  portal_->runEventsLoop();
}

void ProducerSocket::passContentObjectToCallbacks(
    const std::shared_ptr<ContentObject> &content_object) {
  if (content_object) {
    if (on_new_segment_) {
      io_service_.dispatch([this, content_object]() {
        on_new_segment_(*this, *content_object);
      });
    }

    if (on_content_object_to_sign_) {
      io_service_.dispatch([this, content_object]() {
        on_content_object_to_sign_(*this, *content_object);
      });
    }

    if (on_content_object_in_output_buffer_) {
      io_service_.dispatch([this, content_object]() {
        on_content_object_in_output_buffer_(*this, *content_object);
      });
    }

    output_buffer_.insert(content_object);

    if (on_content_object_output_) {
      io_service_.dispatch([this, content_object]() {
        on_content_object_output_(*this, *content_object);
      });
    }

    portal_->sendContentObject(*content_object);
  }
}

void ProducerSocket::produce(ContentObject &content_object) {
  if (on_content_object_in_output_buffer_) {
    io_service_.dispatch([this, &content_object]() {
      on_content_object_in_output_buffer_(*this, content_object);
    });
  }

  output_buffer_.insert(std::static_pointer_cast<ContentObject>(
      content_object.shared_from_this()));

  if (on_content_object_output_) {
    io_service_.dispatch([this, &content_object]() {
      on_content_object_output_(*this, content_object);
    });
  }

  portal_->sendContentObject(content_object);
}

uint32_t ProducerSocket::produce(Name content_name,
                                 std::unique_ptr<utils::MemBuf> &&buffer,
                                 bool is_last, uint32_t start_offset) {
  if (TRANSPORT_EXPECT_FALSE(buffer->length() == 0)) {
    return 0;
  }

  // Copy the atomic variables to ensure they keep the same value
  // during the production
  std::size_t data_packet_size = data_packet_size_;
  uint32_t content_object_expiry_time = content_object_expiry_time_;
  HashAlgorithm hash_algo = hash_algorithm_;
  bool making_manifest = making_manifest_;
  auto suffix_strategy = utils::SuffixStrategyFactory::getSuffixStrategy(
      suffix_strategy_, start_offset);
  std::shared_ptr<utils::Identity> identity;
  getSocketOption(GeneralTransportOptions::IDENTITY, identity);

  auto buffer_size = buffer->length();
  int bytes_segmented = 0;
  std::size_t header_size;
  std::size_t manifest_header_size = 0;
  std::size_t signature_length = 0;
  std::uint32_t final_block_number = start_offset;
  uint64_t free_space_for_content = 0;

  core::Packet::Format format;
  std::shared_ptr<ContentObjectManifest> manifest;
  bool is_last_manifest = false;

  // TODO Manifest may still be used for indexing
  if (making_manifest && !identity) {
    TRANSPORT_LOGD("Making manifests without setting producer identity.");
  }

  core::Packet::Format hf_format = core::Packet::Format::HF_UNSPEC;
  core::Packet::Format hf_format_ah = core::Packet::Format::HF_UNSPEC;
  if (content_name.getType() == HNT_CONTIGUOUS_V4 ||
      content_name.getType() == HNT_IOV_V4) {
    hf_format = core::Packet::Format::HF_INET_TCP;
    hf_format_ah = core::Packet::Format::HF_INET_TCP_AH;
  } else if (content_name.getType() == HNT_CONTIGUOUS_V6 ||
             content_name.getType() == HNT_IOV_V6) {
    hf_format = core::Packet::Format::HF_INET6_TCP;
    hf_format_ah = core::Packet::Format::HF_INET6_TCP_AH;
  } else {
    throw errors::RuntimeException("Unknown name format.");
  }

  format = hf_format;
  if (making_manifest) {
    manifest_header_size = core::Packet::getHeaderSizeFromFormat(
        identity ? hf_format_ah : hf_format,
        identity ? identity->getSignatureLength() : 0);
  } else if (identity) {
    format = hf_format_ah;
    signature_length = identity->getSignatureLength();
  }

  header_size = core::Packet::getHeaderSizeFromFormat(format, signature_length);
  free_space_for_content = data_packet_size - header_size;
  uint32_t number_of_segments =
      uint32_t(std::ceil(double(buffer_size) / double(free_space_for_content)));
  if (free_space_for_content * number_of_segments < buffer_size) {
    number_of_segments++;
  }

  // TODO allocate space for all the headers
  if (making_manifest) {
    uint32_t segment_in_manifest = static_cast<uint32_t>(
        std::floor(double(data_packet_size - manifest_header_size -
                          ContentObjectManifest::getManifestHeaderSize()) /
                   ContentObjectManifest::getManifestEntrySize()) -
        1.0);
    uint32_t number_of_manifests = static_cast<uint32_t>(
        std::ceil(float(number_of_segments) / segment_in_manifest));
    final_block_number += number_of_segments + number_of_manifests - 1;

    manifest.reset(ContentObjectManifest::createManifest(
        content_name.setSuffix(suffix_strategy->getNextManifestSuffix()),
        core::ManifestVersion::VERSION_1, core::ManifestType::INLINE_MANIFEST,
        hash_algo, is_last_manifest, content_name, suffix_strategy_,
        identity ? identity->getSignatureLength() : 0));
    manifest->setLifetime(content_object_expiry_time);

    if (is_last) {
      manifest->setFinalBlockNumber(final_block_number);
    } else {
      manifest->setFinalBlockNumber(utils::SuffixStrategy::INVALID_SUFFIX);
    }
  }

  for (unsigned int packaged_segments = 0;
       packaged_segments < number_of_segments; packaged_segments++) {
    if (making_manifest) {
      if (manifest->estimateManifestSize(2) >
          data_packet_size - manifest_header_size) {
        // Send the current manifest
        manifest->encode();

        // If identity set, sign manifest
        if (identity) {
          identity->getSigner().sign(*manifest);
        }

        passContentObjectToCallbacks(manifest);

        // Send content objects stored in the queue
        while (!content_queue_.empty()) {
          passContentObjectToCallbacks(content_queue_.front());
          content_queue_.pop();
        }

        // Create new manifest. The reference to the last manifest has been
        // acquired in the passContentObjectToCallbacks function, so we can
        // safely release this reference
        manifest.reset(ContentObjectManifest::createManifest(
            content_name.setSuffix(suffix_strategy->getNextManifestSuffix()),
            core::ManifestVersion::VERSION_1,
            core::ManifestType::INLINE_MANIFEST, hash_algo, is_last_manifest,
            content_name, suffix_strategy_,
            identity ? identity->getSignatureLength() : 0));

        manifest->setLifetime(content_object_expiry_time);
        manifest->setFinalBlockNumber(
            is_last ? final_block_number
                    : utils::SuffixStrategy::INVALID_SUFFIX);
      }
    }

    auto content_suffix = suffix_strategy->getNextContentSuffix();
    auto content_object = std::make_shared<ContentObject>(
        content_name.setSuffix(content_suffix), format);
    content_object->setLifetime(content_object_expiry_time);

    auto b = buffer->cloneOne();
    b->trimStart(free_space_for_content * packaged_segments);
    b->trimEnd(b->length());

    if (TRANSPORT_EXPECT_FALSE(packaged_segments == number_of_segments - 1)) {
      b->append(buffer_size - bytes_segmented);
      bytes_segmented += (int)(buffer_size - bytes_segmented);

      if (is_last && making_manifest) {
        is_last_manifest = true;
      } else if (is_last) {
        content_object->setRst();
      }

    } else {
      b->append(free_space_for_content);
      bytes_segmented += (int)(free_space_for_content);
    }

    content_object->appendPayload(std::move(b));

    if (making_manifest) {
      using namespace std::chrono_literals;
      utils::CryptoHash hash = content_object->computeDigest(hash_algo);
      manifest->addSuffixHash(content_suffix, hash);
      content_queue_.push(content_object);
    } else {
      if (identity) {
        identity->getSigner().sign(*content_object);
      }
      passContentObjectToCallbacks(content_object);
    }
  }

  if (making_manifest) {
    if (is_last_manifest) {
      manifest->setFinalManifest(is_last_manifest);
    }

    manifest->encode();
    if (identity) {
      identity->getSigner().sign(*manifest);
    }

    passContentObjectToCallbacks(manifest);
    while (!content_queue_.empty()) {
      passContentObjectToCallbacks(content_queue_.front());
      content_queue_.pop();
    }
  }

  if (on_content_produced_) {
    io_service_.dispatch([this, buffer_size]() {
      on_content_produced_(*this, std::make_error_code(std::errc(0)),
                           buffer_size);
    });
  }

  return suffix_strategy->getTotalCount();
}

void ProducerSocket::asyncProduce(ContentObject &content_object) {
  if (!async_thread_.stopped()) {
    auto co_ptr = std::static_pointer_cast<ContentObject>(
        content_object.shared_from_this());
    async_thread_.add([this, content_object = std::move(co_ptr)]() {
      produce(*content_object);
    });
  }
}

void ProducerSocket::asyncProduce(const Name &suffix, const uint8_t *buf,
                                  size_t buffer_size) {
  if (!async_thread_.stopped()) {
    async_thread_.add([this, suffix, buffer = buf, size = buffer_size]() {
      produce(suffix, buffer, size, 0, false);
    });
  }
}

void ProducerSocket::onInterest(Interest &interest) {
  if (on_interest_input_) {
    on_interest_input_(*this, interest);
  }

  const std::shared_ptr<ContentObject> content_object =
      output_buffer_.find(interest);

  if (content_object) {
    if (on_interest_satisfied_output_buffer_) {
      on_interest_satisfied_output_buffer_(*this, interest);
    }

    if (on_content_object_output_) {
      on_content_object_output_(*this, *content_object);
    }

    portal_->sendContentObject(*content_object);
  } else {
    if (on_interest_process_) {
      on_interest_process_(*this, interest);
    }
  }
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    uint32_t socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::DATA_PACKET_SIZE:
      if (socket_option_value < default_values::max_content_object_size &&
          socket_option_value > 0) {
        data_packet_size_ = socket_option_value;
        break;
      }

    case GeneralTransportOptions::OUTPUT_BUFFER_SIZE:
      output_buffer_.setLimit(socket_option_value);
      break;

    case GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME:
      content_object_expiry_time_ = socket_option_value;
      break;

    default:
      return SOCKET_OPTION_NOT_SET;
  }

  return SOCKET_OPTION_SET;
}

int ProducerSocket::setSocketOption(int socket_option_key,
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
      });
}

int ProducerSocket::setSocketOption(int socket_option_key,
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

int ProducerSocket::setSocketOption(int socket_option_key,
                                    Name *socket_option_value) {
  return SOCKET_OPTION_NOT_SET;
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    std::list<Prefix> socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::NETWORK_NAME:
      served_namespaces_ = socket_option_value;
      break;
    default:
      return SOCKET_OPTION_NOT_SET;
  }

  return SOCKET_OPTION_SET;
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ProducerContentObjectCallback socket_option_value) {
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
      });
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ProducerInterestCallback socket_option_value) {
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

int ProducerSocket::setSocketOption(
    int socket_option_key, ProducerContentCallback socket_option_value) {
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

int ProducerSocket::setSocketOption(int socket_option_key,
                                    HashAlgorithm socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::HASH_ALGORITHM:
      hash_algorithm_ = socket_option_value;
      break;
    default:
      return SOCKET_OPTION_NOT_SET;
  }

  return SOCKET_OPTION_SET;
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    utils::CryptoSuite socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::CRYPTO_SUITE:
      crypto_suite_ = socket_option_value;
      break;
    default:
      return SOCKET_OPTION_NOT_SET;
  }

  return SOCKET_OPTION_SET;
}

int ProducerSocket::setSocketOption(
    int socket_option_key,
    const std::shared_ptr<utils::Identity> &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::IDENTITY: {
      utils::SpinLock::Acquire locked(identity_lock_);
      identity_.reset();
      identity_ = socket_option_value;
    } break;
    default:
      return SOCKET_OPTION_NOT_SET;
  }

  return SOCKET_OPTION_SET;
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    const std::string &socket_option_value) {
  switch (socket_option_key) {
    case DataLinkOptions::OUTPUT_INTERFACE:
      output_interface_ = socket_option_value;
      portal_->setOutputInterface(output_interface_);
      break;
    default:
      return SOCKET_OPTION_NOT_SET;
  }

  return SOCKET_OPTION_SET;
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    uint32_t &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::OUTPUT_BUFFER_SIZE:
      socket_option_value = (uint32_t)output_buffer_.getLimit();
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

int ProducerSocket::getSocketOption(int socket_option_key,
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

int ProducerSocket::getSocketOption(int socket_option_key,
                                    std::list<Prefix> &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::NETWORK_NAME:
      socket_option_value = served_namespaces_;
      break;

    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

int ProducerSocket::getSocketOption(
    int socket_option_key,
    ProducerContentObjectCallback **socket_option_value) {
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
      });
}

int ProducerSocket::getSocketOption(
    int socket_option_key, ProducerContentCallback **socket_option_value) {
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

int ProducerSocket::getSocketOption(
    int socket_option_key, ProducerInterestCallback **socket_option_value) {
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
      });
}

int ProducerSocket::getSocketOption(
    int socket_option_key, std::shared_ptr<Portal> &socket_option_value) {
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

int ProducerSocket::getSocketOption(int socket_option_key,
                                    HashAlgorithm &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::HASH_ALGORITHM:
      socket_option_value = hash_algorithm_;
      break;
    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    utils::CryptoSuite &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::HASH_ALGORITHM:
      socket_option_value = crypto_suite_;
      break;
    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

int ProducerSocket::getSocketOption(
    int socket_option_key,
    std::shared_ptr<utils::Identity> &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::IDENTITY: {
      utils::SpinLock::Acquire locked(identity_lock_);
      socket_option_value = identity_;
    } break;
    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    std::string &socket_option_value) {
  switch (socket_option_key) {
    case DataLinkOptions::OUTPUT_INTERFACE:
      socket_option_value = output_interface_;
      break;
    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

asio::io_service &ProducerSocket::getIoService() { return io_service_; }

}  // namespace interface

}  // end namespace transport
