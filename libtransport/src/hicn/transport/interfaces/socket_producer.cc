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

namespace transport {

namespace interface {

typedef std::chrono::time_point<std::chrono::steady_clock> Time;
typedef std::chrono::microseconds TimeDuration;

ProducerSocket::ProducerSocket() : ProducerSocket(internal_io_service_) {}

ProducerSocket::ProducerSocket(asio::io_service &io_service)
    : io_service_(io_service),
      portal_(std::make_shared<Portal>(io_service_)),
      data_packet_size_(default_values::content_object_packet_size),
      content_object_expiry_time_(default_values::content_object_expiry_time),
      output_buffer_(default_values::producer_socket_output_buffer_size),
      async_thread_(),
      registration_status_(REGISTRATION_NOT_ATTEMPTED),
      making_manifest_(false),
      signature_type_(SHA_256),
      hash_algorithm_(HashAlgorithm::SHA_256),
      input_buffer_capacity_(default_values::producer_socket_input_buffer_size),
      input_buffer_size_(0),
      processing_thread_stop_(false),
      listening_thread_stop_(false),
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
  listening_thread_stop_ = false;
}

ProducerSocket::~ProducerSocket() {
  processing_thread_stop_ = true;
  portal_->stopEventsLoop(true);

  if (processing_thread_.joinable()) {
    processing_thread_.join();
  }

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
    if (on_new_segment_ != VOID_HANDLER) {
      on_new_segment_(*this, *content_object);
    }

    if (on_content_object_to_sign_ != VOID_HANDLER) {
      on_content_object_to_sign_(*this, *content_object);
    }

    if (on_content_object_in_output_buffer_ != VOID_HANDLER) {
      on_content_object_in_output_buffer_(*this, *content_object);
    }

    output_buffer_.insert(content_object);

    if (on_content_object_output_ != VOID_HANDLER) {
      on_content_object_output_(*this, *content_object);
    }

#ifndef PUSH_API
    std::unordered_map<Name, std::shared_ptr<const Interest>>::iterator it;

    {
      std::lock_guard<std::mutex> lock(pending_interests_mtx_);
      it = pending_interests_.find(content_object->getName());
    }

    if (it != pending_interests_.end()) {
      content_object->setLocator(it->second->getLocator());
      portal_->sendContentObject(*content_object);
      std::lock_guard<std::mutex> lock(pending_interests_mtx_);
      pending_interests_.erase(it);
    }
#else
    portal_->sendContentObject(*content_object);
#endif
  }
}

void ProducerSocket::produce(ContentObject &content_object) {
  if (on_content_object_in_output_buffer_ != VOID_HANDLER) {
    on_content_object_in_output_buffer_(*this, content_object);
  }

  output_buffer_.insert(std::static_pointer_cast<ContentObject>(
      content_object.shared_from_this()));

  if (on_content_object_output_ != VOID_HANDLER) {
    on_content_object_output_(*this, content_object);
  }

#ifndef PUSH_API
  std::unordered_map<Name, std::shared_ptr<const Interest>>::iterator it;

  {
    std::lock_guard<std::mutex> lock(pending_interests_mtx_);
    it = pending_interests_.find(content_object.getName());
  }

  if (it != pending_interests_.end()) {
    content_object.setLocator(it->second->getLocator());
    portal_->sendContentObject(content_object);
    std::lock_guard<std::mutex> lock(pending_interests_mtx_);
    pending_interests_.erase(it);
  }
#else
  portal_->sendContentObject(content_object);
#endif
}

uint32_t ProducerSocket::produce(Name content_name, const uint8_t *buf,
                                 size_t buffer_size, bool is_last,
                                 uint32_t start_offset) {
  if (TRANSPORT_EXPECT_FALSE(buffer_size == 0)) {
    return 0;
  }

  const std::size_t hash_size = 32;

  int bytes_segmented = 0;
  std::size_t header_size;
  std::size_t manifest_header_size = 0;
  std::size_t signature_length = 0;
  std::uint32_t final_block_number = 0;

  uint64_t free_space_for_content = 0;

  core::Packet::Format format;

  uint32_t current_segment = start_offset;
  std::shared_ptr<ContentObjectManifest> manifest;
  bool is_last_manifest = false;
  std::unique_ptr<utils::CryptoHash> zero_hash;

  // TODO Manifest may still be used for indexing
  if (making_manifest_ && !identity_) {
    throw errors::RuntimeException(
        "Making manifests without setting producer identity. Aborting.");
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
  if (making_manifest_) {
    format = hf_format;
    manifest_header_size = core::Packet::getHeaderSizeFromFormat(
        hf_format_ah, identity_->getSignatureLength());
  } else if (identity_) {
    format = hf_format_ah;
    signature_length = identity_->getSignatureLength();
  }

  header_size = core::Packet::getHeaderSizeFromFormat(format, signature_length);

  free_space_for_content = data_packet_size_ - header_size;

  uint32_t number_of_segments =
      uint32_t(std::ceil(double(buffer_size) / double(free_space_for_content)));

  if (free_space_for_content * number_of_segments < buffer_size) {
    number_of_segments++;
  }

  if (making_manifest_) {
    auto segment_in_manifest = static_cast<float>(
        std::floor(double(data_packet_size_ - manifest_header_size -
                          ContentObjectManifest::getManifestHeaderSize()) /
                   (4.0 + 32.0)) -
        1.0);
    auto number_of_manifests = static_cast<uint32_t>(
        std::ceil(float(number_of_segments) / segment_in_manifest));
    final_block_number = number_of_segments + number_of_manifests - 1;

    manifest.reset(ContentObjectManifest::createManifest(
        content_name.setSuffix(current_segment++),
        core::ManifestVersion::VERSION_1, core::ManifestType::INLINE_MANIFEST,
        hash_algorithm_, is_last_manifest, content_name,
        core::NextSegmentCalculationStrategy::INCREMENTAL,
        identity_->getSignatureLength()));
    manifest->setLifetime(content_object_expiry_time_);

    if (is_last) {
      manifest->setFinalBlockNumber(final_block_number);
    } else {
      manifest->setFinalBlockNumber(std::numeric_limits<uint32_t>::max());
    }

    uint8_t hash[hash_size];
    std::memset(hash, 0, hash_size);
    zero_hash = std::make_unique<utils::CryptoHash>(
        hash, hash_size, static_cast<utils::CryptoHashType>(hash_algorithm_));
  }

  for (unsigned int packaged_segments = 0;
       packaged_segments < number_of_segments; packaged_segments++) {
    if (making_manifest_) {
      if (manifest->estimateManifestSize(2) >
          data_packet_size_ - manifest_header_size) {
        // Add next manifest
        manifest->addSuffixHash(current_segment, *zero_hash);

        // Send the current manifest
        manifest->encode();

        identity_->getSigner().sign(*manifest);

        passContentObjectToCallbacks(manifest);

        // Create new manifest. The reference to the last manifest has been
        // acquired in the passContentObjectToCallbacks function, so we can
        // safely release this reference
        manifest.reset(ContentObjectManifest::createManifest(
            content_name.setSuffix(current_segment),
            core::ManifestVersion::VERSION_1,
            core::ManifestType::INLINE_MANIFEST, hash_algorithm_,
            is_last_manifest, content_name,
            core::NextSegmentCalculationStrategy::INCREMENTAL,
            identity_->getSignatureLength()));
        manifest->setLifetime(content_object_expiry_time_);
        if (is_last) {
          manifest->setFinalBlockNumber(final_block_number);
        } else {
          manifest->setFinalBlockNumber(std::numeric_limits<uint32_t>::max());
        }
        current_segment++;
      }
    }

    auto content_object = std::make_shared<ContentObject>(
        content_name.setSuffix(current_segment), format);
    content_object->setLifetime(content_object_expiry_time_);

    if (!making_manifest_ && identity_) {
      content_object->setSignatureSize(signature_length);
    }

    if (packaged_segments == number_of_segments - 1) {
      content_object->appendPayload(&buf[bytes_segmented],
                                    buffer_size - bytes_segmented);
      bytes_segmented += (int)(buffer_size - bytes_segmented);

      if (is_last && making_manifest_) {
        is_last_manifest = true;
      } else if (is_last) {
        content_object->setRst();
      }

    } else {
      content_object->appendPayload(&buf[bytes_segmented],
                                    free_space_for_content);
      bytes_segmented += (int)(free_space_for_content);
    }

    if (making_manifest_) {
      using namespace std::chrono_literals;
      utils::CryptoHash hash = content_object->computeDigest(hash_algorithm_);
      manifest->addSuffixHash(current_segment, hash);
    } else if (identity_) {
      identity_->getSigner().sign(*content_object);
    }

    current_segment++;
    passContentObjectToCallbacks(content_object);
  }

  if (making_manifest_) {
    if (is_last_manifest) {
      manifest->setFinalManifest(is_last_manifest);
    }
    manifest->encode();
    //  Time t0 = std::chrono::steady_clock::now();
    identity_->getSigner().sign(*manifest);
    passContentObjectToCallbacks(manifest);
  }

  if (on_content_produced_ != VOID_HANDLER) {
    on_content_produced_(*this, std::make_error_code(std::errc(0)),
                         buffer_size);
  }

  return current_segment;
}

void ProducerSocket::asyncProduce(ContentObject &content_object) {
  if (!async_thread_.stopped()) {
    // async_thread_.add(std::bind(&ProducerSocket::produce, this,
    // content_object));
  }
}

// void ProducerSocket::asyncProduce(const Name &suffix,
//                                   const uint8_t *buf,
//                                   size_t buffer_size,
//                                   AsyncProduceCallback && handler) {
//   if (!async_thread_.stopped()) {
//     async_thread_.add([this, buffer = buf, size = buffer_size, cb =
//     std::move(handler)] () {
//       uint64_t bytes_written = produce(suff, buffer, size, 0, false);
//       auto ec = std::make_errc(0);
//       cb(*this, ec, bytes_written);
//     });
//   }
// }

void ProducerSocket::asyncProduce(const Name &suffix, const uint8_t *buf,
                                  size_t buffer_size) {
  if (!async_thread_.stopped()) {
    async_thread_.add(
        [this, suff = suffix, buffer = buf, size = buffer_size]() {
          produce(suff, buffer, size, true);
        });
  }
}

void ProducerSocket::asyncProduce(
    const Name &suffix, utils::SharableVector<uint8_t> &&output_buffer) {
  if (!async_thread_.stopped()) {
    async_thread_.add(
        [this, suff = suffix, buffer = std::move(output_buffer)]() {
          TRANSPORT_LOGI("FOR REAL!!!!!! --> Producing content with name %s",
                         suff.toString().c_str());
          produce(suff, &buffer[0], buffer.size(), true);
        });
  }
}

void ProducerSocket::onInterest(Interest &interest) {
  if (on_interest_input_ != VOID_HANDLER) {
    on_interest_input_(*this, interest);
  }

  const std::shared_ptr<ContentObject> content_object =
      output_buffer_.find(interest);

  if (content_object) {
    if (on_interest_satisfied_output_buffer_ != VOID_HANDLER) {
      on_interest_satisfied_output_buffer_(*this, interest);
    }

    if (on_content_object_output_ != VOID_HANDLER) {
      on_content_object_output_(*this, *content_object);
    }

    portal_->sendContentObject(*content_object);
  } else {
#ifndef PUSH_API
    {
      std::lock_guard<std::mutex> lock(pending_interests_mtx_);
      pending_interests_[interest.getName()] =
          std::static_pointer_cast<const Interest>(interest.shared_from_this());
    }
#endif

    if (on_interest_process_ != VOID_HANDLER) {
      //  external_io_service_.post([this, &interest] () {
      on_interest_process_(*this, interest);
      //  });
    }
  }
}

asio::io_service &ProducerSocket::getIoService() { return io_service_; }

int ProducerSocket::setSocketOption(int socket_option_key,
                                    uint32_t socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::DATA_PACKET_SIZE:
      if (socket_option_value < default_values::max_content_object_size &&
          socket_option_value > 0) {
        data_packet_size_ = socket_option_value;
        return SOCKET_OPTION_SET;
      } else {
        return SOCKET_OPTION_NOT_SET;
      }

    case GeneralTransportOptions::INPUT_BUFFER_SIZE:
      if (socket_option_value >= 1) {
        input_buffer_capacity_ = socket_option_value;
        return SOCKET_OPTION_SET;
      } else {
        return SOCKET_OPTION_NOT_SET;
      }

    case GeneralTransportOptions::OUTPUT_BUFFER_SIZE:
      output_buffer_.setLimit(socket_option_value);
      return SOCKET_OPTION_SET;

    case GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME:
      content_object_expiry_time_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case GeneralTransportOptions::SIGNATURE_TYPE:
      if (socket_option_value == SOCKET_OPTION_DEFAULT) {
        signature_type_ = SHA_256;
      } else {
        signature_type_ = socket_option_value;
      }

      if (signature_type_ == SHA_256 || signature_type_ == RSA_256) {
        signature_size_ = 32;
      }

    case ProducerCallbacksOptions::INTEREST_INPUT:
      if (socket_option_value == VOID_HANDLER) {
        on_interest_input_ = VOID_HANDLER;
        return SOCKET_OPTION_SET;
      }

    case ProducerCallbacksOptions::INTEREST_DROP:
      if (socket_option_value == VOID_HANDLER) {
        on_interest_dropped_input_buffer_ = VOID_HANDLER;
        return SOCKET_OPTION_SET;
      }

    case ProducerCallbacksOptions::INTEREST_PASS:
      if (socket_option_value == VOID_HANDLER) {
        on_interest_inserted_input_buffer_ = VOID_HANDLER;
        return SOCKET_OPTION_SET;
      }

    case ProducerCallbacksOptions::CACHE_HIT:
      if (socket_option_value == VOID_HANDLER) {
        on_interest_satisfied_output_buffer_ = VOID_HANDLER;
        return SOCKET_OPTION_SET;
      }

    case ProducerCallbacksOptions::CACHE_MISS:
      if (socket_option_value == VOID_HANDLER) {
        on_interest_process_ = VOID_HANDLER;
        return SOCKET_OPTION_SET;
      }

    case ProducerCallbacksOptions::NEW_CONTENT_OBJECT:
      if (socket_option_value == VOID_HANDLER) {
        on_new_segment_ = VOID_HANDLER;
        return SOCKET_OPTION_SET;
      }

    case ProducerCallbacksOptions::CONTENT_OBJECT_SIGN:
      if (socket_option_value == VOID_HANDLER) {
        on_content_object_to_sign_ = VOID_HANDLER;
        return SOCKET_OPTION_SET;
      }

    case ProducerCallbacksOptions::CONTENT_OBJECT_READY:
      if (socket_option_value == VOID_HANDLER) {
        on_content_object_in_output_buffer_ = VOID_HANDLER;
        return SOCKET_OPTION_SET;
      }

    case ProducerCallbacksOptions::CONTENT_OBJECT_OUTPUT:
      if (socket_option_value == VOID_HANDLER) {
        on_content_object_output_ = VOID_HANDLER;
        return SOCKET_OPTION_SET;
      }

    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    double socket_option_value) {
  return SOCKET_OPTION_NOT_SET;
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    bool socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::MAKE_MANIFEST:
      making_manifest_ = socket_option_value;
      return SOCKET_OPTION_SET;

    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    Name socket_option_value) {
  return SOCKET_OPTION_NOT_SET;
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    std::list<Prefix> socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::NETWORK_NAME:
      served_namespaces_ = socket_option_value;
    default:
      return SOCKET_OPTION_NOT_SET;
  }

  return SOCKET_OPTION_SET;
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ProducerContentObjectCallback socket_option_value) {
  switch (socket_option_key) {
    case ProducerCallbacksOptions::NEW_CONTENT_OBJECT:
      on_new_segment_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case ProducerCallbacksOptions::CONTENT_OBJECT_SIGN:
      on_content_object_to_sign_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case ProducerCallbacksOptions::CONTENT_OBJECT_READY:
      on_content_object_in_output_buffer_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case ProducerCallbacksOptions::CONTENT_OBJECT_OUTPUT:
      on_content_object_output_ = socket_option_value;
      return SOCKET_OPTION_SET;

    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ProducerInterestCallback socket_option_value) {
  switch (socket_option_key) {
    case ProducerCallbacksOptions::INTEREST_INPUT:
      on_interest_input_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case ProducerCallbacksOptions::INTEREST_DROP:
      on_interest_dropped_input_buffer_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case ProducerCallbacksOptions::INTEREST_PASS:
      on_interest_inserted_input_buffer_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case ProducerCallbacksOptions::CACHE_HIT:
      on_interest_satisfied_output_buffer_ = socket_option_value;
      return SOCKET_OPTION_SET;

    case ProducerCallbacksOptions::CACHE_MISS:
      on_interest_process_ = socket_option_value;
      return SOCKET_OPTION_SET;

    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ProducerContentCallback socket_option_value) {
  switch (socket_option_key) {
    case ProducerCallbacksOptions::CONTENT_PRODUCED:
      on_content_produced_ = socket_option_value;
      return SOCKET_OPTION_SET;

    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ConsumerContentObjectCallback socket_option_value) {
  return SOCKET_OPTION_NOT_SET;
}

int ProducerSocket::setSocketOption(
    int socket_option_key,
    ConsumerContentObjectVerificationCallback socket_option_value) {
  return SOCKET_OPTION_NOT_SET;
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ConsumerInterestCallback socket_option_value) {
  return SOCKET_OPTION_NOT_SET;
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ConsumerContentCallback socket_option_value) {
  return SOCKET_OPTION_NOT_SET;
}

int ProducerSocket::setSocketOption(
    int socket_option_key, ConsumerManifestCallback socket_option_value) {
  return SOCKET_OPTION_NOT_SET;
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    HashAlgorithm socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::HASH_ALGORITHM:
      hash_algorithm_ = socket_option_value;
      return SOCKET_OPTION_SET;
    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    utils::CryptoSuite socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::CRYPTO_SUITE:
      crypto_suite_ = socket_option_value;
      return SOCKET_OPTION_SET;
    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int ProducerSocket::setSocketOption(
    int socket_option_key, const utils::Identity &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::IDENTITY:
      identity_.reset();
      identity_ = std::make_unique<utils::Identity>(socket_option_value);
      return SOCKET_OPTION_SET;
    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    const std::string &socket_option_value) {
  switch (socket_option_key) {
    case DataLinkOptions::OUTPUT_INTERFACE:
      output_interface_ = socket_option_value;
      portal_->setOutputInterface(output_interface_);
      return SOCKET_OPTION_SET;
  }

  return SOCKET_OPTION_NOT_SET;
}

int ProducerSocket::setSocketOption(
    int socket_option_key,
    interface::ConsumerTimerCallback socket_option_value) {
  return SOCKET_OPTION_NOT_SET;
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    uint32_t &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::INPUT_BUFFER_SIZE:
      socket_option_value = (int)input_buffer_capacity_;
      return SOCKET_OPTION_GET;

    case GeneralTransportOptions::OUTPUT_BUFFER_SIZE:
      socket_option_value = (uint32_t)output_buffer_.getLimit();
      return SOCKET_OPTION_GET;

    case GeneralTransportOptions::DATA_PACKET_SIZE:
      socket_option_value = (uint32_t)data_packet_size_;
      return SOCKET_OPTION_GET;

    case GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME:
      socket_option_value = content_object_expiry_time_;
      return SOCKET_OPTION_GET;

    case GeneralTransportOptions::SIGNATURE_TYPE:
      socket_option_value = signature_type_;
      return SOCKET_OPTION_GET;

    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    double &socket_option_value) {
  return SOCKET_OPTION_NOT_GET;
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    bool &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::MAKE_MANIFEST:
      socket_option_value = making_manifest_;
      return SOCKET_OPTION_GET;

    default:
      return SOCKET_OPTION_NOT_GET;
  }
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    Name &socket_option_value) {
  return SOCKET_OPTION_NOT_GET;
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    std::list<Prefix> &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::NETWORK_NAME:

      socket_option_value = served_namespaces_;
      return SOCKET_OPTION_GET;

    default:
      return SOCKET_OPTION_NOT_GET;
  }
}

int ProducerSocket::getSocketOption(
    int socket_option_key, ProducerContentObjectCallback &socket_option_value) {
  switch (socket_option_key) {
    case ProducerCallbacksOptions::NEW_CONTENT_OBJECT:
      socket_option_value = on_new_segment_;
      return SOCKET_OPTION_GET;

    case ProducerCallbacksOptions::CONTENT_OBJECT_SIGN:
      socket_option_value = on_content_object_to_sign_;
      return SOCKET_OPTION_GET;

    case ProducerCallbacksOptions::CONTENT_OBJECT_READY:
      socket_option_value = on_content_object_in_output_buffer_;
      return SOCKET_OPTION_GET;

    case ProducerCallbacksOptions::CONTENT_OBJECT_OUTPUT:
      socket_option_value = on_content_object_output_;
      return SOCKET_OPTION_GET;

    default:
      return SOCKET_OPTION_NOT_GET;
  }
}

int ProducerSocket::getSocketOption(
    int socket_option_key, ProducerContentCallback &socket_option_value) {
  switch (socket_option_key) {
    case ProducerCallbacksOptions::CONTENT_PRODUCED:
      socket_option_value = on_content_produced_;
      return SOCKET_OPTION_GET;

    default:
      return SOCKET_OPTION_NOT_GET;
  }
}

int ProducerSocket::getSocketOption(
    int socket_option_key, ProducerInterestCallback &socket_option_value) {
  switch (socket_option_key) {
    case ProducerCallbacksOptions::INTEREST_INPUT:
      socket_option_value = on_interest_input_;
      return SOCKET_OPTION_GET;

    case ProducerCallbacksOptions::INTEREST_DROP:
      socket_option_value = on_interest_dropped_input_buffer_;
      return SOCKET_OPTION_GET;

    case ProducerCallbacksOptions::INTEREST_PASS:
      socket_option_value = on_interest_inserted_input_buffer_;
      return SOCKET_OPTION_GET;

    case CACHE_HIT:
      socket_option_value = on_interest_satisfied_output_buffer_;
      return SOCKET_OPTION_GET;

    case CACHE_MISS:
      socket_option_value = on_interest_process_;
      return SOCKET_OPTION_GET;

    default:
      return SOCKET_OPTION_NOT_GET;
  }
}

int ProducerSocket::getSocketOption(
    int socket_option_key, ConsumerContentObjectCallback &socket_option_value) {
  return SOCKET_OPTION_NOT_GET;
}

int ProducerSocket::getSocketOption(
    int socket_option_key,
    ConsumerContentObjectVerificationCallback &socket_option_value) {
  return SOCKET_OPTION_NOT_GET;
}

int ProducerSocket::getSocketOption(
    int socket_option_key, ConsumerInterestCallback &socket_option_value) {
  return SOCKET_OPTION_NOT_GET;
}

int ProducerSocket::getSocketOption(
    int socket_option_key, ConsumerContentCallback &socket_option_value) {
  return SOCKET_OPTION_NOT_GET;
}

int ProducerSocket::getSocketOption(
    int socket_option_key, ConsumerManifestCallback &socket_option_value) {
  return SOCKET_OPTION_NOT_GET;
}

int ProducerSocket::getSocketOption(
    int socket_option_key, std::shared_ptr<Portal> &socket_option_value) {
  switch (socket_option_key) {
    case PORTAL:
      socket_option_value = portal_;
      return SOCKET_OPTION_GET;
  }

  return SOCKET_OPTION_NOT_GET;
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    IcnObserver **socket_option_value) {
  return SOCKET_OPTION_NOT_GET;
}

int ProducerSocket::setSocketOption(int socket_option_key,
                                    IcnObserver *socket_option_value) {
  return SOCKET_OPTION_NOT_SET;
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    HashAlgorithm &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::HASH_ALGORITHM:
      socket_option_value = hash_algorithm_;
      return SOCKET_OPTION_GET;
    default:
      return SOCKET_OPTION_NOT_GET;
  }
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    utils::CryptoSuite &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::HASH_ALGORITHM:
      socket_option_value = crypto_suite_;
      return SOCKET_OPTION_GET;
    default:
      return SOCKET_OPTION_NOT_GET;
  }
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    utils::Identity &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::IDENTITY:
      if (identity_) {
        socket_option_value = *identity_;
        return SOCKET_OPTION_SET;
      }
    default:
      return SOCKET_OPTION_NOT_SET;
  }
}

int ProducerSocket::getSocketOption(int socket_option_key,
                                    std::string &socket_option_value) {
  switch (socket_option_key) {
    case DataLinkOptions::OUTPUT_INTERFACE:
      socket_option_value = output_interface_;
      return SOCKET_OPTION_GET;
  }

  return SOCKET_OPTION_NOT_GET;
}

int ProducerSocket::getSocketOption(
    int socket_option_key,
    interface::ConsumerTimerCallback &socket_option_value) {
  return SOCKET_OPTION_NOT_GET;
}

}  // namespace interface

}  // end namespace transport
