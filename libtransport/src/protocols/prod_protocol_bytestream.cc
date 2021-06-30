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

#include <implementation/socket_producer.h>
#include <protocols/prod_protocol_bytestream.h>

#include <atomic>

namespace transport {

namespace protocol {

using namespace core;
using namespace implementation;

ByteStreamProductionProtocol::ByteStreamProductionProtocol(
    implementation::ProducerSocket *icn_socket)
    : ProductionProtocol(icn_socket) {}

ByteStreamProductionProtocol::~ByteStreamProductionProtocol() {
  stop();
  if (listening_thread_.joinable()) {
    listening_thread_.join();
  }
}

uint32_t ByteStreamProductionProtocol::produceDatagram(
    const Name &content_name, std::unique_ptr<utils::MemBuf> &&buffer) {
  throw errors::NotImplementedException();
}

uint32_t ByteStreamProductionProtocol::produceDatagram(const Name &content_name,
                                                       const uint8_t *buffer,
                                                       size_t buffer_size) {
  throw errors::NotImplementedException();
}

uint32_t ByteStreamProductionProtocol::produceStream(const Name &content_name,
                                                     const uint8_t *buffer,
                                                     size_t buffer_size,
                                                     bool is_last,
                                                     uint32_t start_offset) {
  if (!buffer_size) {
    return 0;
  }

  return produceStream(content_name,
                       utils::MemBuf::copyBuffer(buffer, buffer_size), is_last,
                       start_offset);
}

uint32_t ByteStreamProductionProtocol::produceStream(
    const Name &content_name, std::unique_ptr<utils::MemBuf> &&buffer,
    bool is_last, uint32_t start_offset) {
  if (TRANSPORT_EXPECT_FALSE(buffer->length() == 0)) {
    return 0;
  }

  Name name(content_name);

  // Get the atomic variables to ensure they keep the same value
  // during the production

  // Total size of the data packet
  uint32_t data_packet_size;
  socket_->getSocketOption(GeneralTransportOptions::DATA_PACKET_SIZE,
                           data_packet_size);

  // Expiry time
  uint32_t content_object_expiry_time;
  socket_->getSocketOption(GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
                           content_object_expiry_time);

  // Hash algorithm
  auth::CryptoHashType hash_algo;
  socket_->getSocketOption(GeneralTransportOptions::HASH_ALGORITHM, hash_algo);

  // Suffix calculation strategy
  core::NextSegmentCalculationStrategy _suffix_strategy;
  socket_->getSocketOption(GeneralTransportOptions::SUFFIX_STRATEGY,
                           _suffix_strategy);
  auto suffix_strategy = utils::SuffixStrategyFactory::getSuffixStrategy(
      _suffix_strategy, start_offset);

  auto buffer_size = buffer->length();
  int bytes_segmented = 0;
  std::size_t header_size;
  std::size_t manifest_header_size = 0;
  std::size_t signature_length = 0;
  std::uint32_t final_block_number = start_offset;
  uint64_t free_space_for_content = 0;

  core::Packet::Format format;
  std::shared_ptr<core::ContentObjectManifest> manifest;
  bool is_last_manifest = false;

  // TODO Manifest may still be used for indexing
  if (making_manifest_ && !signer_) {
    LOG(FATAL) << "Making manifests without setting producer identity.";
  }

  core::Packet::Format hf_format = core::Packet::Format::HF_UNSPEC;
  core::Packet::Format hf_format_ah = core::Packet::Format::HF_UNSPEC;

  if (name.getType() == HNT_CONTIGUOUS_V4 || name.getType() == HNT_IOV_V4) {
    hf_format = core::Packet::Format::HF_INET_TCP;
    hf_format_ah = core::Packet::Format::HF_INET_TCP_AH;
  } else if (name.getType() == HNT_CONTIGUOUS_V6 ||
             name.getType() == HNT_IOV_V6) {
    hf_format = core::Packet::Format::HF_INET6_TCP;
    hf_format_ah = core::Packet::Format::HF_INET6_TCP_AH;
  } else {
    throw errors::RuntimeException("Unknown name format.");
  }

  format = hf_format;
  if (making_manifest_) {
    manifest_header_size = core::Packet::getHeaderSizeFromFormat(
        signer_ ? hf_format_ah : hf_format,
        signer_ ? signer_->getSignatureFieldSize() : 0);
  } else if (signer_) {
    format = hf_format_ah;
    signature_length = signer_->getSignatureFieldSize();
  }

  header_size = core::Packet::getHeaderSizeFromFormat(format, signature_length);
  free_space_for_content = data_packet_size - header_size;
  uint32_t number_of_segments =
      uint32_t(std::ceil(double(buffer_size) / double(free_space_for_content)));
  if (free_space_for_content * number_of_segments < buffer_size) {
    number_of_segments++;
  }

  // TODO allocate space for all the headers
  if (making_manifest_) {
    uint32_t segment_in_manifest = static_cast<uint32_t>(
        std::floor(double(data_packet_size - manifest_header_size -
                          ContentObjectManifest::getManifestHeaderSize()) /
                   ContentObjectManifest::getManifestEntrySize()) -
        1.0);
    uint32_t number_of_manifests = static_cast<uint32_t>(
        std::ceil(float(number_of_segments) / segment_in_manifest));
    final_block_number += number_of_segments + number_of_manifests - 1;

    manifest.reset(ContentObjectManifest::createManifest(
        name.setSuffix(suffix_strategy->getNextManifestSuffix()),
        core::ManifestVersion::VERSION_1, core::ManifestType::INLINE_MANIFEST,
        hash_algo, is_last_manifest, name, _suffix_strategy,
        signer_ ? signer_->getSignatureFieldSize() : 0));
    manifest->setLifetime(content_object_expiry_time);

    if (is_last) {
      manifest->setFinalBlockNumber(final_block_number);
    } else {
      manifest->setFinalBlockNumber(utils::SuffixStrategy::INVALID_SUFFIX);
    }
  }

  for (unsigned int packaged_segments = 0;
       packaged_segments < number_of_segments; packaged_segments++) {
    if (making_manifest_) {
      if (manifest->estimateManifestSize(2) >
          data_packet_size - manifest_header_size) {
        manifest->encode();

        // If identity set, sign manifest
        if (signer_) {
          signer_->signPacket(manifest.get());
        }

        // Send the current manifest
        passContentObjectToCallbacks(manifest);

        DLOG_IF(INFO, VLOG_IS_ON(3)) << "Send manifest " << manifest->getName();

        // Send content objects stored in the queue
        while (!content_queue_.empty()) {
          passContentObjectToCallbacks(content_queue_.front());
          DLOG_IF(INFO, VLOG_IS_ON(3))
              << "Send content " << content_queue_.front()->getName();
          content_queue_.pop();
        }

        // Create new manifest. The reference to the last manifest has been
        // acquired in the passContentObjectToCallbacks function, so we can
        // safely release this reference
        manifest.reset(ContentObjectManifest::createManifest(
            name.setSuffix(suffix_strategy->getNextManifestSuffix()),
            core::ManifestVersion::VERSION_1,
            core::ManifestType::INLINE_MANIFEST, hash_algo, is_last_manifest,
            name, _suffix_strategy,
            signer_ ? signer_->getSignatureFieldSize() : 0));

        manifest->setLifetime(content_object_expiry_time);
        manifest->setFinalBlockNumber(
            is_last ? final_block_number
                    : utils::SuffixStrategy::INVALID_SUFFIX);
      }
    }

    auto content_suffix = suffix_strategy->getNextContentSuffix();
    auto content_object = std::make_shared<ContentObject>(
        name.setSuffix(content_suffix), format,
        signer_ && !making_manifest_ ? signer_->getSignatureFieldSize() : 0);
    content_object->setLifetime(content_object_expiry_time);

    auto b = buffer->cloneOne();
    b->trimStart(free_space_for_content * packaged_segments);
    b->trimEnd(b->length());

    if (TRANSPORT_EXPECT_FALSE(packaged_segments == number_of_segments - 1)) {
      b->append(buffer_size - bytes_segmented);
      bytes_segmented += (int)(buffer_size - bytes_segmented);

      if (is_last && making_manifest_) {
        is_last_manifest = true;
      } else if (is_last) {
        content_object->setRst();
      }

    } else {
      b->append(free_space_for_content);
      bytes_segmented += (int)(free_space_for_content);
    }

    content_object->appendPayload(std::move(b));

    if (making_manifest_) {
      using namespace std::chrono_literals;
      auth::CryptoHash hash = content_object->computeDigest(hash_algo);
      manifest->addSuffixHash(content_suffix, hash);
      content_queue_.push(content_object);
    } else {
      if (signer_) {
        signer_->signPacket(content_object.get());
      }
      passContentObjectToCallbacks(content_object);
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "Send content " << content_object->getName();
    }
  }

  if (making_manifest_) {
    if (is_last_manifest) {
      manifest->setFinalManifest(is_last_manifest);
    }

    manifest->encode();

    if (signer_) {
      signer_->signPacket(manifest.get());
    }

    passContentObjectToCallbacks(manifest);
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Send manifest " << manifest->getName();

    while (!content_queue_.empty()) {
      passContentObjectToCallbacks(content_queue_.front());
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "Send content " << content_queue_.front()->getName();
      content_queue_.pop();
    }
  }

  portal_->getIoService().post([this]() {
    std::shared_ptr<ContentObject> co;
    while (object_queue_for_callbacks_.pop(co)) {
      if (*on_new_segment_) {
        on_new_segment_->operator()(*socket_->getInterface(), *co);
      }

      if (*on_content_object_to_sign_) {
        on_content_object_to_sign_->operator()(*socket_->getInterface(), *co);
      }

      if (*on_content_object_in_output_buffer_) {
        on_content_object_in_output_buffer_->operator()(
            *socket_->getInterface(), *co);
      }

      if (*on_content_object_output_) {
        on_content_object_output_->operator()(*socket_->getInterface(), *co);
      }
    }
  });

  portal_->getIoService().dispatch([this, buffer_size]() {
    if (*on_content_produced_) {
      on_content_produced_->operator()(*socket_->getInterface(),
                                       std::make_error_code(std::errc(0)),
                                       buffer_size);
    }
  });

  return suffix_strategy->getTotalCount();
}

void ByteStreamProductionProtocol::scheduleSendBurst() {
  portal_->getIoService().post([this]() {
    std::shared_ptr<ContentObject> co;

    for (uint32_t i = 0; i < burst_size; i++) {
      if (object_queue_for_callbacks_.pop(co)) {
        if (*on_new_segment_) {
          on_new_segment_->operator()(*socket_->getInterface(), *co);
        }

        if (*on_content_object_to_sign_) {
          on_content_object_to_sign_->operator()(*socket_->getInterface(), *co);
        }

        if (*on_content_object_in_output_buffer_) {
          on_content_object_in_output_buffer_->operator()(
              *socket_->getInterface(), *co);
        }

        if (*on_content_object_output_) {
          on_content_object_output_->operator()(*socket_->getInterface(), *co);
        }
      } else {
        break;
      }
    }
  });
}

void ByteStreamProductionProtocol::passContentObjectToCallbacks(
    const std::shared_ptr<ContentObject> &content_object) {
  output_buffer_.insert(content_object);
  portal_->sendContentObject(*content_object);
  object_queue_for_callbacks_.push(std::move(content_object));

  if (object_queue_for_callbacks_.size() >= burst_size) {
    scheduleSendBurst();
  }
}

void ByteStreamProductionProtocol::onInterest(Interest &interest) {
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Received interest for " << interest.getName();
  if (*on_interest_input_) {
    on_interest_input_->operator()(*socket_->getInterface(), interest);
  }

  const std::shared_ptr<ContentObject> content_object =
      output_buffer_.find(interest.getName());

  if (content_object) {
    if (*on_interest_satisfied_output_buffer_) {
      on_interest_satisfied_output_buffer_->operator()(*socket_->getInterface(),
                                                       interest);
    }

    if (*on_content_object_output_) {
      on_content_object_output_->operator()(*socket_->getInterface(),
                                            *content_object);
    }

    portal_->sendContentObject(*content_object);
  } else {
    if (*on_interest_process_) {
      on_interest_process_->operator()(*socket_->getInterface(), interest);
    }
  }
}

void ByteStreamProductionProtocol::onError(std::error_code ec) {}

}  // namespace protocol
}  // end namespace transport
