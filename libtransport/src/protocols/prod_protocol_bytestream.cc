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

ByteStreamProductionProtocol::~ByteStreamProductionProtocol() { stop(); }

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

  // Total size of the data packet
  uint32_t data_packet_size;
  socket_->getSocketOption(GeneralTransportOptions::DATA_PACKET_SIZE,
                           data_packet_size);

  // Maximum size of a segment
  uint32_t max_segment_size;
  socket_->getSocketOption(GeneralTransportOptions::MAX_SEGMENT_SIZE,
                           max_segment_size);

  // Expiry time
  uint32_t content_object_expiry_time;
  socket_->getSocketOption(GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
                           content_object_expiry_time);

  // Hash algorithm
  auth::CryptoHashType hash_algo;
  socket_->getSocketOption(GeneralTransportOptions::HASH_ALGORITHM, hash_algo);

  // Suffix calculation strategy
  std::shared_ptr<utils::SuffixStrategy> suffix_strategy;
  socket_->getSocketOption(GeneralTransportOptions::SUFFIX_STRATEGY,
                           suffix_strategy);
  suffix_strategy->reset(start_offset);

  // Default format
  core::Packet::Format default_format;
  socket_->getSocketOption(GeneralTransportOptions::PACKET_FORMAT,
                           default_format);

  Name name(content_name);
  size_t buffer_size = buffer->length();
  size_t signature_length = signer_->getSignatureFieldSize();
  uint32_t final_block_number = start_offset;

  // Content-related
  core::Packet::Format content_format;
  uint32_t content_header_size;
  uint64_t content_free_space;
  uint32_t nb_segments;
  int bytes_segmented = 0;

  // Manifest-related
  core::Packet::Format manifest_format;
  uint32_t manifest_header_size;
  uint64_t manifest_free_space;
  uint32_t nb_manifests;
  std::shared_ptr<core::ContentObjectManifest> manifest;
  uint32_t manifest_capacity = making_manifest_;
  bool is_last_manifest = false;
  ParamsBytestream transport_params;

  manifest_format = Packet::toAHFormat(default_format);
  content_format =
      !making_manifest_ ? Packet::toAHFormat(default_format) : default_format;

  content_header_size =
      core::Packet::getHeaderSizeFromFormat(content_format, signature_length);
  manifest_header_size =
      core::Packet::getHeaderSizeFromFormat(manifest_format, signature_length);
  content_free_space =
      std::min(max_segment_size, data_packet_size - content_header_size);
  manifest_free_space =
      std::min(max_segment_size, data_packet_size - manifest_header_size);

  // Compute the number of segments the data will be split into
  nb_segments =
      uint32_t(std::ceil(double(buffer_size) / double(content_free_space)));
  if (content_free_space * nb_segments < buffer_size) {
    nb_segments++;
  }

  if (making_manifest_) {
    nb_manifests = static_cast<uint32_t>(
        std::ceil(float(nb_segments) / manifest_capacity));
    final_block_number += nb_segments + nb_manifests - 1;
    transport_params.final_segment =
        is_last ? final_block_number : utils::SuffixStrategy::MAX_SUFFIX;

    manifest.reset(ContentObjectManifest::createManifest(
        manifest_format,
        name.setSuffix(suffix_strategy->getNextManifestSuffix()),
        core::ManifestVersion::VERSION_1, core::ManifestType::INLINE_MANIFEST,
        is_last_manifest, name, hash_algo, signature_length));

    manifest->setLifetime(content_object_expiry_time);
    manifest->setParamsBytestream(transport_params);
  }

  auto self = shared_from_this();
  for (unsigned int packaged_segments = 0; packaged_segments < nb_segments;
       packaged_segments++) {
    if (making_manifest_) {
      if (manifest->estimateManifestSize(1) > manifest_free_space) {
        manifest->encode();
        signer_->signPacket(manifest.get());

        // Send the current manifest
        passContentObjectToCallbacks(manifest, self);
        DLOG_IF(INFO, VLOG_IS_ON(3)) << "Send manifest " << manifest->getName();

        // Send content objects stored in the queue
        while (!content_queue_.empty()) {
          passContentObjectToCallbacks(content_queue_.front(), self);
          DLOG_IF(INFO, VLOG_IS_ON(3))
              << "Send content " << content_queue_.front()->getName();
          content_queue_.pop();
        }

        // Create new manifest. The reference to the last manifest has been
        // acquired in the passContentObjectToCallbacks function, so we can
        // safely release this reference.
        manifest.reset(ContentObjectManifest::createManifest(
            manifest_format,
            name.setSuffix(suffix_strategy->getNextManifestSuffix()),
            core::ManifestVersion::VERSION_1,
            core::ManifestType::INLINE_MANIFEST, is_last_manifest, name,
            hash_algo, signature_length));

        manifest->setLifetime(content_object_expiry_time);
        manifest->setParamsBytestream(transport_params);
      }
    }

    // Create content object
    uint32_t content_suffix = suffix_strategy->getNextContentSuffix();
    auto content_object = std::make_shared<ContentObject>(
        name.setSuffix(content_suffix), content_format,
        !making_manifest_ ? signature_length : 0);
    content_object->setLifetime(content_object_expiry_time);

    auto b = buffer->cloneOne();
    b->trimStart(content_free_space * packaged_segments);
    b->trimEnd(b->length());

    // Segment the input data
    if (TRANSPORT_EXPECT_FALSE(packaged_segments == nb_segments - 1)) {
      b->append(buffer_size - bytes_segmented);
      bytes_segmented += (int)(buffer_size - bytes_segmented);

      if (is_last && making_manifest_) {
        is_last_manifest = true;
      } else if (is_last) {
        content_object->setLast();
      }

    } else {
      b->append(content_free_space);
      bytes_segmented += (int)(content_free_space);
    }

    // Set the segmented data as payload
    content_object->appendPayload(std::move(b));

    // Either we sign the content object or we save its hash into the current
    // manifest
    if (making_manifest_) {
      auth::CryptoHash hash = content_object->computeDigest(hash_algo);
      manifest->addSuffixHash(content_suffix, hash);
      content_queue_.push(content_object);
    } else {
      signer_->signPacket(content_object.get());
      passContentObjectToCallbacks(content_object, self);
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "Send content " << content_object->getName();
    }
  }

  // We send the manifest that hasn't been fully filled yet
  if (making_manifest_) {
    if (is_last_manifest) {
      manifest->setIsLast(is_last_manifest);
    }

    manifest->encode();
    signer_->signPacket(manifest.get());

    passContentObjectToCallbacks(manifest, self);
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Send manifest " << manifest->getName();

    while (!content_queue_.empty()) {
      passContentObjectToCallbacks(content_queue_.front(), self);
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "Send content " << content_queue_.front()->getName();
      content_queue_.pop();
    }
  }

  portal_->getThread().add([this, self]() {
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

  portal_->getThread().add([this, buffer_size, self]() {
    if (*on_content_produced_) {
      on_content_produced_->operator()(*socket_->getInterface(),
                                       std::make_error_code(std::errc(0)),
                                       buffer_size);
    }
  });

  return suffix_strategy->getTotalCount();
}

void ByteStreamProductionProtocol::scheduleSendBurst(
    const std::shared_ptr<ByteStreamProductionProtocol> &self) {
  portal_->getThread().add([this, self]() {
    ContentObject::Ptr co;

    for (uint32_t i = 0; i < burst_size; i++) {
      if (object_queue_for_callbacks_.pop(co)) {
        if (*on_new_segment_) {
          on_new_segment_->operator()(*socket_->getInterface(), *co);
        }

        if (*on_content_object_to_sign_) {
          on_content_object_to_sign_->operator()(*socket_->getInterface(), *co);
        }

        output_buffer_.insert(co);

        if (*on_content_object_in_output_buffer_) {
          on_content_object_in_output_buffer_->operator()(
              *socket_->getInterface(), *co);
        }

        portal_->sendContentObject(*co);

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
    const std::shared_ptr<ContentObject> &content_object,
    const std::shared_ptr<ByteStreamProductionProtocol> &self) {
  object_queue_for_callbacks_.push(std::move(content_object));

  if (object_queue_for_callbacks_.size() >= burst_size) {
    scheduleSendBurst(self);
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

}  // namespace protocol
}  // end namespace transport
