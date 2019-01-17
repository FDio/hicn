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

#include <hicn/transport/errors/not_implemented_exception.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/protocols/vegas.h>
#include <hicn/transport/utils/literals.h>

#include <cmath>

namespace transport {

namespace protocol {

using namespace interface;

VegasTransportProtocol::VegasTransportProtocol(BaseSocket *icnet_socket)
    : TransportProtocol(icnet_socket),
      is_final_block_number_discovered_(false),
      final_block_number_(std::numeric_limits<uint32_t>::max()),
      last_reassembled_segment_(0),
      content_buffer_size_(0),
      current_window_size_(default_values::min_window_size),
      interests_in_flight_(0),
      next_suffix_(0),
      interest_retransmissions_(1 << default_values::log_2_default_buffer_size),
      interest_timepoints_(1 << default_values::log_2_default_buffer_size),
      retx_count_(0),
      receive_buffer_(1 << default_values::log_2_default_buffer_size),
      unverified_segments_(1 << default_values::log_2_default_buffer_size),
      verified_manifests_(1 << default_values::log_2_default_buffer_size),
      mask_((1 << default_values::log_2_default_buffer_size) - 1),
      incremental_suffix_index_(0),
      suffix_queue_completed_(false),
      download_with_manifest_(false),
      next_manifest_interval_(0_U16),
      interest_tx_(0),
      interest_count_(0),
      byte_count_(0),
      average_rtt_(0.0) {
  portal_ = socket_->portal_;
  incremental_suffix_index_++;
}

VegasTransportProtocol::~VegasTransportProtocol() { stop(); }

void VegasTransportProtocol::reset() {
  portal_->setConsumerCallback(this);

  is_final_block_number_discovered_ = false;
  interest_pool_index_ = 0;
  final_block_number_ = std::numeric_limits<uint32_t>::max();
  next_suffix_ = 0;
  interests_in_flight_ = 0;
  last_reassembled_segment_ = 0;
  content_buffer_size_ = 0;
  content_buffer_->clear();
  interest_retransmissions_.clear();
  interest_retransmissions_.resize(
      1 << default_values::log_2_default_buffer_size, 0);
  interest_timepoints_.clear();
  interest_timepoints_.resize(1 << default_values::log_2_default_buffer_size,
                              std::chrono::steady_clock::time_point());
  receive_buffer_.clear();
  unverified_segments_.clear();
  verified_manifests_.clear();
  next_manifest_interval_ = 0;
  next_manifest_ = 0;
  download_with_manifest_ = false;
  incremental_suffix_index_ = 0;

  interest_tx_ = 0;
  interest_count_ = 0;
  byte_count_ = 0;
  average_rtt_ = 0;

  // asio::io_service &io_service = portal_->getIoService();

  // if (io_service.stopped()) {
  //   io_service.reset();
  // }
}

void VegasTransportProtocol::start(
    utils::SharableVector<uint8_t> &content_buffer) {

  if(is_running_)
    return;

  socket_->t0_ = std::chrono::steady_clock::now();

  is_running_ = true;
  content_buffer_ = content_buffer.shared_from_this();

  reset();

  sendInterest(next_suffix_++);
  portal_->runEventsLoop();
  removeAllPendingInterests();
  is_running_ = false;

}

void VegasTransportProtocol::resume(){
  if(is_running_)
    return;

  is_running_ = true;
  sendInterest(next_suffix_++); 
  portal_->runEventsLoop();
  removeAllPendingInterests();
  is_running_ = false;
}

void VegasTransportProtocol::sendInterest(std::uint64_t next_suffix) {
  auto interest = getInterest();
  socket_->network_name_.setSuffix(next_suffix);
  interest->setName(socket_->network_name_);

  interest->setLifetime(uint32_t(socket_->interest_lifetime_));

  if (socket_->on_interest_output_ != VOID_HANDLER) {
    socket_->on_interest_output_(*socket_, *interest);
  }

  if (TRANSPORT_EXPECT_FALSE(!is_running_)) {
    return;
  }

  interests_in_flight_++;
  interest_retransmissions_[next_suffix & mask_] = 0;
  interest_timepoints_[next_suffix & mask_] = std::chrono::steady_clock::now();

  using namespace std::placeholders;
  portal_->sendInterest(std::move(interest));
}

void VegasTransportProtocol::stop() {
  is_running_ = false;
  portal_->stopEventsLoop();
}

void VegasTransportProtocol::onContentSegment(
    Interest::Ptr &&interest, ContentObject::Ptr &&content_object) {
  uint32_t incremental_suffix = content_object->getName().getSuffix();
  bool virtual_download = socket_->virtual_download_;

  if (verifyContentObject(*content_object)) {
    byte_count_ += content_object->getPayload().length();

    if (TRANSPORT_EXPECT_FALSE(content_object->testRst())) {
      is_final_block_number_discovered_ = true;
      final_block_number_ = incremental_suffix;
    }

    if (!virtual_download) {
      receive_buffer_.emplace(
          std::make_pair(incremental_suffix, std::move(content_object)));
      reassemble();
    } else if (TRANSPORT_EXPECT_FALSE(is_final_block_number_discovered_ &&
                                      incremental_suffix ==
                                          final_block_number_)) {
      returnContentToUser();
    }
  } else {
    unverified_segments_.emplace(
        std::make_pair(incremental_suffix, std::move(content_object)));
  }
}

void VegasTransportProtocol::afterContentReception(
    const Interest &interest, const ContentObject &content_object) {
  increaseWindow();
}

void VegasTransportProtocol::afterDataUnsatisfied(uint64_t segment) {
  decreaseWindow();
}

void VegasTransportProtocol::scheduleNextInterests() {
  if (is_running_) {
    uint32_t next_suffix;
    while (interests_in_flight_ < current_window_size_) {
      if (download_with_manifest_) {
        if (suffix_queue_.size() * 2 < current_window_size_ &&
            next_manifest_ < final_block_number_ && next_manifest_interval_) {
          next_manifest_ += next_manifest_interval_;
          sendInterest(next_manifest_);
          continue;
        }

        if (suffix_queue_.pop(next_suffix)) {
          //          next_suffix = suffix_queue_.front();
          sendInterest(next_suffix);
          //          suffix_queue_.pop_front();
        } else {
          if (!suffix_queue_completed_) {
            TRANSPORT_LOGE("Empty queue!!!!!!");
          }
          break;
        }
      } else {
        if (is_final_block_number_discovered_) {
          if (next_suffix_ > final_block_number_) {
            return;
          }
        }

        sendInterest(next_suffix_++);
      }
    }
  }
}

void VegasTransportProtocol::decreaseWindow() {
  if (current_window_size_ > socket_->min_window_size_) {
    current_window_size_ = std::ceil(current_window_size_ / 2);
    socket_->current_window_size_ = current_window_size_;
  }
}

void VegasTransportProtocol::increaseWindow() {
  if (current_window_size_ < socket_->max_window_size_) {
    current_window_size_++;
    socket_->max_window_size_ = current_window_size_;
  }
};

void VegasTransportProtocol::changeInterestLifetime(uint64_t segment) {
  std::chrono::steady_clock::duration duration =
      std::chrono::steady_clock::now() - interest_timepoints_[segment];
  rtt_estimator_.addMeasurement(
      std::chrono::duration_cast<std::chrono::microseconds>(duration));

  RtoEstimator::Duration rto = rtt_estimator_.computeRto();
  std::chrono::milliseconds lifetime =
      std::chrono::duration_cast<std::chrono::milliseconds>(rto);

  socket_->interest_lifetime_ = lifetime.count();
}

void VegasTransportProtocol::returnContentToUser() {
  if (socket_->on_payload_retrieved_ != VOID_HANDLER) {
    socket_->on_payload_retrieved_(*socket_, byte_count_,
                                   std::make_error_code(std::errc(0)));
  }

  stop();
}

void VegasTransportProtocol::onManifest(
    std::unique_ptr<ContentObjectManifest> &&manifest) {
  if (TRANSPORT_EXPECT_FALSE(!is_running_)) {
    return;
  }

  download_with_manifest_ = true;

  uint32_t segment = manifest->getName().getSuffix();

  if (verifyManifest(*manifest)) {
    manifest->decode();

    if (TRANSPORT_EXPECT_TRUE(manifest->getVersion() ==
                              core::ManifestVersion::VERSION_1)) {
      switch (manifest->getManifestType()) {
        case core::ManifestType::INLINE_MANIFEST: {
          auto _it = manifest->getSuffixList().begin();
          auto _end = --manifest->getSuffixList().end();

          if (TRANSPORT_EXPECT_FALSE(manifest->isFinalManifest())) {
            _end++;
          }

          // Get final block number
          is_final_block_number_discovered_ = true;
          final_block_number_ = manifest->getFinalBlockNumber();

          for (; _it != _end; _it++) {
            suffix_hash_map_[_it->first] = std::make_pair(
                std::vector<uint8_t>(_it->second, _it->second + 32),
                manifest->getHashAlgorithm());
            suffix_queue_.push(_it->first);
          }

          next_manifest_interval_ = manifest->getSuffixList().size();

          if (manifest->isFinalManifest()) {
            suffix_queue_completed_ = true;
            // Give it a try
            if (verifier_thread_) {
              asio::io_service &io_service = portal_->getIoService();
              io_service.post([this]() { scheduleNextInterests(); });
            }
          }

          break;
        }
        case core::ManifestType::FLIC_MANIFEST: {
          throw errors::NotImplementedException();
        }
        case core::ManifestType::FINAL_CHUNK_NUMBER: {
          throw errors::NotImplementedException();
        }
      }
    }

    if (!socket_->virtual_download_) {
      receive_buffer_.emplace(
          std::make_pair(segment, std::move(manifest->getPacket())));
      reassemble();
    } else {
      if (segment >= final_block_number_) {
        stop();
      }
    }
  }
}

bool VegasTransportProtocol::verifyManifest(
    const ContentObjectManifest &manifest) {
  if (!socket_->verify_signature_) {
    return true;
  }

  bool is_data_secure = false;

  if (socket_->on_content_object_verification_ == VOID_HANDLER) {
    is_data_secure = static_cast<bool>(socket_->verifier_.verify(manifest));
  } else if (socket_->on_content_object_verification_(*socket_, manifest)) {
    is_data_secure = true;
  }

  if (TRANSPORT_EXPECT_FALSE(!is_data_secure)) {
    TRANSPORT_LOGE("Verification failed for %s\n",
                   manifest.getName().toString().c_str());
  }

  return is_data_secure;
}

// TODO Add the name in the digest computation!
void VegasTransportProtocol::onContentObject(
    Interest::Ptr &&interest, ContentObject::Ptr &&content_object) {
  uint32_t incremental_suffix = content_object->getName().getSuffix();

  std::chrono::microseconds rtt;
  Time now = std::chrono::steady_clock::now();
  std::chrono::steady_clock::duration duration =
      now - interest_timepoints_[incremental_suffix & mask_];
  rtt = std::chrono::duration_cast<std::chrono::microseconds>(duration);

  average_rtt_ = (0.7 * average_rtt_) + (0.3 * (double)rtt.count());

  if (socket_->on_timer_expires_ != VOID_HANDLER) {
    auto dt = std::chrono::duration_cast<TimeDuration>(now - socket_->t0_);
    if (dt.count() > socket_->timer_interval_milliseconds_) {
      socket_->on_timer_expires_(*socket_, byte_count_, dt,
                                 current_window_size_, retx_count_,
                                 std::round(average_rtt_));
      socket_->t0_ = std::chrono::steady_clock::now();
    }
  }

  interests_in_flight_--;

  if (TRANSPORT_EXPECT_FALSE(!is_running_ || incremental_suffix == ~0_U64 ||
                             receive_buffer_.find(incremental_suffix) !=
                                 receive_buffer_.end())) {
    return;
  }

  changeInterestLifetime(incremental_suffix);

  if (socket_->on_content_object_input_ != VOID_HANDLER) {
    socket_->on_content_object_input_(*socket_, *content_object);
  }

  if (socket_->on_interest_satisfied_ != VOID_HANDLER) {
    socket_->on_interest_satisfied_(*socket_, *interest);
  }

  if (!interest_retransmissions_[incremental_suffix & mask_]) {
    afterContentReception(*interest, *content_object);
  }

  if (TRANSPORT_EXPECT_FALSE(content_object->getPayloadType() ==
                             PayloadType::MANIFEST)) {
    // TODO Fix manifest!!
    auto manifest =
        std::make_unique<ContentObjectManifest>(std::move(content_object));

    if (verifier_thread_ && incremental_suffix != 0) {
      // verifier_thread_->add(std::bind(&VegasTransportProtocol::onManifest,
      // this, std::move(manifest)));
    } else {
      onManifest(std::move(manifest));
    }
  } else if (content_object->getPayloadType() == PayloadType::CONTENT_OBJECT) {
    if (verifier_thread_) {
      // verifier_thread_->add(std::bind(&VegasTransportProtocol::onContentSegment,
      // this, std::move(content_object)));
    } else {
      onContentSegment(std::move(interest), std::move(content_object));
    }
  }

  scheduleNextInterests();
}

bool VegasTransportProtocol::verifyContentObject(
    const ContentObject &content_object) {
  if (!dynamic_cast<ConsumerSocket *>(socket_)->verify_signature_) {
    return true;
  }

  uint64_t segment = content_object.getName().getSuffix();

  bool ret = false;

  if (download_with_manifest_) {
    auto it = suffix_hash_map_.find(segment);
    if (it != suffix_hash_map_.end()) {
      auto hash_type = static_cast<utils::CryptoHashType>(it->second.second);
      auto data_packet_digest = content_object.computeDigest(it->second.second);
      auto data_packet_digest_bytes =
          data_packet_digest.getDigest<uint8_t>().data();
      std::vector<uint8_t> &manifest_digest_bytes = it->second.first;

      if (utils::CryptoHash::compareBinaryDigest(data_packet_digest_bytes,
                                                 manifest_digest_bytes.data(),
                                                 hash_type)) {
        suffix_hash_map_.erase(it);
        ret = true;
      } else {
        throw errors::RuntimeException(
            "Verification failure policy has to be implemented.");
      }
    }
  } else {
    ret = static_cast<bool>(
        dynamic_cast<ConsumerSocket *>(socket_)->verifier_.verify(
            content_object));

    if (!ret) {
      throw errors::RuntimeException(
          "Verification failure policy has to be implemented.");
    }
  }

  return ret;
  ;
}

void VegasTransportProtocol::onTimeout(Interest::Ptr &&interest) {
  TRANSPORT_LOGW("Timeout on %s", interest->getName().toString().c_str());

  if (TRANSPORT_EXPECT_FALSE(!is_running_)) {
    return;
  }

  interests_in_flight_--;

  uint64_t segment = interest->getName().getSuffix();

  // Do not retransmit interests asking contents that do not exist.
  if (is_final_block_number_discovered_) {
    if (segment > final_block_number_) {
      return;
    }
  }

  if (socket_->on_interest_timeout_ != VOID_HANDLER) {
    socket_->on_interest_timeout_(*socket_, *interest);
  }

  afterDataUnsatisfied(segment);

  if (TRANSPORT_EXPECT_TRUE(interest_retransmissions_[segment & mask_] <
                            socket_->max_retransmissions_)) {
    retx_count_++;

    if (socket_->on_interest_retransmission_ != VOID_HANDLER) {
      socket_->on_interest_retransmission_(*socket_, *interest);
    }

    if (socket_->on_interest_output_ != VOID_HANDLER) {
      socket_->on_interest_output_(*socket_, *interest);
    }

    if (!is_running_) {
      return;
    }

    // retransmit
    interests_in_flight_++;
    interest_retransmissions_[segment & mask_]++;

    using namespace std::placeholders;
    portal_->sendInterest(std::move(interest));
  } else {
    TRANSPORT_LOGE("Stop: reached max retx limit.");
    partialDownload();
    stop();
  }
}

void VegasTransportProtocol::copyContent(const ContentObject &content_object) {
  Array a = content_object.getPayload();

  content_buffer_->insert(content_buffer_->end(), (uint8_t *)a.data(),
                          (uint8_t *)a.data() + a.length());

  bool download_completed =
      is_final_block_number_discovered_ &&
      content_object.getName().getSuffix() == final_block_number_;

  if (TRANSPORT_EXPECT_FALSE(download_completed || !is_running_)) {
    // asio::io_service& io_service = portal_->getIoService();
    // io_service.post([this] () {
    returnContentToUser();
    // });
  }
}

void VegasTransportProtocol::reassemble() {
  uint64_t index = last_reassembled_segment_;
  auto it = receive_buffer_.find(index);

  do {
    if (it->second->getPayloadType() == PayloadType::CONTENT_OBJECT) {
      copyContent(*it->second);
      receive_buffer_.erase(it);
    }

    index = ++last_reassembled_segment_;
    it = receive_buffer_.find(index);
  } while (it != receive_buffer_.end());
}

void VegasTransportProtocol::partialDownload() {
  if (!socket_->virtual_download_) {
    reassemble();
  }

  if (socket_->on_payload_retrieved_ != VOID_HANDLER) {
    socket_->on_payload_retrieved_(
        *socket_, byte_count_,
        std::make_error_code(std::errc(std::errc::io_error)));
  }
}

// TODO Check vegas protocol
// void VegasTransportProtocol::checkForFastRetransmission(const Interest
// &interest) {
//   uint64_t segNumber = interest.getName().getSuffix();
//   received_segments_[segNumber] = true;
//   fast_retransmitted_segments.erase(segNumber);

//   uint64_t possibly_lost_segment = 0;
//   uint64_t highest_received_segment = received_segments_.rbegin()->first;

//   for (uint64_t i = 0; i <= highest_received_segment; i++) {
//     if (received_segments_.find(i) == received_segments_.end()) {
//       if (fast_retransmitted_segments.find(i) ==
//       fast_retransmitted_segments.end()) {
//         possibly_lost_segment = i;
//         uint8_t out_of_order_segments = 0;
//         for (uint64_t j = i; j <= highest_received_segment; j++) {
//           if (received_segments_.find(j) != received_segments_.end()) {
//             out_of_order_segments++;
//             if (out_of_order_segments >=
//             default_values::max_out_of_order_segments) {
//               fast_retransmitted_segments[possibly_lost_segment] = true;
//               fastRetransmit(interest, possibly_lost_segment);
//             }
//           }
//         }
//       }
//     }
//   }
// }

// void VegasTransportProtocol::fastRetransmit(const Interest &interest,
// uint32_t chunk_number) {
//   if (interest_retransmissions_[chunk_number & mask_] <
//       socket_->max_retransmissions_) {
//     Name name = interest.getName();
//     name.setSuffix(chunk_number);

//     std::shared_ptr<Interest> retx_interest =
//     std::make_shared<Interest>(name);

//     if (socket_->on_interest_retransmission_ != VOID_HANDLER) {
//       socket_->on_interest_retransmission_(*socket_, *retx_interest);
//     }

//     if (socket_->on_interest_output_ != VOID_HANDLER) {
//       socket_->on_interest_output_(*socket_, *retx_interest);
//     }

//     if (!is_running_) {
//       return;
//     }

//     interests_in_flight_++;
//     interest_retransmissions_[chunk_number & mask_]++;

//     using namespace std::placeholders;
//     portal_->sendInterest(std::move(retx_interest));
//   }
// }

void VegasTransportProtocol::removeAllPendingInterests() { portal_->clear(); }

}  // end namespace protocol

}  // namespace transport
