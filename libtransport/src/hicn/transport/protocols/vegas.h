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

#include <hicn/transport/protocols/protocol.h>
#include <hicn/transport/protocols/vegas_rto_estimator.h>
#include <hicn/transport/utils/event_thread.h>
#include <hicn/transport/utils/ring_buffer.h>
#include <hicn/transport/utils/sharable_vector.h>

#include <map>

namespace transport {

namespace protocol {

typedef utils::CircularFifo<uint32_t, 1024 * 128> SuffixQueue;
typedef std::chrono::time_point<std::chrono::steady_clock> Time;
typedef std::chrono::milliseconds TimeDuration;

class VegasTransportProtocol : public TransportProtocol {
 public:
  VegasTransportProtocol(interface::BaseSocket *icnet_socket);

  virtual ~VegasTransportProtocol();

  virtual void start(utils::SharableVector<uint8_t> &content_buffer) override;

  void stop() override;

  void resume() override;

 protected:
  void reset();

  void sendInterest(std::uint64_t next_suffix);

  void onContentSegment(Interest::Ptr &&interest,
                        ContentObject::Ptr &&content_object);

  bool verifyContentObject(const ContentObject &content_object);

  bool verifyManifest(const interface::ContentObjectManifest &manifest);

  virtual void onTimeout(Interest::Ptr &&interest) override;

  void onManifest(std::unique_ptr<interface::ContentObjectManifest> &&manifest);

  void onContentObject(Interest::Ptr &&interest,
                       ContentObject::Ptr &&content_object) override;

  virtual void changeInterestLifetime(uint64_t segment);

  void scheduleNextInterests();

  virtual void decreaseWindow();

  virtual void increaseWindow();

  virtual void afterContentReception(const Interest &interest,
                                     const ContentObject &content_object);

  virtual void afterDataUnsatisfied(uint64_t segment);

  void reassemble();

  void returnContentToUser();

  void partialDownload();

  virtual void copyContent(const ContentObject &content_object);

  // virtual void checkForFastRetransmission(const Interest &interest);

  // void fastRetransmit(const Interest &interest, uint32_t chunk_number);

  void removeAllPendingInterests();

 protected:
  void handleTimeout(const std::error_code &ec);

  // reassembly variables
  volatile bool is_final_block_number_discovered_;
  std::atomic<uint64_t> final_block_number_;
  uint64_t last_reassembled_segment_;
  std::shared_ptr<utils::SharableVector<uint8_t>> content_buffer_;
  size_t content_buffer_size_;

  // transmission variablesis_final_block_number_discovered_
  double current_window_size_;
  double pending_window_size_;
  uint64_t interests_in_flight_;
  uint64_t next_suffix_;
  std::vector<std::uint32_t> interest_retransmissions_;
  std::vector<std::chrono::steady_clock::time_point> interest_timepoints_;
  RtoEstimator rtt_estimator_;

  uint32_t retx_count_;

  // buffers
  std::unordered_map<std::uint32_t, ContentObject::Ptr>
      receive_buffer_;  // verified segments by segment number
  std::unordered_map<std::uint32_t, ContentObject::Ptr>
      unverified_segments_;  // used with embedded manifests
  std::unordered_map<std::uint32_t, ContentObject::Ptr>
      verified_manifests_;  // by segment number

  std::uint16_t interest_pool_index_;
  std::uint16_t mask_;

  // suffix randomization: since the suffixes in the manifests could not be in a
  // sequential order, we need to map those suffixes into an ordered sequence.
  std::unordered_map<std::uint64_t, std::uint64_t>
      incremental_suffix_to_real_suffix_map_;
  std::unordered_map<std::uint64_t, std::uint64_t>
      real_suffix_to_incremental_suffix_map_;
  std::uint32_t incremental_suffix_index_;

  // verification
  std::unordered_map<uint32_t, std::pair<std::vector<uint8_t>, HashAlgorithm>>
      suffix_hash_map_;

  // Fast Retransmission
  std::map<uint64_t, bool> received_segments_;
  std::unordered_map<uint64_t, bool> fast_retransmitted_segments;

  // Suffix queue
  volatile bool suffix_queue_completed_;
  SuffixQueue suffix_queue_;

  volatile bool download_with_manifest_;
  uint32_t next_manifest_;
  std::atomic<uint16_t> next_manifest_interval_;

  std::unique_ptr<utils::EventThread> verifier_thread_;

  uint32_t interest_tx_;
  uint32_t interest_count_;

  uint64_t byte_count_;
  double average_rtt_;

  std::unordered_map<uint32_t, uint64_t> sign_time_;
};

}  // namespace protocol

}  // end namespace transport
