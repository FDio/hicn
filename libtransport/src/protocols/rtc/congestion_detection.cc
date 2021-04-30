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

#include <hicn/transport/utils/log.h>
#include <protocols/rtc/congestion_detection.h>

namespace transport {

namespace protocol {

namespace rtc {

CongestionDetection::CongestionDetection()
    : cc_estimator_(), last_processed_chunk_() {}

CongestionDetection::~CongestionDetection() {}

void CongestionDetection::updateStats() {
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();

  if (chunks_number_.empty()) return;

  uint32_t chunk_number = chunks_number_.front();

  while (chunks_[chunk_number].getReceivedTime() + HICN_CC_STATS_MAX_DELAY_MS <
             now ||
         chunks_[chunk_number].isComplete()) {
    if (chunk_number == last_processed_chunk_.getFrameSeqNum() + 1) {
      chunks_[chunk_number].setPreviousSentTime(
          last_processed_chunk_.getSentTime());

      chunks_[chunk_number].setPreviousReceivedTime(
          last_processed_chunk_.getReceivedTime());
      cc_estimator_.Update(chunks_[chunk_number].getReceivedDelta(),
                           chunks_[chunk_number].getSentDelta(),
                           chunks_[chunk_number].getSentTime(),
                           chunks_[chunk_number].getReceivedTime(),
                           chunks_[chunk_number].getFrameSize(), true);

    } else {
      TRANSPORT_LOGD(
          "CongestionDetection::updateStats frame %u but not the \
      previous one, last one was %u currentFrame %u",
          chunk_number, last_processed_chunk_.getFrameSeqNum(),
          chunks_[chunk_number].getFrameSeqNum());
    }

    last_processed_chunk_ = chunks_[chunk_number];

    chunks_.erase(chunk_number);

    chunks_number_.pop();
    if (chunks_number_.empty()) break;

    chunk_number = chunks_number_.front();
  }
}

void CongestionDetection::addPacket(const core::ContentObject &content_object) {
  auto payload = content_object.getPayload();
  uint32_t payload_size = (uint32_t)payload->length();
  uint32_t segmentNumber = content_object.getName().getSuffix();
  // uint32_t pkt = segmentNumber & modMask_;
  uint64_t *sentTimePtr = (uint64_t *)payload->data();

  // this is just for testing with hiperf, assuming a frame is 10 pkts
  // in the final version, the split should be based on the timestamp in the pkt
  uint32_t frameNum = (int)(segmentNumber / HICN_CC_STATS_CHUNK_SIZE);
  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();

  if (chunks_.find(frameNum) == chunks_.end()) {
    // new chunk of pkts or out of order
    if (last_processed_chunk_.getFrameSeqNum() > frameNum)
      return;  // out of order and we already processed the chunk

    chunks_[frameNum] = FrameStats(frameNum, HICN_CC_STATS_CHUNK_SIZE);
    chunks_number_.push(frameNum);
  }

  chunks_[frameNum].addPacket(*sentTimePtr, now, payload_size);
}

}  // namespace rtc
}  // namespace protocol
}  // namespace transport
