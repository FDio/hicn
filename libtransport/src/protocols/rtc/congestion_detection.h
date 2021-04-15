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

#include <hicn/transport/core/content_object.h>
#include <protocols/rtc/trendline_estimator.h>

#include <map>
#include <queue>

#define HICN_CC_STATS_CHUNK_SIZE 10
#define HICN_CC_STATS_MAX_DELAY_MS 100

namespace transport {

namespace protocol {

namespace rtc {

class FrameStats {
 public:
  FrameStats()
      : frame_num_(0),
        sent_time_(0),
        received_time_(0),
        previous_sent_time_(0),
        previous_received_time_(0),
        size_(0),
        received_pkt_m(0),
        burst_size_m(HICN_CC_STATS_CHUNK_SIZE){};

  FrameStats(uint32_t burst_size)
      : frame_num_(0),
        sent_time_(0),
        received_time_(0),
        previous_sent_time_(0),
        previous_received_time_(0),
        size_(0),
        received_pkt_m(0),
        burst_size_m(burst_size){};

  FrameStats(uint32_t frame_num, uint32_t burst_size)
      : frame_num_(frame_num),
        sent_time_(0),
        received_time_(0),
        previous_sent_time_(0),
        previous_received_time_(0),
        size_(0),
        received_pkt_m(0),
        burst_size_m(burst_size){};

  FrameStats(uint32_t frame_num, uint64_t sent_time, uint64_t received_time,
             uint32_t size, FrameStats previousFrame, uint32_t burst_size)
      : frame_num_(frame_num),
        sent_time_(sent_time),
        received_time_(received_time),
        previous_sent_time_(previousFrame.getSentTime()),
        previous_received_time_(previousFrame.getReceivedTime()),
        size_(size),
        received_pkt_m(1),
        burst_size_m(burst_size){};

  void addPacket(uint64_t sent_time, uint64_t received_time, uint32_t size) {
    size_ += size;
    sent_time_ =
        (sent_time_ == 0) ? sent_time : std::min(sent_time_, sent_time);
    received_time_ = std::max(received_time, received_time_);
    received_pkt_m++;
  }

  bool isComplete() { return received_pkt_m == burst_size_m; }

  uint32_t getFrameSeqNum() const { return frame_num_; }
  uint64_t getSentTime() const { return sent_time_; }
  uint64_t getReceivedTime() const { return received_time_; }
  uint32_t getFrameSize() const { return size_; }

  void setPreviousReceivedTime(uint64_t time) {
    previous_received_time_ = time;
  }
  void setPreviousSentTime(uint64_t time) { previous_sent_time_ = time; }

  // todo manage first frame
  double getReceivedDelta() {
    return static_cast<double>(received_time_ - previous_received_time_);
  }
  double getSentDelta() {
    return static_cast<double>(sent_time_ - previous_sent_time_);
  }

 private:
  uint32_t frame_num_;
  uint64_t sent_time_;
  uint64_t received_time_;

  uint64_t previous_sent_time_;
  uint64_t previous_received_time_;
  uint32_t size_;

  uint32_t received_pkt_m;
  uint32_t burst_size_m;
};

class CongestionDetection {
 public:
  CongestionDetection();
  ~CongestionDetection();

  void addPacket(const core::ContentObject &content_object);

  BandwidthUsage getState() { return cc_estimator_.State(); }

  void updateStats();

 private:
  TrendlineEstimator cc_estimator_;
  std::map<uint32_t, FrameStats> chunks_;
  std::queue<uint32_t> chunks_number_;

  FrameStats last_processed_chunk_;
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
