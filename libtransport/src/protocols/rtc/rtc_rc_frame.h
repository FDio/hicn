/*
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
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
#include <protocols/rtc/congestion_detection.h>
#include <protocols/rtc/rtc_rc.h>

namespace transport {

namespace protocol {

namespace rtc {

class RTCRateControlFrame : public RTCRateControl {
 public:
  RTCRateControlFrame();

  ~RTCRateControlFrame();

  void onNewRound(double round_len);
  void onDataPacketReceived(const core::ContentObject &content_object);

  void receivedBwProbeTrain(uint64_t firts_probe_ts, uint64_t last_probe_ts,
                            uint32_t total_probes);

 private:
  CongestionDetection cc_detector_;
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
