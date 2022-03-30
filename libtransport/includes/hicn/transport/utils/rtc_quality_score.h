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

#pragma once

namespace transport {

namespace protocol {

namespace rtc {

class RTCQualityScore {
 public:
  RTCQualityScore(){};
  ~RTCQualityScore(){};

  uint8_t getQualityScore(uint64_t RTT, uint32_t loss_rate) {
    uint32_t delay_index = getDelay(RTT);
    uint32_t loss_index = getLossRate(loss_rate);
    return quality_score_[loss_index][delay_index];
  }

 private:
  // see quality score map
  uint8_t quality_score_[7][6]{{5, 5, 5, 4, 3, 1}, {5, 4, 3, 2, 1, 1},
                               {5, 3, 2, 1, 1, 1}, {5, 2, 1, 1, 1, 1},
                               {4, 1, 1, 1, 1, 1}, {3, 1, 1, 1, 1, 1},
                               {1, 1, 1, 1, 1, 1}};

  uint8_t getDelay(uint64_t RTT) {
    uint64_t OWD = RTT / 2;
    // we should never get a OWD of 0. so we take the first col if OWD is < 5ms
    if (OWD < 5) return 0;
    if (OWD < 50) return 1;
    if (OWD < 100) return 2;
    if (OWD < 200) return 3;
    if (OWD < 300) return 4;
    return 5;
  }

  uint8_t getLossRate(uint32_t loss_rate) {
    // we use 3% as mean loss rate
    if (loss_rate < 3) return 0;
    if (loss_rate < 10) return 1;
    if (loss_rate < 20) return 2;
    if (loss_rate < 30) return 3;
    if (loss_rate < 40) return 4;
    if (loss_rate < 50) return 5;
    return 6;
  }
};

}  // namespace rtc

}  // namespace protocol

}  // namespace transport
