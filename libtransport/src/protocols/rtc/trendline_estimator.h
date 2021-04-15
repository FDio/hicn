/*
 *  Copyright (c) 2016 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

// FROM
// https://source.chromium.org/chromium/chromium/src/+/master:third_party/webrtc/modules/congestion_controller/goog_cc/trendline_estimator.h

#ifndef MODULES_CONGESTION_CONTROLLER_GOOG_CC_TRENDLINE_ESTIMATOR_H_
#define MODULES_CONGESTION_CONTROLLER_GOOG_CC_TRENDLINE_ESTIMATOR_H_

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <deque>
#include <memory>
#include <utility>

namespace transport {

namespace protocol {

namespace rtc {

class OptionalDouble {
 public:
  OptionalDouble() : val(0), has_val(false){};
  OptionalDouble(double val) : val(val), has_val(true){};

  double value() { return val; }
  bool has_value() { return has_val; }

 private:
  double val;
  bool has_val;
};

enum class BandwidthUsage {
  kBwNormal = 0,
  kBwUnderusing = 1,
  kBwOverusing = 2,
  kLast
};

struct TrendlineEstimatorSettings {
  static constexpr char kKey[] = "WebRTC-Bwe-TrendlineEstimatorSettings";
  static constexpr unsigned kDefaultTrendlineWindowSize = 20;

  // TrendlineEstimatorSettings() = delete;
  TrendlineEstimatorSettings(
      /*const WebRtcKeyValueConfig* key_value_config*/);

  // Sort the packets in the window. Should be redundant,
  // but then almost no cost.
  bool enable_sort = false;

  // Cap the trendline slope based on the minimum delay seen
  // in the beginning_packets and end_packets respectively.
  bool enable_cap = false;
  unsigned beginning_packets = 7;
  unsigned end_packets = 7;
  double cap_uncertainty = 0.0;

  // Size (in packets) of the window.
  unsigned window_size = kDefaultTrendlineWindowSize;

  // std::unique_ptr<StructParametersParser> Parser();
};

class TrendlineEstimator /*: public DelayIncreaseDetectorInterface */ {
 public:
  TrendlineEstimator(/*const WebRtcKeyValueConfig* key_value_config,
                     NetworkStatePredictor* network_state_predictor*/);

  ~TrendlineEstimator();

  // Update the estimator with a new sample. The deltas should represent deltas
  // between timestamp groups as defined by the InterArrival class.
  void Update(double recv_delta_ms, double send_delta_ms, int64_t send_time_ms,
              int64_t arrival_time_ms, size_t packet_size,
              bool calculated_deltas);

  void UpdateTrendline(double recv_delta_ms, double send_delta_ms,
                       int64_t send_time_ms, int64_t arrival_time_ms,
                       size_t packet_size);

  BandwidthUsage State() const;

  struct PacketTiming {
    PacketTiming(double arrival_time_ms, double smoothed_delay_ms,
                 double raw_delay_ms)
        : arrival_time_ms(arrival_time_ms),
          smoothed_delay_ms(smoothed_delay_ms),
          raw_delay_ms(raw_delay_ms) {}
    double arrival_time_ms;
    double smoothed_delay_ms;
    double raw_delay_ms;
  };

 private:
  // friend class GoogCcStatePrinter;
  void Detect(double trend, double ts_delta, int64_t now_ms);

  void UpdateThreshold(double modified_offset, int64_t now_ms);

  // Parameters.
  TrendlineEstimatorSettings settings_;
  const double smoothing_coef_;
  const double threshold_gain_;
  // Used by the existing threshold.
  int num_of_deltas_;
  // Keep the arrival times small by using the change from the first packet.
  int64_t first_arrival_time_ms_;
  // Exponential backoff filtering.
  double accumulated_delay_;
  double smoothed_delay_;
  // Linear least squares regression.
  std::deque<PacketTiming> delay_hist_;

  const double k_up_;
  const double k_down_;
  double overusing_time_threshold_;
  double threshold_;
  double prev_modified_trend_;
  int64_t last_update_ms_;
  double prev_trend_;
  double time_over_using_;
  int overuse_counter_;
  BandwidthUsage hypothesis_;
  // BandwidthUsage hypothesis_predicted_;
  // NetworkStatePredictor* network_state_predictor_;

  // RTC_DISALLOW_COPY_AND_ASSIGN(TrendlineEstimator);
};

}  // namespace rtc

}  // end namespace protocol

}  // end namespace transport
#endif  // MODULES_CONGESTION_CONTROLLER_GOOG_CC_TRENDLINE_ESTIMATOR_H_
