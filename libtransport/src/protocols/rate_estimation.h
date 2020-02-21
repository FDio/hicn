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

#include <hicn/transport/interfaces/statistics.h>

#include <protocols/raaqm_data_path.h>

#include <chrono>

namespace transport {

namespace protocol {

class IcnRateEstimator {
 public:
  using TimePoint = std::chrono::steady_clock::time_point;
  using Microseconds = std::chrono::microseconds;

  IcnRateEstimator(){};

  virtual ~IcnRateEstimator(){};

  virtual void onRttUpdate(double rtt){};

  virtual void onDataReceived(int packetSize){};

  virtual void onWindowIncrease(double winCurrent){};

  virtual void onWindowDecrease(double winCurrent){};

  virtual void onStart(){};

  virtual void onDownloadFinished(){};

  virtual void setObserver(interface::IcnObserver *observer) {
    this->observer_ = observer;
  };
  interface::IcnObserver *observer_;
  TimePoint start_time_;
  TimePoint begin_batch_;
  double base_alpha_;
  double alpha_;
  double estimation_;
  int number_of_packets_;
  // this boolean is to make sure at least one estimation of the BW is done
  bool estimated_;
};

// A rate estimator RTT-based. Computes EWMA(WinSize)/EWMA(RTT)

class InterRttEstimator : public IcnRateEstimator {
 public:
  InterRttEstimator(double alpha_arg);

  ~InterRttEstimator();

  void onRttUpdate(double rtt);

  void onDataReceived(int packet_size) {
    if (packet_size > this->max_packet_size_) {
      this->max_packet_size_ = packet_size;
    }
  };

  void onWindowIncrease(double win_current);

  void onWindowDecrease(double win_current);

  void onStart(){};

  void onDownloadFinished(){};

  // private: should be done by using getters
  pthread_t *my_th_;
  bool thread_is_running_;
  double rtt_;
  bool is_running_;
  pthread_mutex_t mutex_;
  double avg_rtt_;
  double avg_win_;
  int max_packet_size_;
  double win_change_;
  double win_current_;
};

// A rate estimator, Batching Packets based. Computes EWMA(WinSize)/EWMA(RTT)

class BatchingPacketsEstimator : public IcnRateEstimator {
 public:
  BatchingPacketsEstimator(double alpha_arg, int batchingParam);

  void onRttUpdate(double rtt);

  void onDataReceived(int packet_size) {
    if (packet_size > this->max_packet_size_) {
      this->max_packet_size_ = packet_size;
    }
  };

  void onWindowIncrease(double win_current);

  void onWindowDecrease(double win_current);

  void onStart(){};

  void onDownloadFinished(){};

 private:
  int batching_param_;
  double avg_rtt_;
  double avg_win_;
  double win_change_;
  int max_packet_size_;
  double win_current_;
};

// Segment Estimator

class ALaTcpEstimator : public IcnRateEstimator {
 public:
  ALaTcpEstimator();

  void onDataReceived(int packet_size);
  void onStart();
  void onDownloadFinished();

 private:
  double totalSize_;
};

// A Rate estimator, this one is the simplest: counting batching_param_ packets
// and then divide the sum of the size of these packets by the time taken to DL
// them. Should be the one used

class SimpleEstimator : public IcnRateEstimator {
 public:
  SimpleEstimator(double alpha, int batching_param);

  void onRttUpdate(double rtt);

  void onDataReceived(int packet_size);

  void onWindowIncrease(double win_current){};

  void onWindowDecrease(double win_current){};

  void onStart();

  void onDownloadFinished();

 private:
  int batching_param_;
  double total_size_;
};

void *Timer(void *data);

}  // namespace protocol

}  // end namespace transport
