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

#include <hicn/transport/interfaces/socket_options_default_values.h>
#include <hicn/transport/protocols/rate_estimation.h>
#include <hicn/transport/utils/log.h>

#include <thread>

namespace transport {

namespace protocol {

void *Timer(void *data) {
  InterRttEstimator *estimator = (InterRttEstimator *)data;

  double dat_rtt, my_avg_win, my_avg_rtt;
  int my_win_change, number_of_packets, max_packet_size;

  pthread_mutex_lock(&(estimator->mutex_));
  dat_rtt = estimator->rtt_;
  pthread_mutex_unlock(&(estimator->mutex_));

  while (estimator->is_running_) {
    std::this_thread::sleep_for(std::chrono::microseconds(
        (uint64_t)(interface::default_values::kv * dat_rtt)));

    pthread_mutex_lock(&(estimator->mutex_));

    dat_rtt = estimator->rtt_;
    my_avg_win = estimator->avg_win_;
    my_avg_rtt = estimator->avg_rtt_;
    my_win_change = (int)(estimator->win_change_);
    number_of_packets = estimator->number_of_packets_;
    max_packet_size = estimator->max_packet_size_;
    estimator->avg_rtt_ = estimator->rtt_;
    estimator->avg_win_ = 0;
    estimator->win_change_ = 0;
    estimator->number_of_packets_ = 1;

    pthread_mutex_unlock(&(estimator->mutex_));

    if (number_of_packets == 0 || my_win_change == 0) {
      continue;
    }
    if (estimator->estimation_ == 0) {
      estimator->estimation_ = (my_avg_win * 8.0 * max_packet_size * 1000000.0 /
                                (1.0 * my_win_change)) /
                               (my_avg_rtt / (1.0 * number_of_packets));
    }

    estimator->estimation_ =
        estimator->alpha_ * estimator->estimation_ +
        (1 - estimator->alpha_) * ((my_avg_win * 8.0 * max_packet_size *
                                    1000000.0 / (1.0 * my_win_change)) /
                                   (my_avg_rtt / (1.0 * number_of_packets)));

    if (estimator->observer_) {
      estimator->observer_->notifyStats(estimator->estimation_);
    }
  }

  return nullptr;
}

InterRttEstimator::InterRttEstimator(double alpha_arg) {
  this->estimated_ = false;
  this->observer_ = NULL;
  this->alpha_ = alpha_arg;
  this->thread_is_running_ = false;
  this->my_th_ = NULL;
  this->is_running_ = true;
  this->avg_rtt_ = 0.0;
  this->estimation_ = 0.0;
  this->avg_win_ = 0.0;
  this->rtt_ = 0.0;
  this->win_change_ = 0;
  this->number_of_packets_ = 0;
  this->max_packet_size_ = 0;
  this->win_current_ = 1.0;

  pthread_mutex_init(&(this->mutex_), NULL);
  this->start_time_ = std::chrono::steady_clock::now();
  this->begin_batch_ = std::chrono::steady_clock::now();
}

InterRttEstimator::~InterRttEstimator() {
  this->is_running_ = false;
  if (this->my_th_) {
    pthread_join(*(this->my_th_), NULL);
  }
  this->my_th_ = NULL;
  pthread_mutex_destroy(&(this->mutex_));
}

void InterRttEstimator::onRttUpdate(double rtt) {
  pthread_mutex_lock(&(this->mutex_));
  this->rtt_ = rtt;
  this->number_of_packets_++;
  this->avg_rtt_ += rtt;
  pthread_mutex_unlock(&(this->mutex_));

  if (!thread_is_running_) {
    my_th_ = (pthread_t *)malloc(sizeof(pthread_t));
    if (!my_th_) {
      TRANSPORT_LOGE("Error allocating thread.");
      my_th_ = NULL;
    }
    if (/*int err = */ pthread_create(my_th_, NULL, transport::protocol::Timer,
                                      (void *)this)) {
      TRANSPORT_LOGE("Error creating the thread");
      my_th_ = NULL;
    }
    thread_is_running_ = true;
  }
}

void InterRttEstimator::onWindowIncrease(double win_current) {
  TimePoint end = std::chrono::steady_clock::now();
  auto delay =
      std::chrono::duration_cast<Microseconds>(end - this->begin_batch_)
          .count();

  pthread_mutex_lock(&(this->mutex_));
  this->avg_win_ += this->win_current_ * delay;
  this->win_current_ = win_current;
  this->win_change_ += delay;
  pthread_mutex_unlock(&(this->mutex_));

  this->begin_batch_ = std::chrono::steady_clock::now();
}

void InterRttEstimator::onWindowDecrease(double win_current) {
  TimePoint end = std::chrono::steady_clock::now();
  auto delay =
      std::chrono::duration_cast<Microseconds>(end - this->begin_batch_)
          .count();

  pthread_mutex_lock(&(this->mutex_));
  this->avg_win_ += this->win_current_ * delay;
  this->win_current_ = win_current;
  this->win_change_ += delay;
  pthread_mutex_unlock(&(this->mutex_));

  this->begin_batch_ = std::chrono::steady_clock::now();
}

ALaTcpEstimator::ALaTcpEstimator() {
  this->estimation_ = 0.0;
  this->observer_ = NULL;
  this->start_time_ = std::chrono::steady_clock::now();
  this->totalSize_ = 0.0;
}

void ALaTcpEstimator::onStart() {
  this->totalSize_ = 0.0;
  this->start_time_ = std::chrono::steady_clock::now();
}

void ALaTcpEstimator::onDownloadFinished() {
  TimePoint end = std::chrono::steady_clock::now();
  auto delay =
      std::chrono::duration_cast<Microseconds>(end - this->start_time_).count();
  this->estimation_ = this->totalSize_ * 8 * 1000000 / delay;
  if (observer_) {
    observer_->notifyStats(this->estimation_);
  }
}

void ALaTcpEstimator::onDataReceived(int packet_size) {
  this->totalSize_ += packet_size;
}

SimpleEstimator::SimpleEstimator(double alphaArg, int batching_param) {
  this->estimation_ = 0.0;
  this->estimated_ = false;
  this->observer_ = nullptr;
  this->batching_param_ = batching_param;
  this->total_size_ = 0.0;
  this->number_of_packets_ = 0;
  this->base_alpha_ = alphaArg;
  this->alpha_ = alphaArg;
  this->start_time_ = std::chrono::steady_clock::now();
  this->begin_batch_ = std::chrono::steady_clock::now();
}

void SimpleEstimator::onStart() {
  this->estimated_ = false;
  this->number_of_packets_ = 0;
  this->total_size_ = 0.0;
  this->start_time_ = std::chrono::steady_clock::now();
  this->begin_batch_ = std::chrono::steady_clock::now();
}

void SimpleEstimator::onDownloadFinished() {
  TimePoint end = std::chrono::steady_clock::now();
  auto delay =
      std::chrono::duration_cast<Microseconds>(end - this->start_time_).count();
  if (observer_) {
    observer_->notifyDownloadTime((double)delay);
  }
  if (!this->estimated_) {
    // Assuming all packets carry max_packet_size_ bytes of data
    // (8*max_packet_size_ bits); 1000000 factor to convert us to seconds
    if (this->estimation_) {
      this->estimation_ =
          alpha_ * this->estimation_ +
          (1 - alpha_) * (total_size_ * 8 * 1000000.0 / (delay));
    } else {
      this->estimation_ = total_size_ * 8 * 1000000.0 / (delay);
    }
    if (observer_) {
      observer_->notifyStats(this->estimation_);
    }
    this->alpha_ = this->base_alpha_ * (((double)this->number_of_packets_) /
                                        ((double)this->batching_param_));
  } else {
    if (this->number_of_packets_ >=
        (int)(75.0 * (double)this->batching_param_ / 100.0)) {
      delay = std::chrono::duration_cast<Microseconds>(end - this->begin_batch_)
                  .count();
      // Assuming all packets carry max_packet_size_ bytes of data
      // (8*max_packet_size_ bits); 1000000 factor to convert us to seconds
      if (this->estimation_) {
        this->estimation_ =
            alpha_ * this->estimation_ +
            (1 - alpha_) * (total_size_ * 8 * 1000000.0 / (delay));
      } else {
        this->estimation_ = total_size_ * 8 * 1000000.0 / (delay);
      }
      if (observer_) {
        observer_->notifyStats(this->estimation_);
      }
      this->alpha_ = this->base_alpha_ * (((double)this->number_of_packets_) /
                                          ((double)this->batching_param_));
    }
  }
  this->number_of_packets_ = 0;
  this->total_size_ = 0.0;
  this->start_time_ = std::chrono::steady_clock::now();
  this->begin_batch_ = std::chrono::steady_clock::now();
}

void SimpleEstimator::onDataReceived(int packet_size) {
  this->total_size_ += packet_size;
}

void SimpleEstimator::onRttUpdate(double rtt) {
  this->number_of_packets_++;

  if (this->number_of_packets_ == this->batching_param_) {
    TimePoint end = std::chrono::steady_clock::now();
    auto delay =
        std::chrono::duration_cast<Microseconds>(end - this->begin_batch_)
            .count();
    // Assuming all packets carry max_packet_size_ bytes of data
    // (8*max_packet_size_ bits); 1000000 factor to convert us to seconds
    if (this->estimation_) {
      this->estimation_ =
          alpha_ * this->estimation_ +
          (1 - alpha_) * (total_size_ * 8 * 1000000.0 / (delay));
    } else {
      this->estimation_ = total_size_ * 8 * 1000000.0 / (delay);
    }
    if (observer_) {
      observer_->notifyStats(this->estimation_);
    }
    this->alpha_ = this->base_alpha_;
    this->number_of_packets_ = 0;
    this->total_size_ = 0.0;
    this->begin_batch_ = std::chrono::steady_clock::now();
  }
}

BatchingPacketsEstimator::BatchingPacketsEstimator(double alpha_arg,
                                                   int param) {
  this->estimated_ = false;
  this->observer_ = NULL;
  this->alpha_ = alpha_arg;
  this->batching_param_ = param;
  this->number_of_packets_ = 0;
  this->avg_win_ = 0.0;
  this->avg_rtt_ = 0.0;
  this->win_change_ = 0.0;
  this->max_packet_size_ = 0;
  this->estimation_ = 0.0;
  this->win_current_ = 1.0;
  this->begin_batch_ = std::chrono::steady_clock::now();
  this->start_time_ = std::chrono::steady_clock::now();
}

void BatchingPacketsEstimator::onRttUpdate(double rtt) {
  this->number_of_packets_++;
  this->avg_rtt_ += rtt;

  if (number_of_packets_ == this->batching_param_) {
    if (estimation_ == 0) {
      estimation_ = (avg_win_ * 8.0 * max_packet_size_ * 1000000.0 /
                     (1.0 * win_change_)) /
                    (avg_rtt_ / (1.0 * number_of_packets_));
    } else {
      estimation_ = alpha_ * estimation_ +
                    (1 - alpha_) * ((avg_win_ * 8.0 * max_packet_size_ *
                                     1000000.0 / (1.0 * win_change_)) /
                                    (avg_rtt_ / (1.0 * number_of_packets_)));
    }

    if (observer_) {
      observer_->notifyStats(estimation_);
    }

    this->number_of_packets_ = 0;
    this->avg_win_ = 0.0;
    this->avg_rtt_ = 0.0;
    this->win_change_ = 0.0;
  }
}

void BatchingPacketsEstimator::onWindowIncrease(double win_current) {
  TimePoint end = std::chrono::steady_clock::now();
  auto delay =
      std::chrono::duration_cast<Microseconds>(end - this->begin_batch_)
          .count();
  this->avg_win_ += this->win_current_ * delay;
  this->win_current_ = win_current;
  this->win_change_ += delay;
  this->begin_batch_ = std::chrono::steady_clock::now();
}

void BatchingPacketsEstimator::onWindowDecrease(double win_current) {
  TimePoint end = std::chrono::steady_clock::now();
  auto delay =
      std::chrono::duration_cast<Microseconds>(end - this->begin_batch_)
          .count();
  this->avg_win_ += this->win_current_ * delay;
  this->win_current_ = win_current;
  this->win_change_ += delay;
  this->begin_batch_ = std::chrono::steady_clock::now();
}

}  // end namespace protocol

}  // end namespace transport
