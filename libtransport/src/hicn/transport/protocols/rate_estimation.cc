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

#include <hicn/transport/protocols/rate_estimation.h>
#include <hicn/transport/utils/log.h>

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
    usleep(KV * dat_rtt);

    pthread_mutex_lock(&(estimator->mutex_));

    dat_rtt = estimator->rtt_;
    my_avg_win = estimator->avg_win_;
    my_avg_rtt = estimator->avg_rtt_;
    my_win_change = estimator->win_change_;
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
  gettimeofday(&(this->start_time_), 0);
  gettimeofday(&(this->begin_batch_), 0);
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
  timeval end;
  gettimeofday(&end, 0);
  double delay = RaaqmDataPath::getMicroSeconds(end) -
                 RaaqmDataPath::getMicroSeconds(this->begin_batch_);

  pthread_mutex_lock(&(this->mutex_));
  this->avg_win_ += this->win_current_ * delay;
  this->win_current_ = win_current;
  this->win_change_ += delay;
  pthread_mutex_unlock(&(this->mutex_));

  gettimeofday(&(this->begin_batch_), 0);
}

void InterRttEstimator::onWindowDecrease(double win_current) {
  timeval end;
  gettimeofday(&end, 0);
  double delay = RaaqmDataPath::getMicroSeconds(end) -
                 RaaqmDataPath::getMicroSeconds(this->begin_batch_);

  pthread_mutex_lock(&(this->mutex_));
  this->avg_win_ += this->win_current_ * delay;
  this->win_current_ = win_current;
  this->win_change_ += delay;
  pthread_mutex_unlock(&(this->mutex_));

  gettimeofday(&(this->begin_batch_), 0);
}

ALaTcpEstimator::ALaTcpEstimator() {
  this->estimation_ = 0.0;
  this->observer_ = NULL;
  gettimeofday(&(this->start_time_), 0);
  this->totalSize_ = 0.0;
}

void ALaTcpEstimator::onStart() {
  this->totalSize_ = 0.0;
  gettimeofday(&(this->start_time_), 0);
}

void ALaTcpEstimator::onDownloadFinished() {
  timeval end;
  gettimeofday(&end, 0);
  double delay = RaaqmDataPath::getMicroSeconds(end) -
                 RaaqmDataPath::getMicroSeconds(this->start_time_);
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
  this->observer_ = NULL;
  this->batching_param_ = batching_param;
  this->total_size_ = 0.0;
  this->number_of_packets_ = 0;
  this->base_alpha_ = alphaArg;
  this->alpha_ = alphaArg;
  gettimeofday(&(this->start_time_), 0);
  gettimeofday(&(this->begin_batch_), 0);
}

void SimpleEstimator::onStart() {
  this->estimated_ = false;
  this->number_of_packets_ = 0;
  this->total_size_ = 0.0;
  gettimeofday(&(this->begin_batch_), 0);
  gettimeofday(&(this->start_time_), 0);
}

void SimpleEstimator::onDownloadFinished() {
  timeval end;
  gettimeofday(&end, 0);
  double delay = RaaqmDataPath::getMicroSeconds(end) -
                 RaaqmDataPath::getMicroSeconds(this->start_time_);
  if (observer_) {
    observer_->notifyDownloadTime(delay);
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
      delay = RaaqmDataPath::getMicroSeconds(end) -
              RaaqmDataPath::getMicroSeconds(this->begin_batch_);
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
  gettimeofday(&(this->begin_batch_), 0);
  gettimeofday(&(this->start_time_), 0);
}

void SimpleEstimator::onDataReceived(int packet_size) {
  this->total_size_ += packet_size;
}

void SimpleEstimator::onRttUpdate(double rtt) {
  this->number_of_packets_++;

  if (number_of_packets_ == this->batching_param_) {
    timeval end;
    gettimeofday(&end, 0);
    double delay = RaaqmDataPath::getMicroSeconds(end) -
                   RaaqmDataPath::getMicroSeconds(this->begin_batch_);
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
    gettimeofday(&(this->begin_batch_), 0);
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
  gettimeofday(&(this->begin_batch_), 0);
  gettimeofday(&(this->start_time_), 0);
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
  timeval end;
  gettimeofday(&end, 0);
  double delay = RaaqmDataPath::getMicroSeconds(end) -
                 RaaqmDataPath::getMicroSeconds(this->begin_batch_);
  this->avg_win_ += this->win_current_ * delay;
  this->win_current_ = win_current;
  this->win_change_ += delay;
  gettimeofday(&(this->begin_batch_), 0);
}

void BatchingPacketsEstimator::onWindowDecrease(double win_current) {
  timeval end;
  gettimeofday(&end, 0);
  double delay = RaaqmDataPath::getMicroSeconds(end) -
                 RaaqmDataPath::getMicroSeconds(this->begin_batch_);
  this->avg_win_ += this->win_current_ * delay;
  this->win_current_ = win_current;
  this->win_change_ += delay;
  gettimeofday(&(this->begin_batch_), 0);
}

}  // end namespace protocol

}  // end namespace transport
