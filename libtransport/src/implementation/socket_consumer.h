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

#include <hicn/transport/auth/verifier.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_options_default_values.h>
#include <hicn/transport/interfaces/statistics.h>
#include <hicn/transport/utils/event_thread.h>
#include <implementation/socket.h>
#include <protocols/cbr.h>
#include <protocols/raaqm.h>
#include <protocols/rtc/rtc.h>
#include <protocols/transport_protocol.h>

namespace transport {
namespace implementation {

using namespace core;
using namespace interface;
using ReadCallback = interface::ConsumerSocket::ReadCallback;

class ConsumerSocket : public Socket {
 private:
  ConsumerSocket(interface::ConsumerSocket *consumer, int protocol,
                 std::shared_ptr<core::Portal> &&portal)
      : Socket(std::move(portal)),
        consumer_interface_(consumer),
        packet_format_(default_values::packet_format),
        interest_lifetime_(default_values::interest_lifetime),
        min_window_size_(default_values::min_window_size),
        max_window_size_(default_values::max_window_size),
        current_window_size_(-1),
        max_retransmissions_(
            default_values::transport_protocol_max_retransmissions),
        /****** RAAQM Parameters ******/
        minimum_drop_probability_(default_values::minimum_drop_probability),
        sample_number_(default_values::sample_number),
        gamma_(default_values::gamma_value),
        beta_(default_values::beta_value),
        drop_factor_(default_values::drop_factor),
        /****** END RAAQM Parameters ******/
        rate_estimation_alpha_(default_values::rate_alpha),
        rate_estimation_observer_(nullptr),
        rate_estimation_batching_parameter_(default_values::batch),
        rate_estimation_choice_(0),
        manifest_factor_relevant_(default_values::manifest_factor_relevant),
        manifest_factor_alert_(default_values::manifest_factor_alert),
        verifier_(std::make_shared<auth::VoidVerifier>()),
        verify_signature_(false),
        reset_window_(false),
        on_interest_output_(VOID_HANDLER),
        on_interest_timeout_(VOID_HANDLER),
        on_interest_satisfied_(VOID_HANDLER),
        on_content_object_input_(VOID_HANDLER),
        stats_summary_(VOID_HANDLER),
        on_fwd_strategy_(VOID_HANDLER),
        on_rec_strategy_(VOID_HANDLER),
        read_callback_(nullptr),
        timer_interval_milliseconds_(0),
        recovery_strategy_(RtcTransportRecoveryStrategies::RTX_ONLY),
        aggregated_data_(false),
        content_sharing_mode_(false),
        aggregated_interests_(false),
        guard_raaqm_params_() {
    switch (protocol) {
      case TransportProtocolAlgorithms::CBR:
        transport_protocol_ =
            std::make_shared<protocol::CbrTransportProtocol>(this);
        break;
      case TransportProtocolAlgorithms::RTC:
        transport_protocol_ =
            std::make_shared<protocol::rtc::RTCTransportProtocol>(this);
        break;
      case TransportProtocolAlgorithms::RAAQM:
      default:
        transport_protocol_ =
            std::make_shared<protocol::RaaqmTransportProtocol>(this);
        break;
    }
  }

 public:
  ConsumerSocket(interface::ConsumerSocket *consumer, int protocol)
      : ConsumerSocket(consumer, protocol, core::Portal::createShared()) {}

  ConsumerSocket(interface::ConsumerSocket *consumer, int protocol,
                 ::utils::EventThread &worker)
      : ConsumerSocket(consumer, protocol, core::Portal::createShared(worker)) {
    is_async_ = true;
  }

  ~ConsumerSocket() { stop(); }

  interface::ConsumerSocket *getInterface() {
    return consumer_interface_;
  }

  void setInterface(interface::ConsumerSocket *consumer_socket) {
    consumer_interface_ = consumer_socket;
  }

  void connect() { portal_->connect(); }

  bool isRunning() { return transport_protocol_->isRunning(); }

  virtual int consume(const Name &name) {
    if (transport_protocol_->isRunning()) {
      return CONSUMER_BUSY;
    }

    network_name_ = name;
    network_name_.setSuffix(0);

    transport_protocol_->start();

    return CONSUMER_RUNNING;
  }

  void stop() {
    if (transport_protocol_->isRunning()) {
      transport_protocol_->stop();
    }
  }

  void resume() {
    if (!transport_protocol_->isRunning()) {
      transport_protocol_->resume();
    }
  }

  using Socket::getSocketOption;
  using Socket::setSocketOption;

  virtual int setSocketOption(int socket_option_key,
                              ReadCallback *socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ReadCallback *socket_option_value) -> int {
          switch (socket_option_key) {
            case ConsumerCallbacksOptions::READ_CALLBACK:
              read_callback_ = socket_option_value;
              break;
            default:
              return SOCKET_OPTION_NOT_SET;
          }

          return SOCKET_OPTION_SET;
        });
  }

  int getSocketOption(int socket_option_key,
                      ReadCallback **socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ReadCallback **socket_option_value) -> int {
          switch (socket_option_key) {
            case ConsumerCallbacksOptions::READ_CALLBACK:
              *socket_option_value = read_callback_;
              break;
            default:
              return SOCKET_OPTION_NOT_GET;
          }

          return SOCKET_OPTION_GET;
        });
  }

  int setSocketOption(int socket_option_key, double socket_option_value) {
    utils::SpinLock::Acquire locked(guard_raaqm_params_);
    switch (socket_option_key) {
      case MIN_WINDOW_SIZE:
        min_window_size_ = socket_option_value;
        break;

      case MAX_WINDOW_SIZE:
        max_window_size_ = socket_option_value;
        break;

      case CURRENT_WINDOW_SIZE:
        current_window_size_ = socket_option_value;
        break;

      case GAMMA_VALUE:
        gamma_ = socket_option_value;
        break;

      case BETA_VALUE:
        beta_ = socket_option_value;
        break;

      case DROP_FACTOR:
        drop_factor_ = socket_option_value;
        break;

      case MINIMUM_DROP_PROBABILITY:
        minimum_drop_probability_ = socket_option_value;
        break;

      case RATE_ESTIMATION_ALPHA:
        if (socket_option_value >= 0 && socket_option_value < 1) {
          rate_estimation_alpha_ = socket_option_value;
        } else {
          rate_estimation_alpha_ = default_values::alpha;
        }
        break;
      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  int setSocketOption(int socket_option_key, uint32_t socket_option_value) {
    utils::SpinLock::Acquire locked(guard_raaqm_params_);
    switch (socket_option_key) {
      case GeneralTransportOptions::MAX_INTEREST_RETX:
        max_retransmissions_ = socket_option_value;
        break;

      case GeneralTransportOptions::INTEREST_LIFETIME:
        interest_lifetime_ = socket_option_value;
        break;

      case RateEstimationOptions::RATE_ESTIMATION_BATCH_PARAMETER:
        if (socket_option_value > 0) {
          rate_estimation_batching_parameter_ = socket_option_value;
        } else {
          rate_estimation_batching_parameter_ = default_values::batch;
        }
        break;

      case RateEstimationOptions::RATE_ESTIMATION_CHOICE:
        if (socket_option_value > 0) {
          rate_estimation_choice_ = socket_option_value;
        } else {
          rate_estimation_choice_ = default_values::rate_choice;
        }
        break;

      case GeneralTransportOptions::STATS_INTERVAL:
        timer_interval_milliseconds_ = socket_option_value;
        break;

      case RtcTransportOptions::RECOVERY_STRATEGY:
        recovery_strategy_ =
            (RtcTransportRecoveryStrategies)socket_option_value;
        break;

      case MANIFEST_FACTOR_RELEVANT:
        manifest_factor_relevant_ = socket_option_value;
        break;

      case MANIFEST_FACTOR_ALERT:
        manifest_factor_alert_ = socket_option_value;
        break;

      case GeneralTransportOptions::PACKET_FORMAT:
        packet_format_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  int setSocketOption(int socket_option_key,
                      std::nullptr_t socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               std::nullptr_t socket_option_value) -> int {
          switch (socket_option_key) {
            case ConsumerCallbacksOptions::INTEREST_RETRANSMISSION:
              if (socket_option_value == VOID_HANDLER) {
                on_interest_retransmission_ = VOID_HANDLER;
                break;
              }

            case ConsumerCallbacksOptions::INTEREST_EXPIRED:
              if (socket_option_value == VOID_HANDLER) {
                on_interest_timeout_ = VOID_HANDLER;
                break;
              }

            case ConsumerCallbacksOptions::INTEREST_SATISFIED:
              if (socket_option_value == VOID_HANDLER) {
                on_interest_satisfied_ = VOID_HANDLER;
                break;
              }

            case ConsumerCallbacksOptions::INTEREST_OUTPUT:
              if (socket_option_value == VOID_HANDLER) {
                on_interest_output_ = VOID_HANDLER;
                break;
              }

            case ConsumerCallbacksOptions::CONTENT_OBJECT_INPUT:
              if (socket_option_value == VOID_HANDLER) {
                on_content_object_input_ = VOID_HANDLER;
                break;
              }
            default:
              return SOCKET_OPTION_NOT_SET;
          }

          return SOCKET_OPTION_SET;
        });
  }

  int setSocketOption(int socket_option_key, bool socket_option_value) {
    int result = SOCKET_OPTION_NOT_SET;
    if (!transport_protocol_->isRunning()) {
      switch (socket_option_key) {
        case RaaqmTransportOptions::PER_SESSION_CWINDOW_RESET:
          reset_window_ = socket_option_value;
          result = SOCKET_OPTION_SET;
          break;

        case RtcTransportOptions::AGGREGATED_DATA:
          aggregated_data_ = socket_option_value;
          result = SOCKET_OPTION_SET;
          break;

        case RtcTransportOptions::CONTENT_SHARING_MODE:
          content_sharing_mode_ = socket_option_value;
          result = SOCKET_OPTION_SET;
          break;

        case RtcTransportOptions::AGGREGATED_INTERESTS:
          aggregated_interests_ = socket_option_value;
          result = SOCKET_OPTION_SET;
          break;

        default:
          return result;
      }
    }
    return result;
  }

  int setSocketOption(int socket_option_key,
                      ConsumerContentObjectCallback socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ConsumerContentObjectCallback socket_option_value) -> int {
          switch (socket_option_key) {
            case ConsumerCallbacksOptions::CONTENT_OBJECT_INPUT:
              on_content_object_input_ = socket_option_value;
              break;

            default:
              return SOCKET_OPTION_NOT_SET;
          }

          return SOCKET_OPTION_SET;
        });
  }

  int setSocketOption(int socket_option_key,
                      ConsumerInterestCallback socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ConsumerInterestCallback socket_option_value) -> int {
          switch (socket_option_key) {
            case ConsumerCallbacksOptions::INTEREST_RETRANSMISSION:
              on_interest_retransmission_ = socket_option_value;
              break;

            case ConsumerCallbacksOptions::INTEREST_OUTPUT:
              on_interest_output_ = socket_option_value;
              break;

            case ConsumerCallbacksOptions::INTEREST_EXPIRED:
              on_interest_timeout_ = socket_option_value;
              break;

            case ConsumerCallbacksOptions::INTEREST_SATISFIED:
              on_interest_satisfied_ = socket_option_value;
              break;

            default:
              return SOCKET_OPTION_NOT_SET;
          }

          return SOCKET_OPTION_SET;
        });
  }

  int setSocketOption(int socket_option_key, IcnObserver *socket_option_value) {
    utils::SpinLock::Acquire locked(guard_raaqm_params_);
    switch (socket_option_key) {
      case RateEstimationOptions::RATE_ESTIMATION_OBSERVER:
        rate_estimation_observer_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  int setSocketOption(
      int socket_option_key,
      const std::shared_ptr<auth::Signer> &socket_option_value) {
    if (!transport_protocol_->isRunning()) {
      switch (socket_option_key) {
        case GeneralTransportOptions::SIGNER:
          signer_.reset();
          signer_ = socket_option_value;
          break;
        default:
          return SOCKET_OPTION_NOT_SET;
      }
    }
    return SOCKET_OPTION_SET;
  }

  int setSocketOption(
      int socket_option_key,
      const std::shared_ptr<auth::Verifier> &socket_option_value) {
    if (!transport_protocol_->isRunning()) {
      switch (socket_option_key) {
        case GeneralTransportOptions::VERIFIER:
          verifier_.reset();
          verifier_ = socket_option_value;
          break;
        default:
          return SOCKET_OPTION_NOT_SET;
      }
    }
    return SOCKET_OPTION_SET;
  }

  int setSocketOption(int socket_option_key,
                      const std::string &socket_option_value) {
    int result = SOCKET_OPTION_NOT_SET;
    switch (socket_option_key) {
      case DataLinkOptions::OUTPUT_INTERFACE:
        if (!transport_protocol_->isRunning()) {
          output_interface_ = socket_option_value;
          portal_->setOutputInterface(output_interface_);
          result = SOCKET_OPTION_SET;
        }
        break;
      default:
        return result;
    }
    return result;
  }

  int setSocketOption(int socket_option_key,
                      ConsumerTimerCallback socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ConsumerTimerCallback socket_option_value) -> int {
          switch (socket_option_key) {
            case ConsumerCallbacksOptions::STATS_SUMMARY:
              stats_summary_ = socket_option_value;
              break;

            default:
              return SOCKET_OPTION_NOT_SET;
          }

          return SOCKET_OPTION_SET;
        });
  }

  int setSocketOption(int socket_option_key,
                      StrategyCallback socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               StrategyCallback socket_option_value) -> int {
          switch (socket_option_key) {
            case ConsumerCallbacksOptions::FWD_STRATEGY_CHANGE:
              on_fwd_strategy_ = socket_option_value;
              break;
            case ConsumerCallbacksOptions::REC_STRATEGY_CHANGE:
              on_rec_strategy_ = socket_option_value;
              break;
            default:
              return SOCKET_OPTION_NOT_SET;
          }

          return SOCKET_OPTION_SET;
        });
  }

  int getSocketOption(int socket_option_key, double &socket_option_value) {
    utils::SpinLock::Acquire locked(guard_raaqm_params_);
    switch (socket_option_key) {
      case GeneralTransportOptions::MIN_WINDOW_SIZE:
        socket_option_value = min_window_size_;
        break;

      case GeneralTransportOptions::MAX_WINDOW_SIZE:
        socket_option_value = max_window_size_;
        break;

      case GeneralTransportOptions::CURRENT_WINDOW_SIZE:
        socket_option_value = current_window_size_;
        break;

        // RAAQM parameters

      case RaaqmTransportOptions::GAMMA_VALUE:
        socket_option_value = gamma_;
        break;

      case RaaqmTransportOptions::BETA_VALUE:
        socket_option_value = beta_;
        break;

      case RaaqmTransportOptions::DROP_FACTOR:
        socket_option_value = drop_factor_;
        break;

      case RaaqmTransportOptions::MINIMUM_DROP_PROBABILITY:
        socket_option_value = minimum_drop_probability_;
        break;

      case RateEstimationOptions::RATE_ESTIMATION_ALPHA:
        socket_option_value = rate_estimation_alpha_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  int getSocketOption(int socket_option_key, uint32_t &socket_option_value) {
    utils::SpinLock::Acquire locked(guard_raaqm_params_);
    switch (socket_option_key) {
      case GeneralTransportOptions::MAX_INTEREST_RETX:
        socket_option_value = max_retransmissions_;
        break;

      case GeneralTransportOptions::INTEREST_LIFETIME:
        socket_option_value = interest_lifetime_;
        break;

      case RaaqmTransportOptions::SAMPLE_NUMBER:
        socket_option_value = sample_number_;
        break;

      case RateEstimationOptions::RATE_ESTIMATION_BATCH_PARAMETER:
        socket_option_value = rate_estimation_batching_parameter_;
        break;

      case RateEstimationOptions::RATE_ESTIMATION_CHOICE:
        socket_option_value = rate_estimation_choice_;
        break;

      case GeneralTransportOptions::STATS_INTERVAL:
        socket_option_value = timer_interval_milliseconds_;
        break;

      case RtcTransportOptions::RECOVERY_STRATEGY:
        socket_option_value = recovery_strategy_;
        break;

      case GeneralTransportOptions::MANIFEST_FACTOR_RELEVANT:
        socket_option_value = manifest_factor_relevant_;
        break;

      case GeneralTransportOptions::MANIFEST_FACTOR_ALERT:
        socket_option_value = manifest_factor_alert_;
        break;

      case GeneralTransportOptions::PACKET_FORMAT:
        socket_option_value = packet_format_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  int getSocketOption(int socket_option_key, bool &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::RUNNING:
        socket_option_value = transport_protocol_->isRunning();
        break;

      case GeneralTransportOptions::ASYNC_MODE:
        socket_option_value = is_async_;
        break;

      case RaaqmTransportOptions::PER_SESSION_CWINDOW_RESET:
        socket_option_value = reset_window_;
        break;

      case RtcTransportOptions::AGGREGATED_DATA:
        socket_option_value = aggregated_data_;
        break;

      case RtcTransportOptions::CONTENT_SHARING_MODE:
        socket_option_value = content_sharing_mode_;
        break;

      case RtcTransportOptions::AGGREGATED_INTERESTS:
        socket_option_value = aggregated_interests_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  int getSocketOption(int socket_option_key, Name **socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::NETWORK_NAME:
        *socket_option_value = &network_name_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  int getSocketOption(int socket_option_key,
                      ConsumerContentObjectCallback **socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ConsumerContentObjectCallback **socket_option_value) -> int {
          switch (socket_option_key) {
            case ConsumerCallbacksOptions::CONTENT_OBJECT_INPUT:
              *socket_option_value = &on_content_object_input_;
              break;

            default:
              return SOCKET_OPTION_NOT_GET;
          }

          return SOCKET_OPTION_GET;
        });
  }

  int getSocketOption(int socket_option_key,
                      ConsumerInterestCallback **socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ConsumerInterestCallback **socket_option_value) -> int {
          switch (socket_option_key) {
            case ConsumerCallbacksOptions::INTEREST_RETRANSMISSION:
              *socket_option_value = &on_interest_retransmission_;
              break;

            case ConsumerCallbacksOptions::INTEREST_OUTPUT:
              *socket_option_value = &on_interest_output_;
              break;

            case ConsumerCallbacksOptions::INTEREST_EXPIRED:
              *socket_option_value = &on_interest_timeout_;
              break;

            case ConsumerCallbacksOptions::INTEREST_SATISFIED:
              *socket_option_value = &on_interest_satisfied_;
              break;

            default:
              return SOCKET_OPTION_NOT_GET;
          }

          return SOCKET_OPTION_GET;
        });
  }

  int getSocketOption(int socket_option_key,
                      IcnObserver **socket_option_value) {
    utils::SpinLock::Acquire locked(guard_raaqm_params_);
    switch (socket_option_key) {
      case RateEstimationOptions::RATE_ESTIMATION_OBSERVER:
        *socket_option_value = (rate_estimation_observer_);
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  int getSocketOption(int socket_option_key,
                      std::shared_ptr<auth::Signer> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::SIGNER:
        socket_option_value = signer_;
        return SOCKET_OPTION_GET;

      default:
        return SOCKET_OPTION_NOT_GET;
    }
  }

  int getSocketOption(int socket_option_key,
                      std::shared_ptr<auth::Verifier> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::VERIFIER:
        socket_option_value = verifier_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }
    return SOCKET_OPTION_GET;
  }

  int getSocketOption(int socket_option_key, std::string &socket_option_value) {
    switch (socket_option_key) {
      case DataLinkOptions::OUTPUT_INTERFACE:
        socket_option_value = output_interface_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }
    return SOCKET_OPTION_GET;
  }

  int getSocketOption(int socket_option_key,
                      interface::TransportStatistics **socket_option_value) {
    switch (socket_option_key) {
      case OtherOptions::STATISTICS:
        *socket_option_value = &stats_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  int getSocketOption(int socket_option_key,
                      ConsumerTimerCallback **socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               ConsumerTimerCallback **socket_option_value) -> int {
          switch (socket_option_key) {
            case ConsumerCallbacksOptions::STATS_SUMMARY:
              *socket_option_value = &stats_summary_;
              break;
            default:
              return SOCKET_OPTION_NOT_GET;
          }

          return SOCKET_OPTION_GET;
        });
  }

  int getSocketOption(int socket_option_key,
                      StrategyCallback **socket_option_value) {
    // Reschedule the function on the io_service to avoid race condition in
    // case setSocketOption is called while the io_service is running.
    return rescheduleOnIOService(
        socket_option_key, socket_option_value,
        [this](int socket_option_key,
               StrategyCallback **socket_option_value) -> int {
          switch (socket_option_key) {
            case ConsumerCallbacksOptions::FWD_STRATEGY_CHANGE:
              *socket_option_value = &on_fwd_strategy_;
              break;
            case ConsumerCallbacksOptions::REC_STRATEGY_CHANGE:
              *socket_option_value = &on_rec_strategy_;
              break;
            default:
              return SOCKET_OPTION_NOT_GET;
          }

          return SOCKET_OPTION_GET;
        });
  }

 protected:
  template <typename Lambda, typename arg2>
  int rescheduleOnIOService(int socket_option_key, arg2 socket_option_value,
                            Lambda lambda_func) {
    // To enforce type check
    std::function<int(int, arg2)> func = lambda_func;
    int result = SOCKET_OPTION_SET;
    if (transport_protocol_ && transport_protocol_->isRunning()) {
      std::mutex mtx;
      /* Condition variable for the wait */
      std::condition_variable cv;
      bool done = false;
      portal_->getThread().tryRunHandlerNow([&socket_option_key,
                                             &socket_option_value, &mtx, &cv,
                                             &result, &done, &func]() {
        std::unique_lock<std::mutex> lck(mtx);
        done = true;
        result = func(socket_option_key, socket_option_value);
        cv.notify_all();
      });
      std::unique_lock<std::mutex> lck(mtx);
      if (!done) {
        cv.wait(lck);
      }
    } else {
      result = func(socket_option_key, socket_option_value);
    }

    return result;
  }

 protected:
  interface::ConsumerSocket *consumer_interface_;

  // No need to protect from multiple accesses in the async consumer
  // The parameter is accessible only with a getSocketOption and
  // set from the consume
  Name network_name_;

  hicn_packet_format_t packet_format_;
  int interest_lifetime_;

  double min_window_size_;
  double max_window_size_;
  double current_window_size_;
  uint32_t max_retransmissions_;

  // RAAQM Parameters
  double minimum_drop_probability_;
  unsigned int sample_number_;
  double gamma_;
  double beta_;
  double drop_factor_;

  // Rate estimation parameters
  double rate_estimation_alpha_;
  IcnObserver *rate_estimation_observer_;
  int rate_estimation_batching_parameter_;
  int rate_estimation_choice_;

  // Verification parameters
  uint32_t manifest_factor_relevant_;
  uint32_t manifest_factor_alert_;
  std::shared_ptr<auth::Verifier> verifier_;
  transport::auth::KeyId *key_id_;
  std::atomic_bool verify_signature_;
  bool reset_window_;

  ConsumerInterestCallback on_interest_retransmission_;
  ConsumerInterestCallback on_interest_output_;
  ConsumerInterestCallback on_interest_timeout_;
  ConsumerInterestCallback on_interest_satisfied_;
  ConsumerContentObjectCallback on_content_object_input_;
  ConsumerTimerCallback stats_summary_;
  StrategyCallback on_fwd_strategy_;
  StrategyCallback on_rec_strategy_;

  ReadCallback *read_callback_;

  uint32_t timer_interval_milliseconds_;

  // Transport protocol
  std::shared_ptr<protocol::TransportProtocol> transport_protocol_;

  // Statistic
  TransportStatistics stats_;

  // RTC protocol
  RtcTransportRecoveryStrategies recovery_strategy_;
  bool aggregated_data_;
  bool content_sharing_mode_;
  bool aggregated_interests_;

  utils::SpinLock guard_raaqm_params_;
  std::string output_interface_;
};

}  // namespace implementation
}  // namespace transport
