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

#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/protocols/cbr.h>
#include <hicn/transport/protocols/raaqm.h>
#include <hicn/transport/protocols/rtc.h>

namespace transport {

namespace interface {

ConsumerSocket::ConsumerSocket(int protocol)
    : ConsumerSocket(protocol, internal_io_service_) {}

ConsumerSocket::ConsumerSocket(int protocol, asio::io_service &io_service)
    : io_service_(io_service),
      portal_(std::make_shared<Portal>(io_service_)),
      async_downloader_(),
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
      rate_estimation_choice_(0),
      verifier_(std::make_shared<utils::Verifier>()),
      verify_signature_(false),
      on_interest_output_(VOID_HANDLER),
      on_interest_timeout_(VOID_HANDLER),
      on_interest_satisfied_(VOID_HANDLER),
      on_content_object_input_(VOID_HANDLER),
      on_content_object_verification_(VOID_HANDLER),
      on_content_object_(VOID_HANDLER),
      on_manifest_(VOID_HANDLER),
      stats_summary_(VOID_HANDLER),
      read_callback_(nullptr),
      virtual_download_(false),
      timer_interval_milliseconds_(0),
      guard_raaqm_params_() {
  switch (protocol) {
    case TransportProtocolAlgorithms::CBR:
      transport_protocol_ = std::make_unique<CbrTransportProtocol>(this);
      break;
    case TransportProtocolAlgorithms::RTC:
      transport_protocol_ = std::make_unique<RTCTransportProtocol>(this);
      break;
    case TransportProtocolAlgorithms::RAAQM:
    default:
      transport_protocol_ = std::make_unique<RaaqmTransportProtocol>(this);
      break;
  }
}

ConsumerSocket::~ConsumerSocket() {
  stop();
  async_downloader_.stop();
}

void ConsumerSocket::connect() { portal_->connect(); }

int ConsumerSocket::consume(const Name &name) {
  if (transport_protocol_->isRunning()) {
    return CONSUMER_BUSY;
  }

  network_name_ = name;
  network_name_.setSuffix(0);

  transport_protocol_->start();

  return CONSUMER_FINISHED;
}

int ConsumerSocket::asyncConsume(const Name &name) {
  if (!async_downloader_.stopped()) {
    async_downloader_.add([this, name]() {
      network_name_ = std::move(name);
      network_name_.setSuffix(0);
      transport_protocol_->start();
    });
  }

  return CONSUMER_RUNNING;
}

void ConsumerSocket::stop() {
  if (transport_protocol_->isRunning()) {
    transport_protocol_->stop();
  }
}

void ConsumerSocket::resume() {
  if (!transport_protocol_->isRunning()) {
    transport_protocol_->resume();
  }
}

asio::io_service &ConsumerSocket::getIoService() {
  return portal_->getIoService();
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    ReadCallback *socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key, ReadCallback *socket_option_value) -> int {
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

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    ReadCallback **socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key, ReadCallback **socket_option_value) -> int {
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

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    double socket_option_value) {
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

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    uint32_t socket_option_value) {
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

    default:
      return SOCKET_OPTION_NOT_SET;
  }

  return SOCKET_OPTION_SET;
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    std::nullptr_t socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key, std::nullptr_t socket_option_value) -> int {
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

          case ConsumerCallbacksOptions::CONTENT_OBJECT_TO_VERIFY:
            if (socket_option_value == VOID_HANDLER) {
              on_content_object_verification_ = VOID_HANDLER;
              break;
            }

          default:
            return SOCKET_OPTION_NOT_SET;
        }

        return SOCKET_OPTION_SET;
      });
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    bool socket_option_value) {
  int result = SOCKET_OPTION_NOT_SET;
  if (!transport_protocol_->isRunning()) {
    switch (socket_option_key) {
      case OtherOptions::VIRTUAL_DOWNLOAD:
        virtual_download_ = socket_option_value;
        result = SOCKET_OPTION_SET;
        break;

      case GeneralTransportOptions::VERIFY_SIGNATURE:
        verify_signature_ = socket_option_value;
        result = SOCKET_OPTION_SET;
        break;

      default:
        return result;
    }
  }
  return result;
}

int ConsumerSocket::setSocketOption(
    int socket_option_key, ConsumerContentObjectCallback socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
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

int ConsumerSocket::setSocketOption(
    int socket_option_key,
    ConsumerContentObjectVerificationCallback socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key,
             ConsumerContentObjectVerificationCallback socket_option_value)
          -> int {
        switch (socket_option_key) {
          case ConsumerCallbacksOptions::CONTENT_OBJECT_TO_VERIFY:
            on_content_object_verification_ = socket_option_value;
            break;

          default:
            return SOCKET_OPTION_NOT_SET;
        }

        return SOCKET_OPTION_SET;
      });
}

int ConsumerSocket::setSocketOption(
    int socket_option_key, ConsumerInterestCallback socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
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

int ConsumerSocket::setSocketOption(
    int socket_option_key, ConsumerManifestCallback socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key,
             ConsumerManifestCallback socket_option_value) -> int {
        switch (socket_option_key) {
          case ConsumerCallbacksOptions::MANIFEST_INPUT:
            on_manifest_ = socket_option_value;
            break;

          default:
            return SOCKET_OPTION_NOT_SET;
        }

        return SOCKET_OPTION_SET;
      });
}

int ConsumerSocket::setSocketOption(
    int socket_option_key,
    ConsumerContentObjectVerificationFailedCallback socket_option_value) {
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](
          int socket_option_key,
          ConsumerContentObjectVerificationFailedCallback socket_option_value)
          -> int {
        switch (socket_option_key) {
          case ConsumerCallbacksOptions::VERIFICATION_FAILED:
            verification_failed_callback_ = socket_option_value;
            break;

          default:
            return SOCKET_OPTION_NOT_SET;
        }

        return SOCKET_OPTION_SET;
      });
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    IcnObserver *socket_option_value) {
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

int ConsumerSocket::setSocketOption(
    int socket_option_key,
    const std::shared_ptr<utils::Verifier> &socket_option_value) {
  int result = SOCKET_OPTION_NOT_SET;
  if (!transport_protocol_->isRunning()) {
    switch (socket_option_key) {
      case GeneralTransportOptions::VERIFIER:
        verifier_ = socket_option_value;
        result = SOCKET_OPTION_SET;
        break;
      default:
        return result;
    }
  }

  return result;
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    const std::string &socket_option_value) {
  int result = SOCKET_OPTION_NOT_SET;
  if (!transport_protocol_->isRunning()) {
    switch (socket_option_key) {
      case GeneralTransportOptions::CERTIFICATE:
        key_id_ = verifier_->addKeyFromCertificate(socket_option_value);

        if (key_id_ != nullptr) {
          result = SOCKET_OPTION_SET;
        }
        break;

      case DataLinkOptions::OUTPUT_INTERFACE:
        output_interface_ = socket_option_value;
        portal_->setOutputInterface(output_interface_);
        result = SOCKET_OPTION_SET;
        break;

      default:
        return result;
    }
  }
  return result;
}

int ConsumerSocket::setSocketOption(int socket_option_key,
                                    ConsumerTimerCallback socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
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

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    double &socket_option_value) {
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

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    uint32_t &socket_option_value) {
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

    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    bool &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::RUNNING:
      socket_option_value = transport_protocol_->isRunning();
      break;

    case OtherOptions::VIRTUAL_DOWNLOAD:
      socket_option_value = virtual_download_;
      break;

    case GeneralTransportOptions::VERIFY_SIGNATURE:
      socket_option_value = verify_signature_;
      break;

    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    Name **socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::NETWORK_NAME:
      *socket_option_value = &network_name_;
      break;

    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

int ConsumerSocket::getSocketOption(
    int socket_option_key,
    ConsumerContentObjectCallback **socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
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

int ConsumerSocket::getSocketOption(
    int socket_option_key,
    ConsumerContentObjectVerificationCallback **socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key,
             ConsumerContentObjectVerificationCallback **socket_option_value)
          -> int {
        switch (socket_option_key) {
          case ConsumerCallbacksOptions::CONTENT_OBJECT_TO_VERIFY:
            *socket_option_value = &on_content_object_verification_;
            break;

          default:
            return SOCKET_OPTION_NOT_GET;
        }

        return SOCKET_OPTION_GET;
      });
}

int ConsumerSocket::getSocketOption(
    int socket_option_key, ConsumerInterestCallback **socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
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

int ConsumerSocket::getSocketOption(
    int socket_option_key, ConsumerManifestCallback **socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](int socket_option_key,
             ConsumerManifestCallback **socket_option_value) -> int {
        switch (socket_option_key) {
          case ConsumerCallbacksOptions::MANIFEST_INPUT:
            *socket_option_value = &on_manifest_;
            break;
          default:
            return SOCKET_OPTION_NOT_GET;
        }

        return SOCKET_OPTION_GET;
      });
}

int ConsumerSocket::getSocketOption(
    int socket_option_key,
    ConsumerContentObjectVerificationFailedCallback **socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
  return rescheduleOnIOService(
      socket_option_key, socket_option_value,
      [this](
          int socket_option_key,
          ConsumerContentObjectVerificationFailedCallback **socket_option_value)
          -> int {
        switch (socket_option_key) {
          case ConsumerCallbacksOptions::VERIFICATION_FAILED:
            *socket_option_value = &verification_failed_callback_;
            break;
          default:
            return SOCKET_OPTION_NOT_GET;
        }

        return SOCKET_OPTION_GET;
      });
}

int ConsumerSocket::getSocketOption(
    int socket_option_key, std::shared_ptr<Portal> &socket_option_value) {
  switch (socket_option_key) {
    case PORTAL:
      socket_option_value = portal_;
      break;

    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

int ConsumerSocket::getSocketOption(int socket_option_key,
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

int ConsumerSocket::getSocketOption(
    int socket_option_key,
    std::shared_ptr<utils::Verifier> &socket_option_value) {
  switch (socket_option_key) {
    case GeneralTransportOptions::VERIFIER:
      socket_option_value = verifier_;
      break;
    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    std::string &socket_option_value) {
  switch (socket_option_key) {
    case DataLinkOptions::OUTPUT_INTERFACE:
      socket_option_value = output_interface_;
      break;
    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

int ConsumerSocket::getSocketOption(int socket_option_key,
                                    TransportStatistics **socket_option_value) {
  switch (socket_option_key) {
    case OtherOptions::STATISTICS:
      *socket_option_value = &stats_;
      break;
    default:
      return SOCKET_OPTION_NOT_GET;
  }

  return SOCKET_OPTION_GET;
}

int ConsumerSocket::getSocketOption(
    int socket_option_key, ConsumerTimerCallback **socket_option_value) {
  // Reschedule the function on the io_service to avoid race condition in case
  // setSocketOption is called while the io_service is running.
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

}  // namespace interface

}  // namespace transport