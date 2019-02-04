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

#include <hicn/transport/interfaces/socket.h>
#include <hicn/transport/interfaces/socket_options_default_values.h>
#include <hicn/transport/protocols/protocol.h>
#include <hicn/transport/utils/event_thread.h>

#define CONSUMER_FINISHED 0
#define CONSUMER_BUSY 1
#define CONSUMER_RUNNING 2

namespace transport {

namespace interface {

class ConsumerSocket : public BaseSocket {
 public:
  explicit ConsumerSocket(int protocol);
  explicit ConsumerSocket(int protocol, asio::io_service &io_service);

  ~ConsumerSocket();

  void connect() override;

  int consume(const Name &name, ContentBuffer &receive_buffer);

  int asyncConsume(const Name &name, ContentBuffer &receive_buffer);

  void asyncSendInterest(Interest::Ptr &&interest,
                         Portal::ConsumerCallback *callback);

  void stop();

  void resume();

  asio::io_service &getIoService() override;

  TRANSPORT_ALWAYS_INLINE int setSocketOption(int socket_option_key,
                                              double socket_option_value) {
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

  TRANSPORT_ALWAYS_INLINE int setSocketOption(int socket_option_key,
                                              uint32_t socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::INPUT_BUFFER_SIZE:
        input_buffer_size_ = socket_option_value;
        break;

      case GeneralTransportOptions::OUTPUT_BUFFER_SIZE:
        output_buffer_size_ = socket_option_value;
        break;

      case GeneralTransportOptions::MAX_INTEREST_RETX:
        max_retransmissions_ = socket_option_value;
        break;

      case GeneralTransportOptions::INTEREST_LIFETIME:
        interest_lifetime_ = socket_option_value;
        break;

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

      case ConsumerCallbacksOptions::CONTENT_RETRIEVED:
        if (socket_option_value == VOID_HANDLER) {
          on_payload_retrieved_ = VOID_HANDLER;
          break;
        }

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

  TRANSPORT_ALWAYS_INLINE int setSocketOption(int socket_option_key,
                                              bool socket_option_value) {
    switch (socket_option_key) {
      case OtherOptions::VIRTUAL_DOWNLOAD:
        virtual_download_ = socket_option_value;
        break;

      case RaaqmTransportOptions::RTT_STATS:
        rtt_stats_ = socket_option_value;
        break;

      case GeneralTransportOptions::VERIFY_SIGNATURE:
        verify_signature_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(int socket_option_key,
                                              Name *socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::NETWORK_NAME:
        network_name_ = *socket_option_value;
        break;
      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key,
      ConsumerContentObjectCallback socket_option_value) {
    switch (socket_option_key) {
      case ConsumerCallbacksOptions::CONTENT_OBJECT_INPUT:
        on_content_object_input_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key,
      ConsumerContentObjectVerificationCallback socket_option_value) {
    switch (socket_option_key) {
      case ConsumerCallbacksOptions::CONTENT_OBJECT_TO_VERIFY:
        on_content_object_verification_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key, ConsumerInterestCallback socket_option_value) {
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
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key, ConsumerContentCallback socket_option_value) {
    switch (socket_option_key) {
      case ConsumerCallbacksOptions::CONTENT_RETRIEVED:
        on_payload_retrieved_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key, ConsumerManifestCallback socket_option_value) {
    switch (socket_option_key) {
      case ConsumerCallbacksOptions::MANIFEST_INPUT:
        on_manifest_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key, IcnObserver *socket_option_value) {
    switch (socket_option_key) {
      case RateEstimationOptions::RATE_ESTIMATION_OBSERVER:
        rate_estimation_observer_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key,
      const std::shared_ptr<utils::Verifier> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::VERIFIER:
        verifier_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key,
      const std::shared_ptr<std::vector<uint8_t>> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::APPLICATION_BUFFER:
        content_buffer_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key, const std::string &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::CERTIFICATE:
        key_id_ = verifier_->addKeyFromCertificate(socket_option_value);

        if (key_id_ != nullptr) {
          break;
        }

      case DataLinkOptions::OUTPUT_INTERFACE:
        output_interface_ = socket_option_value;
        portal_->setOutputInterface(output_interface_);
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int setSocketOption(
      int socket_option_key, ConsumerTimerCallback socket_option_value) {
    switch (socket_option_key) {
      case ConsumerCallbacksOptions::STATS_SUMMARY:
        stats_summary_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(int socket_option_key,
                                              double &socket_option_value) {
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

  TRANSPORT_ALWAYS_INLINE int getSocketOption(int socket_option_key,
                                              uint32_t &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::INPUT_BUFFER_SIZE:
        socket_option_value = input_buffer_size_;
        break;

      case GeneralTransportOptions::OUTPUT_BUFFER_SIZE:
        socket_option_value = output_buffer_size_;
        break;

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

  TRANSPORT_ALWAYS_INLINE int getSocketOption(int socket_option_key,
                                              bool &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::ASYNC_MODE:
        socket_option_value = is_async_;
        break;

      case GeneralTransportOptions::RUNNING:
        socket_option_value = transport_protocol_->isRunning();
        break;

      case OtherOptions::VIRTUAL_DOWNLOAD:
        socket_option_value = virtual_download_;
        break;

      case RaaqmTransportOptions::RTT_STATS:
        socket_option_value = rtt_stats_;
        break;

      case GeneralTransportOptions::VERIFY_SIGNATURE:
        socket_option_value = verify_signature_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(int socket_option_key,
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

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key,
      ConsumerContentObjectCallback **socket_option_value) {
    switch (socket_option_key) {
      case ConsumerCallbacksOptions::CONTENT_OBJECT_INPUT:
        *socket_option_value = &on_content_object_input_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key,
      ConsumerContentObjectVerificationCallback **socket_option_value) {
    switch (socket_option_key) {
      case ConsumerCallbacksOptions::CONTENT_OBJECT_TO_VERIFY:
        *socket_option_value = &on_content_object_verification_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key, ConsumerInterestCallback **socket_option_value) {
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
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key, ConsumerContentCallback **socket_option_value) {
    switch (socket_option_key) {
      case ConsumerCallbacksOptions::CONTENT_RETRIEVED:
        *socket_option_value = &on_payload_retrieved_;
        return SOCKET_OPTION_GET;

      default:
        return SOCKET_OPTION_NOT_GET;
    }
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key, ConsumerManifestCallback **socket_option_value) {
    switch (socket_option_key) {
      case ConsumerCallbacksOptions::MANIFEST_INPUT:
        *socket_option_value = &on_manifest_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
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

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key, IcnObserver **socket_option_value) {
    switch (socket_option_key) {
      case RateEstimationOptions::RATE_ESTIMATION_OBSERVER:
        *socket_option_value = (rate_estimation_observer_);
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
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

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key,
      std::shared_ptr<std::vector<uint8_t>> &socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::APPLICATION_BUFFER:
        socket_option_value = content_buffer_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key, std::string &socket_option_value) {
    switch (socket_option_key) {
      case DataLinkOptions::OUTPUT_INTERFACE:
        socket_option_value = output_interface_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  TRANSPORT_ALWAYS_INLINE int getSocketOption(
      int socket_option_key, ConsumerTimerCallback **socket_option_value) {
    switch (socket_option_key) {
      case ConsumerCallbacksOptions::STATS_SUMMARY:
        *socket_option_value = &stats_summary_;
        break;
      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

 protected:
  std::shared_ptr<TransportProtocol> transport_protocol_;

 private:
  // context inner state variables
  asio::io_service internal_io_service_;
  asio::io_service &io_service_;

  std::shared_ptr<Portal> portal_;

  utils::EventThread async_downloader_;

  Name network_name_;

  int interest_lifetime_;

  double min_window_size_;
  double max_window_size_;
  double current_window_size_;
  uint32_t max_retransmissions_;
  size_t output_buffer_size_;
  size_t input_buffer_size_;

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

  bool is_async_;

  // Verification parameters
  std::shared_ptr<utils::Verifier> verifier_;
  PARCKeyId *key_id_;
  bool verify_signature_;

  ContentBuffer content_buffer_;

  ConsumerInterestCallback on_interest_retransmission_;
  ConsumerInterestCallback on_interest_output_;
  ConsumerInterestCallback on_interest_timeout_;
  ConsumerInterestCallback on_interest_satisfied_;

  ConsumerContentObjectCallback on_content_object_input_;
  ConsumerContentObjectVerificationCallback on_content_object_verification_;

  ConsumerContentObjectCallback on_content_object_;
  ConsumerManifestCallback on_manifest_;

  ConsumerContentCallback on_payload_retrieved_;

  ConsumerTimerCallback stats_summary_;

  // Virtual download for traffic generator

  bool virtual_download_;
  bool rtt_stats_;

  uint32_t timer_interval_milliseconds_;
};

}  // namespace interface

}  // end namespace transport
