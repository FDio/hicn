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

/**
 * @brief Main interface for consumer applications.
 *
 * The consumer socket is the main interface for a consumer application.
 * It allows to retrieve an application data from one/many producers, by hiding
 * all the complexity of the transport protocol used underneath.
 */
class ConsumerSocket : public BaseSocket {
 public:
  /**
   * @brief Create a new consumer socket.
   *
   * @param protocol - The transport protocol to use. So far the following
   * transport are supported:
   *  - CBR: Constant bitrate
   *  - Raaqm: Based on paper: Optimal multipath congestion control and request
   * forwarding in information-centric networks: Protocol design and
   * experimentation. G Carofiglio, M Gallo, L Muscariello. Computer Networks
   * 110, 104-117
   *  - RTC: Real time communication
   */
  explicit ConsumerSocket(int protocol);

  /**
   * @brief Destroy the consumer socket.
   */
  ~ConsumerSocket();

  /**
   * @brief Connect the consumer socket to the underlying hICN forwarder.
   */
  void connect() override;

  /**
   * Retrieve a content using the protocol specified in the constructor.
   * This function blocks until the whole content is downloaded.
   * For monitoring the status of the download, the application MUST set the
   * CONTENT_RETRIEVED callback using setSocketOption(). This callback will be
   * called periodically, allowing the application to save the retrieved data.
   *
   * @param name - The name of the content to retrieve.
   * @param receive_buffer - The application buffer, which will be filled with
   * the application content.
   *
   * @return CONSUMER_BUSY if a pending download exists
   * @return CONSUMER_FINISHED when the download finishes
   *
   * Notice that the fact consume() returns CONSUMER_FINISHED does not imply the
   * content retrieval succeeded. This information can be obtained from the
   * error code in CONTENT_RETRIEVED callback.
   */
  int consume(const Name &name, ContentBuffer &receive_buffer);

  /**
   * @brief Start a download operation in another thread, without blocking until
   * it finishes. If the asyncConsume() is called multiple times, the consumer
   * operations wil be queued and executed in order.
   *
   * @param name - The name of the content to retrieve.
   * @param receive_buffer - The application buffer, which will be filled with
   * the application content.
   *
   * @return CONSUMER_RUNNING, to signal the download is ongoing.
   */
  int asyncConsume(const Name &name, ContentBuffer &receive_buffer);

  /**
   * Send an interest asynchronously in another thread, which is the same used
   * for asyncConsume.
   *
   * @param interest - An Interest::Ptr to the interest. Notice that the
   * application looses the ownership of the interest, which is transferred to
   * the library itself.
   * @param callback - A ConsumerCallback containing the events to be trigger in
   * case of timeout or content reception.
   *
   */
  void asyncSendInterest(Interest::Ptr &&interest,
                         Portal::ConsumerCallback *callback);

  /**
   * Stops the consumer socket. If several downloads are queued, this call stops
   * just the current one.
   */
  void stop();

  /**
   * Resume the download from the same exact point it stopped.
   */
  void resume();

  /**
   * Get the io_service which is running the transport protocol event loop.
   *
   * @return A reference to the internal io_service where the transport protocol
   * is running.
   */
  asio::io_service &getIoService() override;

  /**
   * Set the socket options which are represented by a double value:
   * MIN_WINDOW_SIZE: The max value of the congestion window
   * MAX_WINDOW_SIZE: The min value of the congestion window
   * CURRENT_WINDOW_SIZE: The current value of the window
   * GAMMA_VALUE: The RAAQM gamma parameter
   * BETA_VALUE: The RAAQM beta parameter
   * DROP_FACTOR: The RAAQM drop factor parameter
   * MINIMUM_DROP_PROBABILITY: The RAAQM minimmum drop probability
   * RATE_ESTIMATION_ALPHA: The alpha value for the rate estimation.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_SET otherwise
   */
  TRANSPORT_ALWAYS_INLINE int setSocketOption(int socket_option_key,
                                              double socket_option_value) {
    switch (socket_option_key) {
      case GeneralTransportOptions::MIN_WINDOW_SIZE:
        min_window_size_ = socket_option_value;
        break;

      case GeneralTransportOptions::MAX_WINDOW_SIZE:
        max_window_size_ = socket_option_value;
        break;

      case GeneralTransportOptions::CURRENT_WINDOW_SIZE:
        current_window_size_ = socket_option_value;
        break;

      case RaaqmTransportOptions::GAMMA_VALUE:
        gamma_ = socket_option_value;
        break;

      case RaaqmTransportOptions::BETA_VALUE:
        beta_ = socket_option_value;
        break;

      case RaaqmTransportOptions::DROP_FACTOR:
        drop_factor_ = socket_option_value;
        break;

      case RaaqmTransportOptions::MINIMUM_DROP_PROBABILITY:
        minimum_drop_probability_ = socket_option_value;
        break;

      case RateEstimationOptions::RATE_ESTIMATION_ALPHA:
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

  /**
   * Get the socket options which are represented by a double value:
   * MIN_WINDOW_SIZE: The max value of the congestion window
   * MAX_WINDOW_SIZE: The min value of the congestion window
   * CURRENT_WINDOW_SIZE: The current value of the window
   * GAMMA_VALUE: The RAAQM gamma parameter
   * BETA_VALUE: The RAAQM beta parameter
   * DROP_FACTOR: The RAAQM drop factor parameter
   * MINIMUM_DROP_PROBABILITY: The RAAQM minimmum drop probability
   * RATE_ESTIMATION_ALPHA: The alpha value for the rate estimation.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a uint32_t value:
   * MAX_INTEREST_RETX: If the same interest is retransmitted more than
   * MAX_INTEREST_RETX, the download is aborted.
   *
   * INTEREST_LIFETIME: The lifetime of the interest INTEREST_RETRANSMISSION:
   * When socket_option_value == VOID_HANDLER, the callback called when an
   * interest retransmission happens is uninstalled.
   *
   * INTEREST_EXPIRED:  When socket_option_value ==
   * VOID_HANDLER, the callback called when an interest times out is
   * uninstalled.
   *
   * INTEREST_SATISFIED: When socket_option_value == VOID_HANDLER,
   * the callback called when an interest is satisfied is uninstalled.
   *
   * INTEREST_OUTPUT: When socket_option_value == VOID_HANDLER, the callback
   * called when an interest is sent out to the network is uninstalled.
   *
   * CONTENT_OBJECT_INPUT: When socket_option_value == VOID_HANDLER, the
   * callback called when a content object is received is uninstalled.
   *
   * CONTENT_OBJECT_TO_VERIFY: When socket_option_value == VOID_HANDLER, the
   * callback called when a content object has to be verified is uninstalled.
   *
   * CONTENT_RETRIEVED: When socket_option_value == VOID_HANDLER, the callback
   * called when the content has to be passed to the application is uninstalled.
   *
   * RATE_ESTIMATION_BATCH_PARAMETER: The rate estimation batch parameter.
   *
   * RATE_ESTIMATION_CHOICE: The rate estimation choice parameter.
   *
   * STATS_INTERVAL: The period (in milliseconds) of the stats callback.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_SET otherwise
   */
  TRANSPORT_ALWAYS_INLINE int setSocketOption(int socket_option_key,
                                              uint32_t socket_option_value) {
    switch (socket_option_key) {
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

  /**
   * Get the socket options which are represented by a uint32_t value:
   * MAX_INTEREST_RETX: If the same interest is retransmitted more than
   *
   * MAX_INTEREST_RETX, the download is aborted.
   *
   * INTEREST_LIFETIME: The lifetime of the interest
   *
   * RATE_ESTIMATION_BATCH_PARAMETER: The rate estimation batch parameter.
   *
   * RATE_ESTIMATION_CHOICE: The rate estimation choice parameter.
   *
   * STATS_INTERVAL: The period (in milliseconds) of the stats callback.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_GET otherwise
   */
  TRANSPORT_ALWAYS_INLINE int getSocketOption(int socket_option_key,
                                              uint32_t &socket_option_value) {
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

  /**
   * Set the socket options which are represented by a boolean value:
   *
   * VIRTUAL_DOWNLOAD: Decides whether the content retrieved should be saved or
   * not.
   *
   * VERIFY_SIGNATURE: Decides whether verifying the signature of the data
   * packet retrieved
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_SET otherwise
   */
  TRANSPORT_ALWAYS_INLINE int setSocketOption(int socket_option_key,
                                              bool socket_option_value) {
    switch (socket_option_key) {
      case OtherOptions::VIRTUAL_DOWNLOAD:
        virtual_download_ = socket_option_value;
        break;

      case GeneralTransportOptions::VERIFY_SIGNATURE:
        verify_signature_ = socket_option_value;
        break;

      default:
        return SOCKET_OPTION_NOT_SET;
    }

    return SOCKET_OPTION_SET;
  }

  /**
   * Get the socket options which are represented by a boolean value:
   *
   * VIRTUAL_DOWNLOAD: Decides whether the content retrieved should be saved or
   * not.
   *
   * VERIFY_SIGNATURE: Decides whether verifying the signature of the data
   * packet retrieved
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_GET otherwise
   */
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

      case GeneralTransportOptions::VERIFY_SIGNATURE:
        socket_option_value = verify_signature_;
        break;

      default:
        return SOCKET_OPTION_NOT_GET;
    }

    return SOCKET_OPTION_GET;
  }

  /**
   * Set the socket options which are represented by a Name*:
   *
   * NETWORK_NAME: Set the name the consumer should use to download. This
   * value, when used during the downlaod, overrides the name set by the
   * consume() API.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_SET otherwise
   */
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

  /**
   * Get the socket options which are represented by a Name*:
   *
   * NETWORK_NAME: Get the name the consumer should use to download. This
   * value, when used during the download, overrides the name set by the
   * consume() API.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * ConsumerContentObjectCallback:
   *
   * CONTENT_OBJECT_INPUT: The callback to be called when a content object is
   * received by the transport.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_SET otherwise
   */
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

  /**
   * Get the socket options which are represented by a
   * ConsumerContentObjectCallback:
   *
   * CONTENT_OBJECT_INPUT: The callback to be called when a content object is
   * received by the transport.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * ConsumerContentObjectVerificationCallback:
   *
   * CONTENT_OBJECT_INPUT: The callback to be called when a content object has
   * to be verified by the application. If this callback is not set the
   * transport tries to use a verifier passed by the application.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_SET otherwise
   */
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

  /**
   * Get the socket options which are represented by a
   * ConsumerContentObjectVerificationCallback:
   *
   * CONTENT_OBJECT_INPUT: The callback to be called when a content object has
   * to be verified by the application. If this callback is not set the
   * transport tries to use a verifier passed by the application.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * ConsumerInterestCallback:
   *
   * INTEREST_RETRANSMISSION: The callback to be called when an interest is
   * retransmitted.
   *
   * INTEREST_OUTPUT: The callback to be called when an interest is sent out to
   * the network.
   *
   * INTEREST_EXPIRED: The callback to be called when an interest is timed out.
   *
   * INTEREST_SATISFIED: The callback to be called when an interest is
   * satisfied, i.e. a corresponding data packet is received.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_SET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * ConsumerInterestCallback:
   *
   * INTEREST_RETRANSMISSION: The callback to be called when an interest is
   * retransmitted.
   *
   * INTEREST_OUTPUT: The callback to be called when an interest is sent out to
   * the network.
   *
   * INTEREST_EXPIRED: The callback to be called when an interest is timed out.
   *
   * INTEREST_SATISFIED: The callback to be called when an interest is
   * satisfied, i.e. a corresponding data packet is received.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * ConsumerContentCallback:
   *
   * CONTENT_RETRIEVED: The callback to be called when the whole content is
   * downloaded.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_SET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * ConsumerContentCallback:
   *
   * CONTENT_RETRIEVED: The callback to be called when the whole content is
   * downloaded.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * ConsumerManifestCallback:
   *
   * CONTENT_RETRIEVED: The callback to be called when a manifest is received.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * ConsumerManifestCallback:
   *
   * CONTENT_RETRIEVED: The callback to be called when a manifest is received.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * IcnObserver *:
   *
   * RATE_ESTIMATION_OBSERVER: An observer used for the rate estimation
   * operations.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_SET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * IcnObserver *:
   *
   * RATE_ESTIMATION_OBSERVER: An observer used for the rate estimation
   * operations.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * std::shared_ptr<Portal> *:
   *
   * PORTAL: A shared pointer to the internal portal used for
   * sending/receiveing. This function is used by the transport protocols for
   * retrieving the portal to use for sending/receiving interests/data, but
   * SHOULD NOT e used by applications, which normally do not need to deal with
   * interest and data.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_SET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * std::shared_ptr<utils::Verifier>:
   *
   * VERIFIER: A verifier used by the transport for verifying the data packets
   * received. This is a shared ptr to underline the fact that the verifier is
   * an application object and here the transport is sharing its ownership with
   * the application. The transport itself does not own a verifier.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_SET otherwise
   */
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

  /**
   * Get the socket options which are represented by a
   * std::shared_ptr<utils::Verifier>:
   *
   * VERIFIER: A verifier used by the transport for verifying the data packets
   * received. This is a shared ptr to underline the fact that the verifier is
   * an application object and here the transport is sharing its ownership with
   * the application. The transport itself does not own a verifier.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * std::shared_ptr<std::vector<uint8_t>>
   *
   * APPLICATION_BUFFER: A shared pointer to the buffer where the transport will
   * write the data downloaded.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_SET otherwise
   */
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

  /**
   * Get the socket options which are represented by a
   * std::shared_ptr<std::vector<uint8_t>>
   *
   * APPLICATION_BUFFER: A shared pointer to the buffer where the transport will
   * write the data downloaded.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * const std::string
   *
   * CERTIFICATE: The path of the certificate containing the producer public
   * key. OUTPUT_INTERFACE: The output interface where to send out the
   * interests. This option is not supported yet.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_SET otherwise
   */
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

  /**
   * Get the socket options which are represented by a
   * const std::string
   *
   * OUTPUT_INTERFACE: The output interface where to send out the interests.
   * This option is not supported yet.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value [out] - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_GET otherwise
   */
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

  /**
   * Set the socket options which are represented by a
   * ConsumerTimerCallback
   *
   * STATS_SUMMARY: The callback to be called every STATS_INTERVAL milliseconds.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_SET if the key does not exist or the value is
   * wrong return SOCKET_OPTION_SET otherwise
   */
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

  /**
   * Get the socket options which are represented by a
   * ConsumerTimerCallback
   *
   * STATS_SUMMARY: The callback to be called every STATS_INTERVAL milliseconds.
   *
   * @param socket_option_key - One of the values above
   * @param socket_option_value - The value of the parameter.
   *
   * @return SOCKET_OPTION_NOT_GET if the key does not exist or the value is
   * wrong
   * @return SOCKET_OPTION_GET otherwise
   */
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
  std::unique_ptr<TransportProtocol> transport_protocol_;

 private:
  /**
   * @brief Internal io_service where the event loop runs.
   */
  asio::io_service internal_io_service_;
  asio::io_service &io_service_;

  /**
   * Shared reference
   */
  std::shared_ptr<Portal> portal_;

  utils::EventThread async_downloader_;

  Name network_name_;

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

  bool is_async_;

  // Verification parameters
  std::shared_ptr<utils::Verifier> verifier_;
  PARCKeyId *key_id_;
  bool verify_signature_;

  // Callbacks
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

  uint32_t timer_interval_milliseconds_;
};

}  // namespace interface

}  // end namespace transport
