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

#include <hicn/transport/protocols/cbr.h>
#include <hicn/transport/protocols/protocol.h>
#include <hicn/transport/protocols/raaqm.h>
#include <hicn/transport/protocols/rtc.h>
#include <hicn/transport/protocols/vegas.h>

#include <hicn/transport/utils/event_thread.h>
#include <hicn/transport/utils/sharable_vector.h>

#define CONSUMER_FINISHED 0
#define CONSUMER_BUSY 1
#define CONSUMER_RUNNING 2

namespace transport {

namespace interface {

class ConsumerSocket : public BaseSocket {
  friend class protocol::TransportProtocol;
  friend class protocol::VegasTransportProtocol;
  friend class protocol::RaaqmTransportProtocol;
  friend class protocol::CbrTransportProtocol;

 public:
  explicit ConsumerSocket(int protocol);
  explicit ConsumerSocket(int protocol, asio::io_service &io_service);

  ~ConsumerSocket();

  void connect() override;

  int consume(const Name &name, utils::SharableVector<uint8_t> &receive_buffer);

  int asyncConsume(
      const Name &name,
      std::shared_ptr<utils::SharableVector<uint8_t>> receive_buffer);

  void asyncSendInterest(Interest::Ptr &&interest,
                         Portal::ConsumerCallback *callback);

  void stop();

  void resume();

  asio::io_service &getIoService() override;

  int setSocketOption(int socket_option_key,
                      uint32_t socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      double socket_option_value) override;

  int setSocketOption(int socket_option_key, bool socket_option_value) override;

  int setSocketOption(int socket_option_key, Name socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      std::list<Prefix> socket_option_value) override;

  int setSocketOption(
      int socket_option_key,
      ProducerContentObjectCallback socket_option_value) override;

  int setSocketOption(
      int socket_option_key,
      ConsumerContentObjectVerificationCallback socket_option_value) override;

  int setSocketOption(
      int socket_option_key,
      ConsumerContentObjectCallback socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      ConsumerInterestCallback socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      ProducerInterestCallback socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      ConsumerContentCallback socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      ConsumerManifestCallback socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      IcnObserver *socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      HashAlgorithm socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      utils::CryptoSuite crypto_suite) override;

  int setSocketOption(int socket_option_key,
                      const utils::Identity &crypto_suite) override;

  int setSocketOption(int socket_option_key,
                      const std::string &socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      ConsumerTimerCallback socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      ProducerContentCallback socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      uint32_t &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      double &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      bool &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      Name &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      std::list<Prefix> &socket_option_value) override;

  int getSocketOption(
      int socket_option_key,
      ProducerContentObjectCallback &socket_option_value) override;

  int getSocketOption(
      int socket_option_key,
      ConsumerContentObjectVerificationCallback &socket_option_value) override;

  int getSocketOption(
      int socket_option_key,
      ConsumerContentObjectCallback &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      ConsumerInterestCallback &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      ProducerInterestCallback &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      ConsumerContentCallback &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      ConsumerManifestCallback &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      std::shared_ptr<Portal> &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      IcnObserver **socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      HashAlgorithm &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      utils::CryptoSuite &crypto_suite) override;

  int getSocketOption(int socket_option_key,
                      utils::Identity &crypto_suite) override;

  int getSocketOption(int socket_option_key,
                      std::string &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      ConsumerTimerCallback &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      ProducerContentCallback &socket_option_value) override;

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

  utils::Verifier verifier_;
  PARCKeyId *key_id_;
  bool verify_signature_;

  std::shared_ptr<utils::SharableVector<uint8_t>> content_buffer_;

  ConsumerInterestCallback on_interest_retransmission_;
  ConsumerInterestCallback on_interest_output_;
  ConsumerInterestCallback on_interest_timeout_;
  ConsumerInterestCallback on_interest_satisfied_;

  ConsumerContentObjectCallback on_content_object_input_;
  ConsumerContentObjectVerificationCallback on_content_object_verification_;

  ConsumerContentObjectCallback on_content_object_;
  ConsumerManifestCallback on_manifest_;

  ConsumerContentCallback on_payload_retrieved_;

  ConsumerTimerCallback on_timer_expires_;

  // Virtual download for traffic generator

  bool virtual_download_;
  bool rtt_stats_;

  Time t0_;
  Time t1_;
  asio::steady_timer timer_;
  uint32_t timer_interval_milliseconds_;
};

}  // namespace interface

}  // end namespace transport
