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
#include <hicn/transport/utils/content_store.h>
#include <hicn/transport/utils/event_thread.h>
#include <hicn/transport/utils/sharable_vector.h>

#include <atomic>
#include <cmath>
#include <mutex>
#include <queue>
#include <thread>

#define PUSH_API 1

#define REGISTRATION_NOT_ATTEMPTED 0
#define REGISTRATION_SUCCESS 1
#define REGISTRATION_FAILURE 2
#define REGISTRATION_IN_PROGRESS 3

namespace transport {

namespace interface {

using namespace core;

class ProducerSocket : public Socket<BasePortal>,
                       public BasePortal::ProducerCallback {
 public:
  explicit ProducerSocket();
  explicit ProducerSocket(asio::io_service &io_service);

  ~ProducerSocket();

  void connect() override;

  uint32_t produce(Name content_name, const uint8_t *buffer, size_t buffer_size,
                   bool is_last = true, uint32_t start_offset = 0);

  void produce(ContentObject &content_object);

  void asyncProduce(const Name &suffix, const uint8_t *buf, size_t buffer_size);

  void asyncProduce(const Name &suffix,
                    utils::SharableVector<uint8_t> &&output_buffer);

  void asyncProduce(ContentObject &content_object);

  void registerPrefix(const Prefix &producer_namespace);

  void serveForever();

  void stop();

  asio::io_service &getIoService() override;

  virtual void onInterest(Interest &interest);

  virtual void onInterest(Interest::Ptr &&interest) override {
    onInterest(*interest);
  };

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

  int setSocketOption(int socket_option_key,
                      ProducerInterestCallback socket_option_value) override;

  int setSocketOption(
      int socket_option_key,
      ConsumerContentObjectVerificationCallback socket_option_value) override;

  int setSocketOption(
      int socket_option_key,
      ConsumerContentObjectCallback socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      ConsumerInterestCallback socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      ConsumerContentCallback socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      ConsumerManifestCallback socket_option_value) override;

  int setSocketOption(int socket_option_key, IcnObserver *obs) override;

  int setSocketOption(int socket_option_key,
                      HashAlgorithm socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      utils::CryptoSuite socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      const utils::Identity &socket_option_value) override;

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

  int getSocketOption(int socket_option_key,
                      ProducerInterestCallback &socket_option_value) override;

  int getSocketOption(
      int socket_option_key,
      ConsumerContentObjectVerificationCallback &socket_option_value) override;

  int getSocketOption(
      int socket_option_key,
      ConsumerContentObjectCallback &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      ConsumerInterestCallback &socket_option_value) override;

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
                      utils::CryptoSuite &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      utils::Identity &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      std::string &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      ProducerContentCallback &socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      ConsumerTimerCallback &socket_option_value) override;

 protected:
  asio::io_service internal_io_service_;
  asio::io_service &io_service_;
  std::shared_ptr<Portal> portal_;
  std::size_t data_packet_size_;
  std::list<Prefix> served_namespaces_;
  uint32_t content_object_expiry_time_;

  // buffers
  utils::ContentStore output_buffer_;

  std::unique_ptr<utils::Identity> identity_;

 private:
  utils::EventThread async_thread_;

  int registration_status_;

  bool making_manifest_;

  // map for storing sequence numbers for several calls of the publish function
  std::unordered_map<Name, std::unordered_map<int, uint32_t>> seq_number_map_;

  int signature_type_;
  int signature_size_;

  HashAlgorithm hash_algorithm_;
  utils::CryptoSuite crypto_suite_;
  // std::unique_ptr<utils::Identity> identity_;
  // utils::Signer& signer_;

  // buffers

  std::queue<std::shared_ptr<const Interest>> input_buffer_;
  std::atomic_size_t input_buffer_capacity_;
  std::atomic_size_t input_buffer_size_;

#ifndef PUSH_API
  std::mutex pending_interests_mtx_;
  std::unordered_map<Name, std::shared_ptr<const Interest>> pending_interests_;
#endif

  // threads
  std::thread listening_thread_;
  std::thread processing_thread_;
  volatile bool processing_thread_stop_;
  volatile bool listening_thread_stop_;

  // callbacks
 protected:
  ProducerInterestCallback on_interest_input_;
  ProducerInterestCallback on_interest_dropped_input_buffer_;
  ProducerInterestCallback on_interest_inserted_input_buffer_;
  ProducerInterestCallback on_interest_satisfied_output_buffer_;
  ProducerInterestCallback on_interest_process_;

  ProducerContentObjectCallback on_new_segment_;
  ProducerContentObjectCallback on_content_object_to_sign_;
  ProducerContentObjectCallback on_content_object_in_output_buffer_;
  ProducerContentObjectCallback on_content_object_output_;
  ProducerContentObjectCallback on_content_object_evicted_from_output_buffer_;

  ProducerContentCallback on_content_produced_;

 private:
  void listen();

  void passContentObjectToCallbacks(
      const std::shared_ptr<ContentObject> &content_object);
};

}  // namespace interface

}  // end namespace transport
