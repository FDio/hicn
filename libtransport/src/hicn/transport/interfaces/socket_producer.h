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
#include <hicn/transport/utils/signer.h>
#include <hicn/transport/utils/suffix_strategy.h>

#include <atomic>
#include <cmath>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

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

  bool isRunning() override { return !io_service_.stopped(); };

  virtual uint32_t produce(Name content_name, const uint8_t *buffer,
                           size_t buffer_size, bool is_last = true,
                           uint32_t start_offset = 0) {
    return ProducerSocket::produce(
        content_name, utils::MemBuf::copyBuffer(buffer, buffer_size), is_last,
        start_offset);
  }

  virtual uint32_t produce(Name content_name,
                           std::unique_ptr<utils::MemBuf> &&buffer,
                           bool is_last = true, uint32_t start_offset = 0);

  virtual void produce(ContentObject &content_object);

  virtual void produce(const uint8_t *buffer, size_t buffer_size) {
    produce(utils::MemBuf::copyBuffer(buffer, buffer_size));
  }

  virtual void produce(std::unique_ptr<utils::MemBuf> &&buffer) {
    // This API is meant to be used just with the RTC producer.
    // Here it cannot be used since no name for the content is specified.
    throw errors::NotImplementedException();
  }

  virtual void asyncProduce(const Name &suffix, const uint8_t *buf,
                            size_t buffer_size, bool is_last = true,
                            uint32_t *start_offset = nullptr);

  void asyncProduce(const Name &suffix);

  virtual void asyncProduce(Name content_name,
                            std::unique_ptr<utils::MemBuf> &&buffer,
                            bool is_last, uint32_t offset,
                            uint32_t **last_segment = nullptr);

  virtual void asyncProduce(ContentObject &content_object);

  virtual void registerPrefix(const Prefix &producer_namespace);

  void serveForever();

  void stop();

  asio::io_service &getIoService() override;

  virtual void onInterest(Interest &interest);

  virtual void onInterest(Interest::Ptr &&interest) override {
    onInterest(*interest);
  };

  virtual int setSocketOption(int socket_option_key,
                              uint32_t socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              std::nullptr_t socket_option_value);

  virtual int setSocketOption(int socket_option_key, bool socket_option_value);

  virtual int setSocketOption(int socket_option_key, Name *socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              std::list<Prefix> socket_option_value);

  virtual int setSocketOption(
      int socket_option_key, ProducerContentObjectCallback socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              ProducerInterestCallback socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              ProducerContentCallback socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              HashAlgorithm socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              utils::CryptoSuite socket_option_value);

  virtual int setSocketOption(
      int socket_option_key,
      const std::shared_ptr<utils::Signer> &socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              const std::string &socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              uint32_t &socket_option_value);

  virtual int getSocketOption(int socket_option_key, bool &socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              std::list<Prefix> &socket_option_value);

  virtual int getSocketOption(
      int socket_option_key,
      ProducerContentObjectCallback **socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              ProducerContentCallback **socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              ProducerInterestCallback **socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              std::shared_ptr<Portal> &socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              HashAlgorithm &socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              utils::CryptoSuite &socket_option_value);

  virtual int getSocketOption(
      int socket_option_key,
      std::shared_ptr<utils::Signer> &socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              std::string &socket_option_value);

  // If the thread calling lambda_func is not the same of io_service, this
  // function reschedule the function on it
  template <typename Lambda, typename arg2>
  int rescheduleOnIOService(int socket_option_key, arg2 socket_option_value,
                            Lambda lambda_func) {
    // To enforce type check
    std::function<int(int, arg2)> func = lambda_func;
    int result = SOCKET_OPTION_SET;
    if (listening_thread_.joinable() &&
        std::this_thread::get_id() != listening_thread_.get_id()) {
      std::mutex mtx;
      /* Condition variable for the wait */
      std::condition_variable cv;
      bool done = false;
      io_service_.dispatch([&socket_option_key, &socket_option_value, &mtx, &cv,
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

  template <typename Lambda, typename arg2>
  int rescheduleOnIOServiceWithReference(int socket_option_key,
                                         arg2 &socket_option_value,
                                         Lambda lambda_func) {
    // To enforce type check
    std::function<int(int, arg2 &)> func = lambda_func;
    int result = SOCKET_OPTION_SET;
    if (listening_thread_.joinable() &&
        std::this_thread::get_id() != this->listening_thread_.get_id()) {
      std::mutex mtx;
      /* Condition variable for the wait */
      std::condition_variable cv;

      bool done = false;
      io_service_.dispatch([&socket_option_key, &socket_option_value, &mtx, &cv,
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
  // Threads
 protected:
  std::thread listening_thread_;
  asio::io_service internal_io_service_;
  asio::io_service &io_service_;
  std::shared_ptr<Portal> portal_;
  std::atomic<size_t> data_packet_size_;
  std::list<Prefix>
      served_namespaces_;  // No need to be threadsafe, this is always modified
                           // by the application thread
  std::atomic<uint32_t> content_object_expiry_time_;

  // buffers
  // ContentStore is thread-safe
  utils::ContentStore output_buffer_;

  utils::EventThread async_thread_;
  int registration_status_;

  std::atomic<bool> making_manifest_;

  // map for storing sequence numbers for several calls of the publish
  // function
  std::unordered_map<Name, std::unordered_map<int, uint32_t>> seq_number_map_;

  std::atomic<HashAlgorithm> hash_algorithm_;
  std::atomic<utils::CryptoSuite> crypto_suite_;
  utils::SpinLock signer_lock_;
  std::shared_ptr<utils::Signer> signer_;
  core::NextSegmentCalculationStrategy suffix_strategy_;

  // While manifests are being built, contents are stored in a queue
  std::queue<std::shared_ptr<ContentObject>> content_queue_;

  // callbacks
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

}  // namespace transport
