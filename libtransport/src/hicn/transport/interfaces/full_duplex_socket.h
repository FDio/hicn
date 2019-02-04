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

/*
 * This class is created for sending/receiving data over an ICN network.
 */

#pragma once

#include <hicn/transport/core/prefix.h>
#include <hicn/transport/interfaces/async_transport.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_producer.h>
#include <hicn/transport/portability/portability.h>

#include <unordered_set>
#include <vector>

namespace transport {

namespace interface {

enum class MessageType : uint8_t { ACTION, RESPONSE, PAYLOAD };

enum class Action : uint8_t {
  SUBSCRIBE,
  CANCEL_SUBSCRIPTION,
  SIGNAL_PRODUCTION,
};

enum class ReturnCode : uint8_t {
  OK,
  FAILED,
};

struct MessageHeader {
  MessageType msg_type;
  uint8_t reserved[2];
};

struct ActionMessage {
  MessageHeader header;
  Action action;
  uint64_t name[2];
};

struct ResponseMessage {
  MessageHeader header;
  ReturnCode return_code;
};

struct SubscriptionResponseMessage {
  ResponseMessage response;
  uint64_t name[2];
};

struct PayloadMessage {
  MessageHeader header;
  uint8_t reserved[1];
};

// struct NotificationMessage {
//   Action action;
//   uint8_t reserved[3];
//   uint64_t
// }

using core::Prefix;

class AsyncFullDuplexSocket : public AsyncSocket,
                              public AsyncReader,
                              public AsyncWriter,
                              public AsyncAcceptor {
 private:
  struct Counters {
    uint64_t app_bytes_written_;
    uint64_t app_bytes_read_;

    TRANSPORT_ALWAYS_INLINE void updateBytesWritten(uint64_t bytes) {
      app_bytes_written_ += bytes;
    }

    TRANSPORT_ALWAYS_INLINE void updateBytesRead(uint64_t bytes) {
      app_bytes_read_ += bytes;
    }
  };

 public:
  using UniquePtr = std::unique_ptr<AsyncFullDuplexSocket>;
  using SharedPtr = std::unique_ptr<AsyncFullDuplexSocket>;

  AsyncFullDuplexSocket(const Prefix &locator, asio::io_service &io_service);
  AsyncFullDuplexSocket(const core::Prefix &locator);

  ~AsyncFullDuplexSocket() {
    TRANSPORT_LOGI("Adios AsyncFullDuplexSocket!!!");
  };

  using ReadCallback = AsyncReader::ReadCallback;
  using WriteCallback = AsyncWriter::WriteCallback;

  TRANSPORT_ALWAYS_INLINE void setReadCB(ReadCallback *callback) override {
    read_callback_ = callback;
  }

  TRANSPORT_ALWAYS_INLINE ReadCallback *getReadCallback() const override {
    return read_callback_;
  }

  TRANSPORT_ALWAYS_INLINE void setWriteCB(WriteCallback *callback) override {
    write_callback_ = callback;
  }

  TRANSPORT_ALWAYS_INLINE WriteCallback *getWriteCallback() const override {
    return write_callback_;
  }

  TRANSPORT_ALWAYS_INLINE const core::Prefix &getLocator() { return locator_; }

  void connect(ConnectCallback *callback, const core::Prefix &prefix) override;

  void write(WriteCallback *callback, const void *buf, size_t bytes,
             const PublicationOptions &options,
             WriteFlags flags = WriteFlags::NONE) override;

  virtual void write(WriteCallback *callback, ContentBuffer &&output_buffer,
                     const PublicationOptions &options,
                     WriteFlags flags = WriteFlags::NONE) override;

  void waitForSubscribers(AcceptCallback *cb) override;

  // void writev(
  //     WriteCallback* callback,
  //     const iovec* vec,
  //     size_t count,
  //     Name &&content_to_publish_name,
  //     WriteFlags flags = WriteFlags::NONE) override;

  void close() override;

  void closeNow() override;

  void shutdownWrite() override;

  void shutdownWriteNow() override;

  bool good() const override;

  bool readable() const override;

  bool writable() const override;

  bool isPending() const override;

  bool connected() const override;

  bool error() const override;

  void setSendTimeout(uint32_t milliseconds) override;

  size_t getAppBytesWritten() const override;
  size_t getRawBytesWritten() const override;
  size_t getAppBytesReceived() const override;
  size_t getRawBytesReceived() const override;

  uint32_t getSendTimeout() const override;

 private:
  std::shared_ptr<core::ContentObject> decodeSynchronizationMessage(
      const core::Interest &interest);

  class OnConnectCallback : public BasePortal::ConsumerCallback {
   public:
    OnConnectCallback(AsyncFullDuplexSocket &socket) : socket_(socket){};
    virtual ~OnConnectCallback() = default;
    void onContentObject(core::Interest::Ptr &&,
                         core::ContentObject::Ptr &&content_object) override;
    void onTimeout(core::Interest::Ptr &&interest) override;

   private:
    AsyncFullDuplexSocket &socket_;
  };

  class OnSignalCallback : public BasePortal::ConsumerCallback {
   public:
    OnSignalCallback(AsyncFullDuplexSocket &socket) : socket_(socket){};
    virtual ~OnSignalCallback() = default;
    void onContentObject(core::Interest::Ptr &&,
                         core::ContentObject::Ptr &&content_object);
    void onTimeout(core::Interest::Ptr &&interest);

   private:
    AsyncFullDuplexSocket &socket_;
  };

  void onControlInterest(ProducerSocket &s, const core::Interest &i);
  void onContentProduced(ProducerSocket &producer, const std::error_code &ec,
                         uint64_t bytes_written);
  void onContentRetrieved(ConsumerSocket &s, std::size_t size,
                          const std::error_code &ec);

  void signalProductionToSubscribers(const core::Name &name);
  void piggybackPayloadToSubscribers(const core::Name &name,
                                     const uint8_t *buffer, std::size_t bytes);

  std::shared_ptr<core::ContentObject> createAck();
  std::shared_ptr<core::ContentObject> createSubscriptionResponse(
      const core::Name &name);

  core::Prefix locator_;
  uint32_t incremental_suffix_;
  core::Name sync_notification_;
  //  std::unique_ptr<BasePortal> portal_;
  asio::io_service internal_io_service_;
  asio::io_service &io_service_;
  asio::io_service::work work_;

  // These names represent the "locator" of a certain
  // peer that subscribed to this.
  std::unordered_set<core::Name> subscribers_;

  // Useful for publishing / Retrieving data
  std::unique_ptr<ProducerSocket> producer_;
  std::unique_ptr<ConsumerSocket> consumer_;

  ReadCallback *read_callback_;
  WriteCallback *write_callback_;
  ConnectCallback *connect_callback_;
  AcceptCallback *accept_callback_;

  std::unique_ptr<OnConnectCallback> internal_connect_callback_;
  std::unique_ptr<OnSignalCallback> internal_signal_callback_;

  uint32_t send_timeout_milliseconds_;
  struct Counters counters_;
  ContentBuffer receive_buffer_;
};

}  // namespace interface
}  // namespace transport
