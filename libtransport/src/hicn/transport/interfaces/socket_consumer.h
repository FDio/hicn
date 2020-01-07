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
#include <hicn/transport/utils/verifier.h>

extern "C" {
#include <parc/security/parc_KeyId.h>
}

#define CONSUMER_FINISHED 0
#define CONSUMER_BUSY 1
#define CONSUMER_RUNNING 2

namespace transport {

namespace interface {

using namespace core;
using namespace protocol;

/**
 * @brief Main interface for consumer applications.
 *
 * The consumer socket is the main interface for a consumer application.
 * It allows to retrieve an application data from one/many producers, by
 * hiding all the complexity of the transport protocol used underneath.
 */
class ConsumerSocket : public BaseSocket {
 public:
  /**
   * The ReadCallback is a class which can be used by the transport for both
   * querying the application needs and notifying events.
   *
   * Beware that the methods of this class will be called synchronously while
   * the transport is working, so the operations the application is performing
   * on the data retrieved should be executed in another thread in an
   * asynchronous manner. Blocking one of these callbacks means blocking the
   * transport.
   */
  class ReadCallback {
   public:
    virtual ~ReadCallback() = default;

    /**
     * This API will specify to the transport whether the buffer should be
     * allocated by the application (and then the retrieved content will be
     * copied there) or the transport should allocate the buffer and "move" it
     * to the application. In other words, if isBufferMovable return true, the
     * transport will transfer the ownership of the read buffer to the
     * application, without performing an additional copy, while if it returns
     * false the transport will use the getReadBuffer API.
     *
     * By default this method returns true.
     *
     */
    virtual bool isBufferMovable() noexcept { return true; }

    /**
     * This method will be called by the transport when the content is
     * available. The application can then allocate its own buffer and provide
     * the address to the transport, which will use it for writing the data.
     * Note that if the application won't allocate enough memory this method
     * will be called several times, until the internal read buffer will be
     * emptied. For ensuring this method will be called once, applications
     * should allocate at least maxBufferSize() bytes.
     *
     * @param application_buffer - Pointer to the application's buffer.
     * @param max_length - The length of the application buffer.
     */
    virtual void getReadBuffer(uint8_t **application_buffer,
                               size_t *max_length) = 0;

    /**
     * This method will be called by the transport after calling getReadBuffer,
     * in order to notify the application that length bytes are available in the
     * buffer. The max_length size of the buffer could be larger than the actual
     * amount of bytes written.
     *
     * @param length - The number of bytes placed in the buffer.
     */
    virtual void readDataAvailable(size_t length) noexcept = 0;

    /**
     * This method will be called by the transport for understanding how many
     * bytes it should read (at most) before notifying the application.
     *
     * By default it reads 64 KB.
     */
    virtual size_t maxBufferSize() const { return 64 * 1024; }

    /**
     * This method will be called by the transport iff (isBufferMovable ==
     * true). The unique_ptr underlines the fact that the ownership of the
     * buffer is being transferred to the application.
     *
     * @param buffer - The buffer
     */
    virtual void readBufferAvailable(
        std::unique_ptr<utils::MemBuf> &&buffer) noexcept {}

    /**
     * readError() will be invoked if an error occurs reading from the
     * transport.
     *
     * @param ec - An error code describing the error.
     */
    virtual void readError(const std::error_code ec) noexcept = 0;

    /**
     * This callback will be invoked when the whole content is retrieved. The
     * transport itself knows when a content is retrieved (since it is not an
     * opaque bytestream like TCP), and the transport itself is able to tell
     * the application when the transfer is done.
     */
    virtual void readSuccess(std::size_t total_size) noexcept = 0;

    virtual void afterRead() {}
  };

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
  explicit ConsumerSocket(int protocol, asio::io_service &io_service);

  /**
   * @brief Destroy the consumer socket.
   */
  ~ConsumerSocket();

  /**
   * @brief Connect the consumer socket to the underlying hICN forwarder.
   */
  void connect() override;

  /**
   * @brief Check whether consumer socket is active or not.
   */
  bool isRunning() override { return transport_protocol_->isRunning(); }

  /**
   * Retrieve a content using the protocol specified in the constructor.
   * This function blocks until the whole content is downloaded.
   * For monitoring the status of the download, the application MUST set the
   * ConsumerRead callback. This callback will be called periodically (depending
   * on the needs of the application), allowing the application to save the
   * retrieved data.
   *
   * @param name - The name of the content to retrieve.
   *
   * @return CONSUMER_BUSY if a pending download exists
   * @return CONSUMER_FINISHED when the download finishes
   *
   * Notice that the fact consume() returns CONSUMER_FINISHED does not imply the
   * content retrieval succeeded. This information can be obtained from the
   * error code in CONTENT_RETRIEVED callback.
   */
  virtual int consume(const Name &name);
  virtual int asyncConsume(const Name &name);

  /**
   * Verify the packets containing a key after the origin of the key has been
   * validated by the client.
   *
   * @return true if all packets are valid, false otherwise
   */
  virtual bool verifyKeyPackets();

  /**
   * Stops the consumer socket. If several downloads are queued (using
   * asyncConsume), this call stops just the current one.
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

  virtual int setSocketOption(int socket_option_key,
                              ReadCallback *socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              ReadCallback **socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              double socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              uint32_t socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              std::nullptr_t socket_option_value);

  virtual int setSocketOption(int socket_option_key, bool socket_option_value);

  virtual int setSocketOption(
      int socket_option_key, ConsumerContentObjectCallback socket_option_value);

  virtual int setSocketOption(
      int socket_option_key,
      ConsumerContentObjectVerificationCallback socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              ConsumerInterestCallback socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              ConsumerManifestCallback socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              IcnObserver *socket_option_value);

  virtual int setSocketOption(
      int socket_option_key,
      const std::shared_ptr<utils::Verifier> &socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              const std::string &socket_option_value);

  virtual int setSocketOption(int socket_option_key,
                              ConsumerTimerCallback socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              double &socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              uint32_t &socket_option_value);

  virtual int getSocketOption(int socket_option_key, bool &socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              Name **socket_option_value);

  virtual int getSocketOption(
      int socket_option_key,
      ConsumerContentObjectCallback **socket_option_value);

  virtual int getSocketOption(
      int socket_option_key,
      ConsumerContentObjectVerificationCallback **socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              ConsumerInterestCallback **socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              ConsumerManifestCallback **socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              std::shared_ptr<Portal> &socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              IcnObserver **socket_option_value);

  virtual int getSocketOption(
      int socket_option_key,
      std::shared_ptr<utils::Verifier> &socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              std::string &socket_option_value);

  virtual int getSocketOption(int socket_option_key,
                              ConsumerTimerCallback **socket_option_value);

 protected:
  // If the thread calling lambda_func is not the same of io_service, this
  // function reschedule the function on it
  template <typename Lambda, typename arg2>
  int rescheduleOnIOService(int socket_option_key, arg2 socket_option_value,
                            Lambda lambda_func) {
    // To enforce type check
    std::function<int(int, arg2)> func = lambda_func;
    int result = SOCKET_OPTION_SET;
    if (transport_protocol_->isRunning()) {
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
  std::atomic_bool verify_signature_;
  std::atomic_bool key_content_;

  ConsumerInterestCallback on_interest_retransmission_;
  ConsumerInterestCallback on_interest_output_;
  ConsumerInterestCallback on_interest_timeout_;
  ConsumerInterestCallback on_interest_satisfied_;

  ConsumerContentObjectCallback on_content_object_input_;
  ConsumerContentObjectVerificationCallback on_content_object_verification_;

  ConsumerContentObjectCallback on_content_object_;
  ConsumerManifestCallback on_manifest_;
  ConsumerTimerCallback stats_summary_;

  ReadCallback *read_callback_;

  // Virtual download for traffic generator
  bool virtual_download_;

  uint32_t timer_interval_milliseconds_;

  // Transport protocol
  std::unique_ptr<TransportProtocol> transport_protocol_;

  utils::SpinLock guard_raaqm_params_;
};

}  // namespace interface

}  // end namespace transport
