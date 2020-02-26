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

#include <implementation/socket_producer.h>

#include <openssl/ssl.h>
#include <condition_variable>
#include <mutex>

namespace transport {
namespace implementation {

class P2PSecureProducerSocket;

class TLSProducerSocket : virtual public ProducerSocket {
  friend class P2PSecureProducerSocket;

 public:
  explicit TLSProducerSocket(interface::ProducerSocket *producer_socket,
                             P2PSecureProducerSocket *parent,
                             const Name &handshake_name);

  ~TLSProducerSocket();

  uint32_t produce(Name content_name, const uint8_t *buffer, size_t buffer_size,
                   bool is_last = true, uint32_t start_offset = 0) override {
    return produce(content_name, utils::MemBuf::copyBuffer(buffer, buffer_size),
                   is_last, start_offset);
  }

  uint32_t produce(Name content_name, std::unique_ptr<utils::MemBuf> &&buffer,
                   bool is_last = true, uint32_t start_offset = 0) override;

  void produce(ContentObject &content_object) override;

  void asyncProduce(const Name &suffix, const uint8_t *buf, size_t buffer_size,
                    bool is_last = true,
                    uint32_t *start_offset = nullptr) override;

  void asyncProduce(Name content_name, std::unique_ptr<utils::MemBuf> &&buffer,
                    bool is_last, uint32_t offset,
                    uint32_t **last_segment = nullptr) override;

  void asyncProduce(ContentObject &content_object) override;

  virtual void accept();

  virtual int async_accept();

  virtual int setSocketOption(
      int socket_option_key,
      ProducerInterestCallback socket_option_value) override;

  virtual int setSocketOption(
      int socket_option_key,
      ProducerContentCallback socket_option_value) override;

  virtual int getSocketOption(
      int socket_option_key,
      ProducerContentCallback **socket_option_value) override;

  int getSocketOption(int socket_option_key,
                      ProducerContentCallback &socket_option_value);

  int getSocketOption(int socket_option_key,
                      ProducerInterestCallback &socket_option_value);

  using ProducerSocket::getSocketOption;
  using ProducerSocket::onInterest;
  using ProducerSocket::setSocketOption;

 protected:
  /* Callback invoked once an interest has been received and its payload
   * decrypted */
  ProducerInterestCallback on_interest_input_decrypted_;
  ProducerInterestCallback on_interest_process_decrypted_;
  ProducerContentCallback on_content_produced_application_;

  std::mutex mtx_;

  /* Condition variable for the wait */
  std::condition_variable cv_;

  /* Bool variable, true if there is something to read (an interest arrived) */
  bool something_to_read_;

  /* First interest that open a secure connection */
  transport::core::Name name_;

  /* SSL handle */
  SSL *ssl_;
  SSL_CTX *ctx_;

  Packet::MemBufPtr packet_;

  std::unique_ptr<utils::MemBuf> head_;
  std::uint32_t last_segment_;
  std::shared_ptr<utils::MemBuf> payload_;
  std::uint32_t key_id_;

  std::thread *handshake;
  P2PSecureProducerSocket *parent_;

  bool first_;
  Name handshake_name_;
  int tls_chunks_;
  int to_call_oncontentproduced_;

  bool still_writing_;

  utils::EventThread encryption_thread_;

  void onInterest(ProducerSocket &p, Interest &interest);
  void cacheMiss(interface::ProducerSocket &p, Interest &interest);

  /* Return the number of read bytes in readbytes */
  static int read(BIO *b, char *buf, size_t size, size_t *readbytes);

  /* Return the number of read bytes in the return param */
  static int readOld(BIO *h, char *buf, int size);

  /* Return the number of written bytes in written */
  static int write(BIO *b, const char *buf, size_t size, size_t *written);

  /* Return the number of written bytes in the return param */
  static int writeOld(BIO *h, const char *buf, int num);

  static long ctrl(BIO *b, int cmd, long num, void *ptr);

  static int addHicnKeyIdCb(SSL *s, unsigned int ext_type, unsigned int context,
                            const unsigned char **out, size_t *outlen, X509 *x,
                            size_t chainidx, int *al, void *add_arg);

  static void freeHicnKeyIdCb(SSL *s, unsigned int ext_type,
                              unsigned int context, const unsigned char *out,
                              void *add_arg);

  static int parseHicnKeyIdCb(SSL *s, unsigned int ext_type,
                              unsigned int context, const unsigned char *in,
                              size_t inlen, X509 *x, size_t chainidx, int *al,
                              void *add_arg);

  void onContentProduced(interface::ProducerSocket &p,
                         const std::error_code &err, uint64_t bytes_written);
};

}  // namespace implementation

}  // end namespace transport
