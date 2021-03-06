/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

#include <hicn/transport/interfaces/socket_consumer.h>
#include <implementation/tls_socket_consumer.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

namespace transport {
namespace implementation {

class P2PSecureConsumerSocket : public ConsumerSocket,
                                public interface::ConsumerSocket::ReadCallback {
  /* Return the number of read bytes in readbytes */
  friend int read(BIO *b, char *buf, size_t size, size_t *readbytes);

  /* Return the number of read bytes in the return param */
  friend int readOld(BIO *h, char *buf, int size);

  /* Return the number of written bytes in written */
  friend int write(BIO *b, const char *buf, size_t size, size_t *written);

  /* Return the number of written bytes in the return param */
  friend int writeOld(BIO *h, const char *buf, int num);

  friend long ctrl(BIO *b, int cmd, long num, void *ptr);

 public:
  explicit P2PSecureConsumerSocket(interface::ConsumerSocket *consumer,
                                   int handshake_protocol,
                                   int transport_protocol);

  ~P2PSecureConsumerSocket();

  int consume(const Name &name) override;

  int asyncConsume(const Name &name) override;

  void registerPrefix(const Prefix &producer_namespace);

  int setSocketOption(
      int socket_option_key,
      interface::ConsumerSocket::ReadCallback *socket_option_value) override;

  using ConsumerSocket::getSocketOption;
  using ConsumerSocket::setSocketOption;

 protected:
  /* Callback invoked once an interest has been received and its payload
   * decrypted */
  ConsumerInterestCallback on_interest_input_decrypted_;
  ConsumerInterestCallback on_interest_process_decrypted_;

 private:
  Name name_;
  std::shared_ptr<TLSConsumerSocket> tls_consumer_;
  /* SSL handle */
  SSL *ssl_;
  SSL_CTX *ctx_;
  BIO_METHOD *bio_meth_;
  /* Chain of MemBuf to be used as a temporary buffer to pass descypted data
   * from the underlying layer to the application */
  std::unique_ptr<utils::MemBuf> decrypted_content_;
  /* Chain of MemBuf holding the payload to be written into interest or data */
  std::unique_ptr<utils::MemBuf> payload_;
  /* Chain of MemBuf holding the data retrieved from the underlying layer */
  std::unique_ptr<utils::MemBuf> head_;
  bool something_to_read_;
  bool content_downloaded_;
  double old_max_win_;
  double old_current_win_;
  uint32_t random_suffix_;
  ip_prefix_t secure_prefix_;
  Prefix producer_namespace_;
  interface::ConsumerSocket::ReadCallback *read_callback_decrypted_;
  std::mutex mtx_;

  /* Condition variable for the wait */
  std::condition_variable cv_;

  int protocol_;

  void setInterestPayload(interface::ConsumerSocket &c,
                          const core::Interest &interest);

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

  virtual void getReadBuffer(uint8_t **application_buffer,
                             size_t *max_length) override;

  virtual void readDataAvailable(size_t length) noexcept override;

  virtual size_t maxBufferSize() const override;

  virtual void readBufferAvailable(
      std::unique_ptr<utils::MemBuf> &&buffer) noexcept override;

  virtual void readError(const std::error_code ec) noexcept override;

  virtual void readSuccess(std::size_t total_size) noexcept override;

  virtual bool isBufferMovable() noexcept override;

  int handshake();

  void initSessionSocket();
};

}  // namespace implementation

}  // end namespace transport
