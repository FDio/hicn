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

#include <implementation/rtc_socket_producer.h>
#include <implementation/tls_socket_producer.h>

namespace transport {
namespace implementation {

class P2PSecureProducerSocket;

class TLSRTCProducerSocket : public RTCProducerSocket,
                             public TLSProducerSocket {
  friend class P2PSecureProducerSocket;

 public:
  explicit TLSRTCProducerSocket(interface::ProducerSocket *producer_socket,
                                P2PSecureProducerSocket *parent,
                                const Name &handshake_name);

  ~TLSRTCProducerSocket() = default;

  void produce(std::unique_ptr<utils::MemBuf> &&buffer) override;

  void accept() override;

  int async_accept() override;

  using TLSProducerSocket::onInterest;
  using TLSProducerSocket::produce;

 protected:
  static int read(BIO *b, char *buf, size_t size, size_t *readbytes);

  static int readOld(BIO *h, char *buf, int size);

  static int write(BIO *b, const char *buf, size_t size, size_t *written);

  static int writeOld(BIO *h, const char *buf, int num);
};

}  // namespace implementation

}  // end namespace transport
