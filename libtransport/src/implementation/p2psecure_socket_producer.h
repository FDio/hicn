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

#include <hicn/transport/security/identity.h>
#include <hicn/transport/security/signer.h>

#include <implementation/socket_producer.h>
#include <implementation/tls_rtc_socket_producer.h>
#include <implementation/tls_socket_producer.h>
#include <utils/content_store.h>

#include <openssl/ssl.h>
#include <condition_variable>
#include <forward_list>
#include <mutex>

namespace transport {
namespace implementation {

class P2PSecureProducerSocket : public ProducerSocket {
  friend class TLSProducerSocket;
  friend class TLSRTCProducerSocket;

 public:
  explicit P2PSecureProducerSocket(interface::ProducerSocket *producer_socket);
  explicit P2PSecureProducerSocket(
      interface::ProducerSocket *producer_socket, bool rtc,
      const std::shared_ptr<utils::Identity> &identity);
  ~P2PSecureProducerSocket();

  void produce(const uint8_t *buffer, size_t buffer_size) override;

  uint32_t produce(Name content_name, const uint8_t *buffer, size_t buffer_size,
                   bool is_last = true, uint32_t start_offset = 0) override;

  uint32_t produce(Name content_name, std::unique_ptr<utils::MemBuf> &&buffer,
                   bool is_last = true, uint32_t start_offset = 0) override;

  void asyncProduce(Name content_name, std::unique_ptr<utils::MemBuf> &&buffer,
                    bool is_last, uint32_t offset,
                    uint32_t **last_segment = nullptr) override;

  void asyncProduce(const Name &suffix, const uint8_t *buf, size_t buffer_size,
                    bool is_last = true,
                    uint32_t *start_offset = nullptr) override;

  int setSocketOption(int socket_option_key,
                      ProducerInterestCallback socket_option_value) override;

  int setSocketOption(
      int socket_option_key,
      const std::shared_ptr<utils::Signer> &socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      uint32_t socket_option_value) override;

  int setSocketOption(int socket_option_key, bool socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      Name *socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      std::list<Prefix> socket_option_value) override;

  int setSocketOption(
      int socket_option_key,
      ProducerContentObjectCallback socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      ProducerContentCallback socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      HashAlgorithm socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      utils::CryptoSuite socket_option_value) override;

  int setSocketOption(int socket_option_key,
                      const std::string &socket_option_value) override;

  using ProducerSocket::getSocketOption;
  using ProducerSocket::onInterest;

 protected:
  bool rtc_;
  /* Callback invoked once an interest has been received and its payload
   * decrypted */
  ProducerInterestCallback on_interest_input_decrypted_;
  ProducerInterestCallback on_interest_process_decrypted_;
  ProducerContentCallback on_content_produced_application_;

 private:
  std::mutex mtx_;

  /* Condition variable for the wait */
  std::condition_variable cv_;

  PARCBuffer *der_cert_;
  PARCBuffer *der_prk_;
  X509 *cert_509_;
  EVP_PKEY *pkey_rsa_;
  std::unordered_map<core::Name, std::unique_ptr<TLSProducerSocket>,
                     core::hash<core::Name>, core::compare2<core::Name>>
      map_secure_producers;
  std::unordered_map<core::Name, std::unique_ptr<TLSRTCProducerSocket>,
                     core::hash<core::Name>, core::compare2<core::Name>>
      map_secure_rtc_producers;
  std::list<std::unique_ptr<TLSProducerSocket>> list_secure_producers;
  std::list<std::unique_ptr<TLSRTCProducerSocket>> list_secure_rtc_producers;

  void onInterestCallback(interface::ProducerSocket &p, Interest &interest);
};

}  // namespace implementation

}  // namespace transport
