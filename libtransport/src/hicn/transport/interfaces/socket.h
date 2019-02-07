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

#include <hicn/transport/config.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/facade.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/core/manifest_format_fixed.h>
#include <hicn/transport/core/manifest_inline.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/interfaces/socket_options_default_values.h>
#include <hicn/transport/interfaces/socket_options_keys.h>
#include <hicn/transport/utils/crypto_suite.h>
#include <hicn/transport/utils/identity.h>
#include <hicn/transport/utils/verifier.h>

#define SOCKET_OPTION_GET 0
#define SOCKET_OPTION_NOT_GET 1
#define SOCKET_OPTION_SET 2
#define SOCKET_OPTION_NOT_SET 3
#define SOCKET_OPTION_DEFAULT 12345

#define VOID_HANDLER 0

namespace transport {

namespace protocol {
class IcnObserver;
}

namespace interface {

template <typename PortalType>
class Socket;
class ConsumerSocket;
class ProducerSocket;

// using Interest = core::Interest;
// using ContentObject = core::ContentObject;
// using Name = core::Name;
// using HashAlgorithm = core::HashAlgorithm;
// using CryptoSuite = utils::CryptoSuite;
// using Identity = utils::Identity;
// using Verifier = utils::Verifier;

using HicnForwarderPortal = core::HicnForwarderPortal;

#ifdef __linux__
#ifndef __ANDROID__
using RawSocketPortal = core::RawSocketPortal;
#endif
#endif

#ifdef __vpp__
using VPPForwarderPortal = core::VPPForwarderPortal;
using BaseSocket = Socket<VPPForwarderPortal>;
using BasePortal = VPPForwarderPortal;
#else
using BaseSocket = Socket<HicnForwarderPortal>;
using BasePortal = HicnForwarderPortal;
#endif

using PayloadType = core::PayloadType;
using Prefix = core::Prefix;
using Array = utils::Array<uint8_t>;

using ConsumerInterestCallback =
    std::function<void(ConsumerSocket &, const core::Interest &)>;

using ConsumerContentCallback =
    std::function<void(ConsumerSocket &, std::size_t, const std::error_code &)>;

using ConsumerTimerCallback =
    std::function<void(ConsumerSocket &, std::size_t,
                       std::chrono::milliseconds &, float, uint32_t, uint32_t)>;

using ProducerContentCallback = std::function<void(
    ProducerSocket &, const std::error_code &, uint64_t bytes_written)>;

using ConsumerContentObjectCallback =
    std::function<void(ConsumerSocket &, const core::ContentObject &)>;

using ConsumerContentObjectVerificationCallback =
    std::function<bool(ConsumerSocket &, const core::ContentObject &)>;

using ConsumerManifestCallback =
    std::function<void(ConsumerSocket &, const core::ContentObjectManifest &)>;

using ProducerContentObjectCallback =
    std::function<void(ProducerSocket &, core::ContentObject &)>;

using ProducerInterestCallback =
    std::function<void(ProducerSocket &, core::Interest &)>;

using namespace protocol;

template <typename PortalType>
class Socket {
  static_assert(std::is_same<PortalType, HicnForwarderPortal>::value
#ifdef __linux__
#ifndef __ANDROID__
                    || std::is_same<PortalType, RawSocketPortal>::value
#ifdef __vpp__
                    || std::is_same<PortalType, VPPForwarderPortal>::value
#endif
#endif
                ,
#else
                ,

#endif
                "This class is not allowed as Portal");

 public:
  using Portal = PortalType;

  virtual asio::io_service &getIoService() = 0;

  virtual void connect() = 0;

  virtual int setSocketOption(int socket_option_key,
                              uint32_t socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              double socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              bool socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              core::Name socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              std::list<Prefix> socket_option_value) = 0;

  virtual int setSocketOption(
      int socket_option_key,
      ProducerContentObjectCallback socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              ProducerInterestCallback socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              ProducerContentCallback socket_option_value) = 0;

  virtual int setSocketOption(
      int socket_option_key,
      ConsumerContentObjectVerificationCallback socket_option_value) = 0;

  virtual int setSocketOption(
      int socket_option_key,
      ConsumerContentObjectCallback socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              ConsumerInterestCallback socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              ConsumerContentCallback socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              ConsumerManifestCallback socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              IcnObserver *socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              core::HashAlgorithm socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              utils::CryptoSuite socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              const utils::Identity &socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              ConsumerTimerCallback socket_option_value) = 0;

  virtual int setSocketOption(int socket_option_key,
                              const std::string &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              uint32_t &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              double &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              bool &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              core::Name &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              std::list<Prefix> &socket_option_value) = 0;

  virtual int getSocketOption(
      int socket_option_key,
      ProducerContentObjectCallback &socket_option_value) = 0;

  virtual int getSocketOption(
      int socket_option_key, ProducerInterestCallback &socket_option_value) = 0;

  virtual int getSocketOption(
      int socket_option_key,
      ConsumerContentObjectVerificationCallback &socket_option_value) = 0;

  virtual int getSocketOption(
      int socket_option_key,
      ConsumerContentObjectCallback &socket_option_value) = 0;

  virtual int getSocketOption(
      int socket_option_key, ConsumerInterestCallback &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              ConsumerContentCallback &socket_option_value) = 0;

  virtual int getSocketOption(
      int socket_option_key, ConsumerManifestCallback &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              ProducerContentCallback &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              std::shared_ptr<Portal> &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              IcnObserver **socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              core::HashAlgorithm &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              utils::CryptoSuite &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              utils::Identity &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              std::string &socket_option_value) = 0;

  virtual int getSocketOption(int socket_option_key,
                              ConsumerTimerCallback &socket_option_value) = 0;

 protected:
  virtual ~Socket(){};

 protected:
  std::string output_interface_;
};

}  // namespace interface

}  // namespace transport
