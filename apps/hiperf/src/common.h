/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <forwarder_interface.h>
#include <hicn/transport/auth/signer.h>
#include <hicn/transport/config.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/interfaces/global_conf_interface.h>
#include <hicn/transport/interfaces/p2psecure_socket_consumer.h>
#include <hicn/transport/interfaces/p2psecure_socket_producer.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_producer.h>
#include <hicn/transport/utils/chrono_typedefs.h>
#include <hicn/transport/utils/literals.h>

#ifndef _WIN32
#include <hicn/transport/utils/daemonizator.h>
#endif

#include <asio.hpp>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_set>

#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS 0
#endif
#define ERROR_SETUP -5
#define MIN_PROBE_SEQ 0xefffffff
#define RTC_HEADER_SIZE 12
#define FEC_HEADER_MAX_SIZE 36
#define HIPERF_MTU 1500

using namespace transport::interface;
using namespace transport::auth;
using namespace transport::core;

static inline uint64_t _ntohll(const uint64_t *input) {
  uint64_t return_val;
  uint8_t *tmp = (uint8_t *)&return_val;

  tmp[0] = *input >> 56;
  tmp[1] = *input >> 48;
  tmp[2] = *input >> 40;
  tmp[3] = *input >> 32;
  tmp[4] = *input >> 24;
  tmp[5] = *input >> 16;
  tmp[6] = *input >> 8;
  tmp[7] = *input >> 0;

  return return_val;
}

static inline uint64_t _htonll(const uint64_t *input) {
  return (_ntohll(input));
}

namespace hiperf {

/**
 * Class to retrieve the maximum payload size given the MTU and packet headers.
 */
class PayloadSize {
 public:
  PayloadSize(Packet::Format format, std::size_t mtu = HIPERF_MTU)
      : mtu_(mtu), format_(format) {}

  std::size_t getPayloadSizeMax(std::size_t transport_size = 0,
                                std::size_t fec_size = 0,
                                std::size_t signature_size = 0) {
    return mtu_ - Packet::getHeaderSizeFromFormat(format_, signature_size) -
           transport_size - fec_size;
  }

  static Packet::Format getFormatFromName(Name name, bool ah = false) {
    switch (name.getAddressFamily()) {
      case AF_INET:
        return ah ? HF_INET_TCP_AH : HF_INET_TCP;
      case AF_INET6:
        return ah ? HF_INET6_TCP_AH : HF_INET6_TCP;
      default:
        return HF_UNSPEC;
    }
  }

 private:
  std::size_t mtu_;
  Packet::Format format_;
};

/**
 * Class for handling the production rate for the RTC producer.
 */
class Rate {
 public:
  Rate() : rate_kbps_(0) {}
  ~Rate() {}

  Rate &operator=(const Rate &other) {
    if (this != &other) {
      rate_kbps_ = other.rate_kbps_;
    }

    return *this;
  }

  Rate(const std::string &rate) {
    std::size_t found = rate.find("kbps");
    if (found != std::string::npos) {
      rate_kbps_ = std::stof(rate.substr(0, found));
    } else {
      throw std::runtime_error("Format " + rate + " not correct");
    }
  }

  Rate(const Rate &other) : rate_kbps_(other.rate_kbps_) {}

  Rate &operator=(const std::string &rate) {
    std::size_t found = rate.find("kbps");
    if (found != std::string::npos) {
      rate_kbps_ = std::stof(rate.substr(0, found));
    } else {
      throw std::runtime_error("Format " + rate + " not correct");
    }

    return *this;
  }

  std::chrono::microseconds getMicrosecondsForPacket(std::size_t packet_size) {
    return std::chrono::microseconds(
        (uint32_t)std::round(packet_size * 1000.0 * 8.0 / (double)rate_kbps_));
  }

 private:
  float rate_kbps_;
};

struct packet_t {
  uint64_t timestamp;
  uint32_t size;
};

/**
 * Container for command line configuration for hiperf client.
 */
struct ClientConfiguration {
  ClientConfiguration()
      : name("b001::abcd", 0),
        beta(-1.f),
        drop_factor(-1.f),
        window(-1),
        producer_certificate(""),
        passphrase(""),
        receive_buffer(nullptr),
        receive_buffer_size_(128 * 1024),
        download_size(0),
        report_interval_milliseconds_(1000),
        transport_protocol_(CBR),
        rtc_(false),
        test_mode_(false),
        relay_(false),
        secure_(false),
        producer_prefix_(),
        interest_lifetime_(500),
        unverified_delay_(2000),
        relay_name_("c001::abcd/64"),
        output_stream_mode_(false),
        port_(0),
        recovery_strategy_(4),
        aggregated_data_(false),
        fec_type_(""),
        packet_format_(default_values::packet_format),
        print_headers_(true),
        nb_iterations_(std::numeric_limits<decltype(nb_iterations_)>::max()) {}

  Name name;
  double beta;
  double drop_factor;
  double window;
  std::string producer_certificate;
  std::string passphrase;
  std::shared_ptr<utils::MemBuf> receive_buffer;
  std::size_t receive_buffer_size_;
  std::size_t download_size;
  std::uint32_t report_interval_milliseconds_;
  TransportProtocolAlgorithms transport_protocol_;
  bool rtc_;
  bool test_mode_;
  bool relay_;
  bool secure_;
  Prefix producer_prefix_;
  uint32_t interest_lifetime_;
  uint32_t unverified_delay_;
  Prefix relay_name_;
  bool output_stream_mode_;
  uint16_t port_;
  uint32_t recovery_strategy_;
  bool aggregated_data_;
  std::string fec_type_;
  Packet::Format packet_format_;
  bool print_headers_;
  std::uint32_t nb_iterations_;
  forwarder_type_t forwarder_type_;
};

/**
 * Container for command line configuration for hiperf server.
 */
struct ServerConfiguration {
  ServerConfiguration()
      : name("b001::abcd/64"),
        virtual_producer(true),
        manifest(0),
        live_production(false),
        content_lifetime(600000000_U32),
        download_size(20 * 1024 * 1024),
        hash_algorithm_(CryptoHashType::SHA256),
        keystore_name(""),
        passphrase(""),
        keystore_password("cisco"),
        multiphase_produce_(false),
        rtc_(false),
        interactive_(false),
        trace_based_(false),
        trace_index_(0),
        trace_file_(nullptr),
        production_rate_(std::string("2048kbps")),
        payload_size_(1384),
        secure_(false),
        input_stream_mode_(false),
        port_(0),
        aggregated_data_(false),
        fec_type_(""),
        packet_format_(default_values::packet_format) {}

  Prefix name;
  bool virtual_producer;
  std::uint32_t manifest;
  bool live_production;
  std::uint32_t content_lifetime;
  std::uint32_t download_size;
  CryptoHashType hash_algorithm_;
  std::string keystore_name;
  std::string passphrase;
  std::string keystore_password;
  bool multiphase_produce_;
  bool rtc_;
  bool interactive_;
  bool trace_based_;
  std::uint32_t trace_index_;
  char *trace_file_;
  Rate production_rate_;
  std::size_t payload_size_;
  bool secure_;
  bool input_stream_mode_;
  uint16_t port_;
  std::vector<struct packet_t> trace_;
  bool aggregated_data_;
  std::string fec_type_;
  Packet::Format packet_format_;
};

}  // namespace hiperf
