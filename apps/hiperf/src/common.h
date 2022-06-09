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

#include <hicn/transport/auth/signer.h>
#include <hicn/transport/config.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/interfaces/global_conf_interface.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_producer.h>
#include <hicn/transport/utils/chrono_typedefs.h>
#include <hicn/transport/utils/color.h>
#include <hicn/transport/utils/literals.h>

#ifndef _WIN32
#include <hicn/transport/utils/daemonizator.h>
#endif

#include <asio.hpp>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
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

namespace hiperf {

/**
 * Logger
 */
static std::ostream &Logger() { return std::cout; }

template <typename D, typename ConfType, typename ParentType>
class Base : protected std::stringbuf, protected std::ostream {
 protected:
  static inline const char separator[] = "|   ";

  Base(ParentType &parent, asio::io_service &io_service, int identifier)
      : std::stringbuf(),
        std::ostream(this),
        parent_(parent),
        configuration_(parent_.getConfig()),
        io_service_(io_service),
        identifier_(identifier),
        name_id_(D::getContextType() + std::to_string(identifier_)),
        flow_name_(configuration_.name_.makeNameWithIndex(identifier_)) {
    std::stringstream begin;
    std::stringstream end;
    if (configuration_.colored_) {
      begin << color_mod_ << bold_mod_;
      end << end_mod_;
    } else {
      begin << "";
      end << "";
    }

    begin << "|" << name_id_ << separator;
    begin_ = begin.str();
    end_ = end.str();
  }

  Base(Base &&other)
      : parent_(other.parent_),
        configuration_(other.configuration_),
        io_service_(other.io_service_),
        identifier_(other.identifier_),
        name_id_(std::move(other.name_id_)),
        flow_name_(other.flow_name_) {}

  /***************************************************************
   * std::stringbuf sync override
   ***************************************************************/

  int sync() override {
    auto string = str();
    asio::post(io_service_,
               [this, string]() { Logger() << begin_ << string << end_; });
    str("");

    return 0;
  }

  std::ostream &getOutputStream() { return *this; }

  // Members initialized by the constructor
  ParentType &parent_;
  ConfType &configuration_;
  asio::io_service &io_service_;
  int identifier_;
  std::string name_id_;
  transport::core::Name flow_name_;
  std::string begin_;
  std::string end_;

  // Members initialized by the in-class initializer
  utils::ColorModifier color_mod_;
  utils::ColorModifier bold_mod_{utils::ColorModifier::Code::BOLD};
  utils::ColorModifier end_mod_{utils::ColorModifier::Code::RESET};
};

static inline int ensureFlows(const Prefix &prefix, std::size_t flows) {
  int ret = ERROR_SUCCESS;

  // Make sure the provided prefix length not allows to accomodate the
  // provided number of flows.
  uint16_t max_ip_addr_len_bits;
  uint16_t log2_n_flow;
  u64 max_n_flow;
  if (prefix.getAddressFamily() == AF_INET) {
    max_ip_addr_len_bits = IPV4_ADDR_LEN_BITS;
  } else if (prefix.getAddressFamily() == AF_INET6) {
    max_ip_addr_len_bits = IPV6_ADDR_LEN_BITS;
  } else {
    Logger() << "Error: unknown address family." << std::endl;
    ret = ERROR_SETUP;
    goto end;
  }

  log2_n_flow = max_ip_addr_len_bits - prefix.getPrefixLength();
  max_n_flow = log2_n_flow < 64 ? (1 << log2_n_flow) : ~0ULL;

  if (flows > max_n_flow) {
    Logger() << "Error: the provided prefix length does not allow to "
                "accomodate the provided number of flows ("
             << flows << " > " << max_n_flow << ")." << std::endl;
    ret = ERROR_SETUP;
  }

end:
  return ret;
}

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

  static Packet::Format getFormatFromPrefix(const Prefix &prefix,
                                            bool ah = false) {
    switch (prefix.getAddressFamily()) {
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

struct Configuration {
  Prefix name_{"b001::abcd/64"};
  std::string passphrase_;
  std::string aggr_interest_passphrase_;
  bool rtc_{false};
  uint16_t port_{0};
  bool aggregated_data_{false};
  Packet::Format packet_format_{default_values::packet_format};
  uint32_t parallel_flows_{1};
  bool colored_{true};
};

/**
 * Container for command line configuration for hiperf client.
 */
struct ClientConfiguration : public Configuration {
  double beta_{-1.f};
  double drop_factor_{-1.f};
  double window_{-1.f};
  std::string producer_certificate_;
  std::string passphrase_;
  std::size_t receive_buffer_size_{128 * 1024};
  std::uint32_t report_interval_milliseconds_{1000};
  TransportProtocolAlgorithms transport_protocol_{CBR};
  bool test_mode_{false};
  bool relay_{false};
  Prefix producer_prefix_;
  uint32_t interest_lifetime_{500};
  uint32_t manifest_factor_relevant_{100};
  uint32_t manifest_factor_alert_{20};
  Prefix relay_name_{"c001::abcd/64"};
  bool output_stream_mode_{false};
  uint32_t recovery_strategy_{4};
  bool print_headers_{true};
  std::uint32_t nb_iterations_{
      std::numeric_limits<decltype(nb_iterations_)>::max()};
  bool content_sharing_mode_{false};
  bool aggregated_interests_{false};
};

/**
 * Container for command line configuration for hiperf server.
 */
struct ServerConfiguration : public Configuration {
  bool virtual_producer_{true};
  std::uint32_t manifest_max_capacity_{0};
  bool live_production_{false};
  std::uint32_t content_lifetime_{
      transport::interface::default_values::content_object_expiry_time};
  std::uint32_t download_size_{20 * 1024 * 1024};
  CryptoHashType hash_algorithm_{CryptoHashType::SHA256};
  std::string keystore_name_;
  std::string keystore_password_{"cisco"};
  bool multiphase_produce_{false};
  bool interactive_{false};
  bool trace_based_{false};
  std::uint32_t trace_index_{0};
  char *trace_file_{nullptr};
  Rate production_rate_{"2048kbps"};
  std::size_t payload_size_{1384};
  bool input_stream_mode_{false};
  std::vector<struct packet_t> trace_;
  std::string fec_type_;
};

}  // namespace hiperf
