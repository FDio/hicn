/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace transport {
namespace core {

struct AtomicConnectorStats {
  AtomicConnectorStats()
      : tx_packets_(0), tx_bytes_(0), rx_packets_(0), rx_bytes_(0), drops_(0) {}
  std::atomic<uint64_t> tx_packets_;
  std::atomic<uint64_t> tx_bytes_;
  std::atomic<uint64_t> rx_packets_;
  std::atomic<uint64_t> rx_bytes_;
  std::atomic<uint64_t> drops_;
};

struct ConnectorStats {
  ConnectorStats()
      : tx_packets_(0), tx_bytes_(0), rx_packets_(0), rx_bytes_(0), drops_(0) {}
  std::uint64_t tx_packets_;
  std::uint64_t tx_bytes_;
  std::uint64_t rx_packets_;
  std::uint64_t rx_bytes_;
  std::uint64_t drops_;
};

using TableEntry = std::tuple<std::string, std::uint64_t, std::uint64_t,
                              std::uint64_t, std::uint64_t, std::uint64_t>;
using StatisticTable = std::vector<TableEntry>;

}  // namespace core
}  // namespace transport