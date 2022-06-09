/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <core/memif_connector.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/utils/chrono_typedefs.h>

namespace transport {
namespace core {

namespace {

using namespace std::placeholders;

/**
 * Master memif connector
 */
template <int Master>
class Memif {
  static inline std::size_t counter = 256;
  static inline std::size_t total_packets = counter * 4096;
  static inline std::size_t packet_size = 64;

 public:
  Memif(asio::io_service &io_service)
      : io_service_(io_service),
        memif_connector_(std::make_shared<MemifConnector>(
            std::bind(&Memif::onPacketReceived, this, _1, _2, _3),
            std::bind(&Memif::onPacketSent, this, _1, _2),
            std::bind(&Memif::onClose, this, _1),
            std::bind(&Memif::onReconnect, this, _1, _2), io_service_,
            Master ? "test_master" : "test_slave")),
        recv_counter_(0),
        sent_counter_(0) {
    memif_connector_->connect(0 /* Memif ID */, Master /* Is Master */,
                              "@hicntransport/test/memif");
  }

  void setStart() { t0_ = utils::SteadyTime::now(); }

  void startTest() {
    if constexpr (!Master) {
      auto &packet_manager = core::PacketManager<>::getInstance();

      // Send in busrt of 256 packet per time
      for (std::size_t i = 0; i < counter; i++) {
        auto packet = packet_manager.getMemBuf();
        packet->append(packet_size);
        memif_connector_->send(packet);
        sent_counter_++;
      }

      if (sent_counter_ < total_packets) {
        asio::post(io_service_, std::bind(&Memif::startTest, this));
      }
    } else {
      setStart();
    }
  }

  auto getRecvCounter() { return recv_counter_; }
  auto getSentCounter() { return sent_counter_; }

 private:
  void onPacketReceived(Connector *c,
                        const std::vector<utils::MemBuf::Ptr> &buffers,
                        const std::error_code &ec) {
    if constexpr (Master) {
      recv_counter_ += buffers.size();
      if (recv_counter_ == total_packets) {
        auto t1 = utils::SteadyTime::now();
        auto delta = utils::SteadyTime::getDurationUs(t0_, t1);
        double rate = double(recv_counter_) * 1.0e6 / double(delta.count());
        LOG(INFO) << "rate: " << rate << " packets/s";
        io_service_.stop();
      }
    } else {
      FAIL() << "Slave should not receive packets";
    }
  }
  void onPacketSent(Connector *c, const std::error_code &ec) {}
  void onClose(Connector *c) {}
  void onReconnect(Connector *c, const std::error_code &ec) {}

 private:
  asio::io_service &io_service_;
  std::shared_ptr<MemifConnector> memif_connector_;
  std::size_t recv_counter_;
  std::size_t sent_counter_;
  utils::SteadyTime::TimePoint t0_;
};

using MemifMaster = Memif<1>;
using MemifSlave = Memif<0>;

}  // namespace

class MemifTest : public ::testing::Test {
 protected:
  MemifTest() : io_service_(), master_(io_service_), slave_(io_service_) {
    // You can do set-up work for each test here.
  }

  void run() {
    asio::post(io_service_, std::bind(&MemifSlave::startTest, &slave_));
    master_.startTest();
    io_service_.run();

    EXPECT_THAT(master_.getRecvCounter(),
                ::testing::Eq(slave_.getSentCounter()));
  }

  virtual ~MemifTest() {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() {
    // Code here will be called immediately after the constructor (right
    // before each test).
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test (right
    // before the destructor).
  }

 protected:
  asio::io_service io_service_;
  MemifMaster master_;
  MemifSlave slave_;
};

TEST_F(MemifTest, Test) { run(); }
}  // namespace core
}  // namespace transport
