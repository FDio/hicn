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

#include <gtest/gtest.h>
#include <hicn/transport/core/asio_wrapper.h>
#include <hicn/transport/interfaces/global_conf_interface.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_options_keys.h>
#include <hicn/transport/interfaces/socket_producer.h>

namespace transport {
namespace interface {

namespace {

class IoModuleInit {
 public:
  IoModuleInit() {
    global_config::IoModuleConfiguration config;
    config.name = "forwarder_module";
    config.set();
  }
};

static IoModuleInit init;

class ConsumerProducerTest : public ::testing::Test,
                             public ConsumerSocket::ReadCallback {
  static const constexpr char prefix[] = "b001::1/128";
  static const constexpr char name[] = "b001::1";
  static const constexpr double prod_rate = 1.0e6;
  static const constexpr size_t payload_size = 1200;
  static constexpr std::size_t receive_buffer_size = 1500;
  static const constexpr double prod_interval_microseconds =
      double(payload_size) * 8 * 1e6 / prod_rate;

 public:
  ConsumerProducerTest()
      : io_service_(),
        rtc_timer_(io_service_),
        stop_timer_(io_service_),
        consumer_(TransportProtocolAlgorithms::RTC),
        producer_(ProductionProtocolAlgorithms::RTC_PROD),
        producer_prefix_(prefix),
        consumer_name_(name),
        packets_sent_(0),
        packets_received_(0) {}

  virtual ~ConsumerProducerTest() {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() override {
    // Code here will be called immediately after the constructor (right
    // before each test).

    auto ret = consumer_.setSocketOption(
        ConsumerCallbacksOptions::READ_CALLBACK, this);
    ASSERT_EQ(ret, SOCKET_OPTION_SET);

    consumer_.connect();
    producer_.registerPrefix(producer_prefix_);
    producer_.connect();
    producer_.start();
  }

  virtual void TearDown() override {
    // Code here will be called immediately after each test (right
    // before the destructor).
  }

  void setTimer() {
    using namespace std::chrono;
    rtc_timer_.expires_from_now(
        microseconds(unsigned(prod_interval_microseconds)));
    rtc_timer_.async_wait(std::bind(&ConsumerProducerTest::produceRTCPacket,
                                    this, std::placeholders::_1));
  }

  void setStopTimer() {
    using namespace std::chrono;
    stop_timer_.expires_from_now(seconds(unsigned(10)));
    stop_timer_.async_wait(
        std::bind(&ConsumerProducerTest::stop, this, std::placeholders::_1));
  }

  void produceRTCPacket(const std::error_code &ec) {
    if (ec) {
      io_service_.stop();
    }

    producer_.produceDatagram(consumer_name_, payload_, payload_size);
    packets_sent_++;
    setTimer();
  }

  void stop(const std::error_code &ec) {
    rtc_timer_.cancel();
    producer_.stop();
    consumer_.stop();
  }

  // Consumer callback
  bool isBufferMovable() noexcept override { return false; }

  void getReadBuffer(uint8_t **application_buffer,
                     size_t *max_length) override {
    *application_buffer = receive_buffer_;
    *max_length = receive_buffer_size;
  }

  void readDataAvailable(std::size_t length) noexcept override {
    packets_received_++;
  }

  size_t maxBufferSize() const override { return receive_buffer_size; }

  void readError(const std::error_code &ec) noexcept override {
    io_service_.stop();
    FAIL() << "Error while reading from RTC socket";
  }

  void readSuccess(std::size_t total_size) noexcept override {}

  asio::io_service io_service_;
  asio::steady_timer rtc_timer_;
  asio::steady_timer stop_timer_;
  ConsumerSocket consumer_;
  ProducerSocket producer_;
  core::Prefix producer_prefix_;
  core::Name consumer_name_;
  uint8_t payload_[payload_size];
  uint8_t receive_buffer_[payload_size];

  uint64_t packets_sent_;
  uint64_t packets_received_;
};

const char ConsumerProducerTest::prefix[];
const char ConsumerProducerTest::name[];

}  // namespace

TEST_F(ConsumerProducerTest, EndToEnd) {
  produceRTCPacket(std::error_code());
  consumer_.consume(consumer_name_);
  setStopTimer();

  io_service_.run();

  std::cout << "Packet received: " << packets_received_ << std::endl;
  std::cout << "Packet sent: " << packets_sent_ << std::endl;
}

}  // namespace interface

}  // namespace transport
