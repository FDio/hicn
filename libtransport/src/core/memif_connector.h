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

#include <hicn/transport/config.h>
#include <hicn/transport/core/connector.h>
#include <hicn/transport/portability/portability.h>
#include <hicn/transport/utils/ring_buffer.h>
//#include <hicn/transport/core/hicn_vapi.h>
#include <hicn/transport/core/asio_wrapper.h>
#include <utils/epoll_event_reactor.h>
#include <utils/fd_deadline_timer.h>

#include <deque>
#include <future>
#include <mutex>
#include <thread>

extern "C" {
#include <libmemif.h>
};

#define _Static_assert static_assert

namespace transport {

namespace core {

#define APP_NAME "libtransport"
#define IF_NAME "vpp_connection"

class MemifConnector : public Connector {
  static inline std::size_t kbuf_size = 2048;
  static inline std::size_t klog2_ring_size = 13;

  using PacketRing = utils::CircularFifo<utils::MemBuf::Ptr, queue_size>;
  struct Details {
    // index
    uint16_t index;
    // memif conenction handle
    memif_conn_handle_t conn;
    // transmit queue id
    uint16_t tx_qid;
    // tx buffers
    memif_buffer_t *tx_bufs;
    // allocated tx buffers counter
    // number of tx buffers pointing to shared memory
    uint16_t tx_buf_num;
    // rx buffers
    memif_buffer_t *rx_bufs;
    // allocated rx buffers counter
    // number of rx buffers pointing to shared memory
    uint16_t rx_buf_num;
    // interface ip address
    uint8_t ip_addr[4];
  };

 public:
  MemifConnector(PacketReceivedCallback &&receive_callback,
                 PacketSentCallback &&packet_sent,
                 OnCloseCallback &&close_callback,
                 OnReconnectCallback &&on_reconnect,
                 asio::io_service &io_service,
                 std::string app_name = "Libtransport");

  ~MemifConnector() override;

  void send(Packet &packet) override;

  void send(const utils::MemBuf::Ptr &buffer) override;

  void close() override;

  void connect(uint32_t memif_id, long memif_mode,
               const std::string &socket_filename,
               std::size_t buffer_size = kbuf_size,
               std::size_t log2_ring_size = klog2_ring_size);

  TRANSPORT_ALWAYS_INLINE uint32_t getMemifId() { return memif_id_; };

 private:
  void init();

  int doSend();

  int createMemif(uint32_t index, uint8_t is_master);

  uint32_t getMemifConfiguration();

  int deleteMemif();

  static int controlFdUpdate(memif_fd_event_t fde, void *private_ctx);

  static int onConnect(memif_conn_handle_t conn, void *private_ctx);

  static int onDisconnect(memif_conn_handle_t conn, void *private_ctx);

  static int onInterrupt(memif_conn_handle_t conn, void *private_ctx,
                         uint16_t qid);

  void threadMain();

  uint16_t txBurst(uint16_t qid, std::error_code &ec);

  uint16_t bufferAlloc(long n, uint16_t qid, std::error_code &ec);

  void scheduleSend(std::uint64_t delay);

  void sendCallback(const std::error_code &ec);

  auto shared_from_this() { return utils::shared_from(this); }

 private:
  int epfd;
  utils::EpollEventReactor event_reactor_;
  std::thread memif_worker_;
  std::atomic_bool timer_set_;
  utils::FdDeadlineTimer send_timer_;
  utils::FdDeadlineTimer disconnect_timer_;
  asio::io_service &io_service_;
  asio::executor_work_guard<asio::io_context::executor_type> work_;
  Details memif_connection_;
  uint16_t tx_buf_counter_;

  PacketRing input_buffer_;
  bool is_reconnection_;
  bool data_available_;
  uint32_t memif_id_;
  uint8_t memif_mode_;
  std::string app_name_;
  uint16_t transmission_index_;
  utils::SpinLock write_msgs_lock_;
  std::string socket_filename_;
  std::size_t buffer_size_;
  std::size_t log2_ring_size_;
  std::size_t max_memif_bufs_;
};

}  // end namespace core

}  // end namespace transport
