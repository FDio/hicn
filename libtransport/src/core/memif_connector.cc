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

#include <hicn/transport/errors/not_implemented_exception.h>

#include <core/memif_connector.h>

#ifdef __vpp__

#include <sys/epoll.h>
#include <cstdlib>

extern "C" {
#include <memif/libmemif.h>
};

#define CANCEL_TIMER 1

namespace transport {

namespace core {

struct memif_connection {
  uint16_t index;
  /* memif conenction handle */
  memif_conn_handle_t conn;
  /* transmit queue id */
  uint16_t tx_qid;
  /* tx buffers */
  memif_buffer_t *tx_bufs;
  /* allocated tx buffers counter */
  /* number of tx buffers pointing to shared memory */
  uint16_t tx_buf_num;
  /* rx buffers */
  memif_buffer_t *rx_bufs;
  /* allcoated rx buffers counter */
  /* number of rx buffers pointing to shared memory */
  uint16_t rx_buf_num;
  /* interface ip address */
  uint8_t ip_addr[4];
};

std::once_flag MemifConnector::flag_;
utils::EpollEventReactor MemifConnector::main_event_reactor_;

MemifConnector::MemifConnector(PacketReceivedCallback &&receive_callback,
                               OnReconnect &&on_reconnect_callback,
                               asio::io_service &io_service,
                               std::string app_name)
    : Connector(std::move(receive_callback), std::move(on_reconnect_callback)),
      memif_worker_(nullptr),
      timer_set_(false),
      send_timer_(std::make_unique<utils::FdDeadlineTimer>(event_reactor_)),
      disconnect_timer_(
          std::make_unique<utils::FdDeadlineTimer>(event_reactor_)),
      io_service_(io_service),
      packet_counter_(0),
      memif_connection_(std::make_unique<memif_connection_t>()),
      tx_buf_counter_(0),
      is_reconnection_(false),
      data_available_(false),
      app_name_(app_name),
      socket_filename_("") {
  std::call_once(MemifConnector::flag_, &MemifConnector::init, this);
}

MemifConnector::~MemifConnector() { close(); }

void MemifConnector::init() {
  /* initialize memory interface */
  int err = memif_init(controlFdUpdate, const_cast<char *>(app_name_.c_str()),
                       nullptr, nullptr, nullptr);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    TRANSPORT_LOGE("memif_init: %s", memif_strerror(err));
  }
}

void MemifConnector::connect(uint32_t memif_id, long memif_mode) {
  state_ = ConnectorState::CONNECTING;

  memif_id_ = memif_id;
  socket_filename_ = "/run/vpp/memif.sock";

  createMemif(memif_id, memif_mode, nullptr);

  work_ = std::make_unique<asio::io_service::work>(io_service_);

  while (state_ != ConnectorState::CONNECTED) {
    MemifConnector::main_event_reactor_.runOneEvent();
  }

  int err;

  /* get interrupt queue id */
  int fd = -1;
  err = memif_get_queue_efd(memif_connection_->conn, 0, &fd);
  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    TRANSPORT_LOGE("memif_get_queue_efd: %s", memif_strerror(err));
    return;
  }

  // Remove fd from main epoll
  main_event_reactor_.delFileDescriptor(fd);

  // Add fd to epoll of instance
  event_reactor_.addFileDescriptor(
      fd, EPOLLIN, [this](const utils::Event &evt) -> int {
        return onInterrupt(memif_connection_->conn, this, 0);
      });

  memif_worker_ = std::make_unique<std::thread>(
      std::bind(&MemifConnector::threadMain, this));
}

int MemifConnector::createMemif(uint32_t index, uint8_t mode, char *s) {
  memif_connection_t *c = memif_connection_.get();

  /* setting memif connection arguments */
  memif_conn_args_t args;
  memset(&args, 0, sizeof(args));

  args.is_master = mode;
  args.log2_ring_size = MEMIF_LOG2_RING_SIZE;
  args.buffer_size = MEMIF_BUF_SIZE;
  args.num_s2m_rings = 1;
  args.num_m2s_rings = 1;
  strncpy((char *)args.interface_name, IF_NAME, strlen(IF_NAME) + 1);
  args.mode = memif_interface_mode_t::MEMIF_INTERFACE_MODE_IP;

  int err;

  err = memif_create_socket(&args.socket, socket_filename_.c_str(), nullptr);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    throw errors::RuntimeException(memif_strerror(err));
  }

  args.interface_id = index;
  /* last argument for memif_create (void * private_ctx) is used by user
     to identify connection. this context is returned with callbacks */

  /* default interrupt */
  if (s == nullptr) {
    err = memif_create(&c->conn, &args, onConnect, onDisconnect, onInterrupt,
                       this);

    if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
      throw errors::RuntimeException(memif_strerror(err));
    }
  }

  c->index = (uint16_t)index;
  c->tx_qid = 0;
  /* alloc memif buffers */
  c->rx_buf_num = 0;
  c->rx_bufs = static_cast<memif_buffer_t *>(
      malloc(sizeof(memif_buffer_t) * MAX_MEMIF_BUFS));
  c->tx_buf_num = 0;
  c->tx_bufs = static_cast<memif_buffer_t *>(
      malloc(sizeof(memif_buffer_t) * MAX_MEMIF_BUFS));

  // memif_set_rx_mode (c->conn, MEMIF_RX_MODE_POLLING, 0);

  return 0;
}

int MemifConnector::deleteMemif() {
  memif_connection_t *c = memif_connection_.get();

  if (c->rx_bufs) {
    free(c->rx_bufs);
  }

  c->rx_bufs = nullptr;
  c->rx_buf_num = 0;

  if (c->tx_bufs) {
    free(c->tx_bufs);
  }

  c->tx_bufs = nullptr;
  c->tx_buf_num = 0;

  int err;
  /* disconenct then delete memif connection */
  err = memif_delete(&c->conn);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    TRANSPORT_LOGE("memif_delete: %s", memif_strerror(err));
  }

  if (TRANSPORT_EXPECT_FALSE(c->conn != nullptr)) {
    TRANSPORT_LOGE("memif delete fail");
  }

  return 0;
}

int MemifConnector::controlFdUpdate(int fd, uint8_t events, void *private_ctx) {
  /* convert memif event definitions to epoll events */
  if (events & MEMIF_FD_EVENT_DEL) {
    return MemifConnector::main_event_reactor_.delFileDescriptor(fd);
  }

  uint32_t evt = 0;

  if (events & MEMIF_FD_EVENT_READ) {
    evt |= EPOLLIN;
  }

  if (events & MEMIF_FD_EVENT_WRITE) {
    evt |= EPOLLOUT;
  }

  if (events & MEMIF_FD_EVENT_MOD) {
    return MemifConnector::main_event_reactor_.modFileDescriptor(fd, evt);
  }

  return MemifConnector::main_event_reactor_.addFileDescriptor(
      fd, evt, [](const utils::Event &evt) -> int {
        uint32_t event = 0;
        int memif_err = 0;

        if (evt.events & EPOLLIN) {
          event |= MEMIF_FD_EVENT_READ;
        }

        if (evt.events & EPOLLOUT) {
          event |= MEMIF_FD_EVENT_WRITE;
        }

        if (evt.events & EPOLLERR) {
          event |= MEMIF_FD_EVENT_ERROR;
        }

        memif_err = memif_control_fd_handler(evt.data.fd, event);

        if (TRANSPORT_EXPECT_FALSE(memif_err != MEMIF_ERR_SUCCESS)) {
          TRANSPORT_LOGE("memif_control_fd_handler: %s",
                         memif_strerror(memif_err));
        }

        return 0;
      });
}

int MemifConnector::bufferAlloc(long n, uint16_t qid) {
  memif_connection_t *c = memif_connection_.get();
  int err;
  uint16_t r;
  /* set data pointer to shared memory and set buffer_len to shared mmeory
   * buffer len */
  err = memif_buffer_alloc(c->conn, qid, c->tx_bufs, n, &r, 2000);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    TRANSPORT_LOGE("memif_buffer_alloc: %s", memif_strerror(err));
  }

  c->tx_buf_num += r;
  return r;
}

int MemifConnector::txBurst(uint16_t qid) {
  memif_connection_t *c = memif_connection_.get();
  int err;
  uint16_t r;
  /* inform peer memif interface about data in shared memory buffers */
  /* mark memif buffers as free */
  err = memif_tx_burst(c->conn, qid, c->tx_bufs, c->tx_buf_num, &r);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    TRANSPORT_LOGE("memif_tx_burst: %s", memif_strerror(err));
  }

  // err = memif_refill_queue(c->conn, qid, r, 0);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    TRANSPORT_LOGE("memif_tx_burst: %s", memif_strerror(err));
    c->tx_buf_num -= r;
    return -1;
  }

  c->tx_buf_num -= r;
  return 0;
}

void MemifConnector::sendCallback(const std::error_code &ec) {
  timer_set_ = false;

  if (TRANSPORT_EXPECT_TRUE(!ec && state_ == ConnectorState::CONNECTED)) {
    doSend();
  }
}

void MemifConnector::processInputBuffer() {
  Packet::MemBufPtr ptr;

  while (input_buffer_.pop(ptr)) {
    receive_callback_(std::move(ptr));
  }
}

/* informs user about connected status. private_ctx is used by user to identify
   connection (multiple connections WIP) */
int MemifConnector::onConnect(memif_conn_handle_t conn, void *private_ctx) {
  MemifConnector *connector = (MemifConnector *)private_ctx;
  connector->state_ = ConnectorState::CONNECTED;
  memif_refill_queue(conn, 0, -1, 0);

  return 0;
}

/* informs user about disconnected status. private_ctx is used by user to
   identify connection (multiple connections WIP) */
int MemifConnector::onDisconnect(memif_conn_handle_t conn, void *private_ctx) {
  MemifConnector *connector = (MemifConnector *)private_ctx;
  connector->state_ = ConnectorState::CLOSED;
  return 0;
}

void MemifConnector::threadMain() { event_reactor_.runEventLoop(1000); }

int MemifConnector::onInterrupt(memif_conn_handle_t conn, void *private_ctx,
                                uint16_t qid) {
  MemifConnector *connector = (MemifConnector *)private_ctx;

  memif_connection_t *c = connector->memif_connection_.get();
  int err = MEMIF_ERR_SUCCESS, ret_val;
  uint16_t rx;

  do {
    err = memif_rx_burst(conn, qid, c->rx_bufs, MAX_MEMIF_BUFS, &rx);
    ret_val = err;

    if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS &&
                               err != MEMIF_ERR_NOBUF)) {
      TRANSPORT_LOGE("memif_rx_burst: %s", memif_strerror(err));
      goto error;
    }

    c->rx_buf_num += rx;

    if (TRANSPORT_EXPECT_TRUE(connector->io_service_.stopped())) {
      TRANSPORT_LOGE("socket stopped: ignoring %u packets", rx);
      goto error;
    }

    std::size_t packet_length;
    for (int i = 0; i < rx; i++) {
      auto packet = connector->getPacket();
      packet_length = (c->rx_bufs + i)->len;
      std::memcpy(packet->writableData(),
                  reinterpret_cast<const uint8_t *>((c->rx_bufs + i)->data),
                  packet_length);
      packet->append(packet_length);

      if (!connector->input_buffer_.push(std::move(packet))) {
        TRANSPORT_LOGE("Error pushing packet. Ring buffer full.");

        // TODO Here we should consider the possibility to signal the congestion
        // to the application, that would react properly (e.g. slow down
        // message)
      }
    }

    /* mark memif buffers and shared memory buffers as free */
    /* free processed buffers */

    err = memif_refill_queue(conn, qid, rx, 0);

    if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
      TRANSPORT_LOGE("memif_buffer_free: %s", memif_strerror(err));
    }

    c->rx_buf_num -= rx;

  } while (ret_val == MEMIF_ERR_NOBUF);

  connector->io_service_.post(
      std::bind(&MemifConnector::processInputBuffer, connector));

  return 0;

error:
  err = memif_refill_queue(c->conn, qid, rx, 0);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    TRANSPORT_LOGE("memif_buffer_free: %s", memif_strerror(err));
  }
  c->rx_buf_num -= rx;

  return 0;
}

void MemifConnector::close() {
  if (state_ != ConnectorState::CLOSED) {
    disconnect_timer_->expiresFromNow(std::chrono::microseconds(50));
    disconnect_timer_->asyncWait([this](const std::error_code &ec) {
      deleteMemif();
      event_reactor_.stop();
      work_.reset();
    });

    if (memif_worker_ && memif_worker_->joinable()) {
      memif_worker_->join();
    }
  }
}

void MemifConnector::send(const Packet::MemBufPtr &packet) {
  {
    utils::SpinLock::Acquire locked(write_msgs_lock_);
    output_buffer_.push_back(packet);
  }
#if CANCEL_TIMER
  if (!timer_set_) {
    timer_set_ = true;
    send_timer_->expiresFromNow(std::chrono::microseconds(50));
    send_timer_->asyncWait(
        std::bind(&MemifConnector::sendCallback, this, std::placeholders::_1));
  }
#endif
}

int MemifConnector::doSend() {
  std::size_t max = 0;
  uint16_t n = 0;
  std::size_t size = 0;

  {
    utils::SpinLock::Acquire locked(write_msgs_lock_);
    size = output_buffer_.size();
  }

  do {
    max = size < MAX_MEMIF_BUFS ? size : MAX_MEMIF_BUFS;

    if (TRANSPORT_EXPECT_FALSE(
            (n = bufferAlloc(max, memif_connection_->tx_qid)) < 0)) {
      TRANSPORT_LOGE("Error allocating buffers.");
      return -1;
    }

    for (uint16_t i = 0; i < n; i++) {
      utils::SpinLock::Acquire locked(write_msgs_lock_);

      auto packet = output_buffer_.front().get();
      const utils::MemBuf *current = packet;
      std::size_t offset = 0;
      uint8_t *shared_buffer =
          reinterpret_cast<uint8_t *>(memif_connection_->tx_bufs[i].data);
      do {
        std::memcpy(shared_buffer + offset, current->data(), current->length());
        offset += current->length();
        current = current->next();
      } while (current != packet);

      memif_connection_->tx_bufs[i].len = uint32_t(offset);

      output_buffer_.pop_front();
    }

    txBurst(memif_connection_->tx_qid);

    utils::SpinLock::Acquire locked(write_msgs_lock_);
    size = output_buffer_.size();
  } while (size > 0);

  return 0;
}

void MemifConnector::send(const uint8_t *packet, std::size_t len,
                          const PacketSentCallback &packet_sent) {
  throw errors::NotImplementedException();
}

}  // end namespace core

}  // end namespace transport

#endif  // __vpp__
