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

#include <core/errors.h>
#include <core/memif_connector.h>
#include <glog/logging.h>
#include <hicn/transport/errors/not_implemented_exception.h>
#include <sys/epoll.h>

#include <cstdlib>

/* sstrncpy */
#include <hicn/util/sstrncpy.h>

#define CANCEL_TIMER 1

namespace transport {

namespace core {

MemifConnector::MemifConnector(PacketReceivedCallback &&receive_callback,
                               PacketSentCallback &&packet_sent,
                               OnCloseCallback &&close_callback,
                               OnReconnectCallback &&on_reconnect,
                               asio::io_service &io_service,
                               std::string app_name)
    : Connector(std::move(receive_callback), std::move(packet_sent),
                std::move(close_callback), std::move(on_reconnect)),
      event_reactor_(),
      memif_worker_(std::bind(&MemifConnector::threadMain, this)),
      timer_set_(false),
      send_timer_(event_reactor_),
      disconnect_timer_(event_reactor_),
      io_service_(io_service),
      work_(asio::make_work_guard(io_service_)),
      memif_connection_({0}),
      tx_buf_counter_(0),
      is_reconnection_(false),
      data_available_(false),
      app_name_(app_name),
      socket_filename_(""),
      buffer_size_(kbuf_size),
      log2_ring_size_(klog2_ring_size),
      max_memif_bufs_(1 << klog2_ring_size) {}

MemifConnector::~MemifConnector() { close(); }

void MemifConnector::connect(uint32_t memif_id, long memif_mode,
                             const std::string &socket_filename,
                             std::size_t buffer_size,
                             std::size_t log2_ring_size) {
  state_ = State::CONNECTING;

  memif_id_ = memif_id;
  socket_filename_ = socket_filename;
  buffer_size_ = buffer_size;
  log2_ring_size_ = log2_ring_size;
  max_memif_bufs_ = 1 << log2_ring_size;
  createMemif(memif_id, memif_mode);
}

int MemifConnector::createMemif(uint32_t index, uint8_t is_master) {
  int err = MEMIF_ERR_SUCCESS;

  memif_socket_args_t socket_args;
  memif_conn_args_t args;
  memset(&socket_args, 0, sizeof(memif_socket_args_t));
  memset(&args, 0, sizeof(memif_conn_args_t));

  // Setup memif socket first

  int rc = strcpy_s(socket_args.path, sizeof(socket_args.path) - 1,
                    socket_filename_.c_str());
  if (rc != EOK) {
    std::string error = "Provided socket path is larger than " +
                        std::to_string(sizeof(socket_args.path)) + " bytes.";
    throw errors::RuntimeException(error);
  }

  rc = strcpy_s(socket_args.app_name, sizeof(socket_args.app_name) - 1,
                app_name_.c_str());
  if (rc != EOK) {
    std::string error = "Provided app_name is larger than " +
                        std::to_string(sizeof(socket_args.app_name)) +
                        " bytes.";
    throw errors::RuntimeException(error);
  }

  socket_args.on_control_fd_update = controlFdUpdate;
  socket_args.alloc = nullptr;
  socket_args.realloc = nullptr;
  socket_args.free = nullptr;

  err = memif_create_socket(&args.socket, &socket_args, this);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    throw errors::RuntimeException(memif_strerror(err));
  }

  // Setup memif connection using provided memif_socket_handle_t
  args.is_master = is_master;
  args.log2_ring_size = log2_ring_size_;
  args.buffer_size = buffer_size_;
  args.num_s2m_rings = 1;
  args.num_m2s_rings = 1;
  strcpy_s((char *)args.interface_name, sizeof(args.interface_name), IF_NAME);
  args.mode = memif_interface_mode_t::MEMIF_INTERFACE_MODE_IP;
  args.interface_id = index;
  err = memif_create(&memif_connection_.conn, &args, onConnect, onDisconnect,
                     onInterrupt, this);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    throw errors::RuntimeException(memif_strerror(err));
  }

  memif_connection_.index = (uint16_t)index;
  memif_connection_.tx_qid = 0;
  /* alloc memif buffers */
  memif_connection_.rx_buf_num = 0;
  memif_connection_.rx_bufs = static_cast<memif_buffer_t *>(
      malloc(sizeof(memif_buffer_t) * max_memif_bufs_));
  memif_connection_.tx_buf_num = 0;
  memif_connection_.tx_bufs = static_cast<memif_buffer_t *>(
      malloc(sizeof(memif_buffer_t) * max_memif_bufs_));

  return 0;
}

int MemifConnector::deleteMemif() {
  if (memif_connection_.rx_bufs) {
    free(memif_connection_.rx_bufs);
  }

  memif_connection_.rx_bufs = nullptr;
  memif_connection_.rx_buf_num = 0;

  if (memif_connection_.tx_bufs) {
    free(memif_connection_.tx_bufs);
  }

  memif_connection_.tx_bufs = nullptr;
  memif_connection_.tx_buf_num = 0;

  int err;
  /* disconenct then delete memif connection */
  err = memif_delete(&memif_connection_.conn);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    LOG(ERROR) << "memif_delete: " << memif_strerror(err);
  }

  if (TRANSPORT_EXPECT_FALSE(memif_connection_.conn != nullptr)) {
    LOG(ERROR) << "memif delete fail";
  }

  state_ = State::CLOSED;

  return 0;
}

int MemifConnector::controlFdUpdate(memif_fd_event_t fde, void *private_ctx) {
  auto self = reinterpret_cast<MemifConnector *>(private_ctx);
  uint32_t evt = 0;

  /* convert memif event definitions to epoll events */
  auto events = fde.type;
  auto fd = fde.fd;

  if (events & MEMIF_FD_EVENT_ERROR) {
    LOG(ERROR) << "memif fd event: Error";
    return -1;
  }

  if (events & MEMIF_FD_EVENT_DEL) {
    DLOG_IF(INFO, VLOG_IS_ON(4)) << "memif fd event: DEL fd " << fd;
    return self->event_reactor_.delFileDescriptor(fd);
  }

  if (events & MEMIF_FD_EVENT_MOD) {
    DLOG_IF(INFO, VLOG_IS_ON(4)) << "memif fd event: MOD fd " << fd;
    return self->event_reactor_.modFileDescriptor(fd, evt);
  }

  if (events & MEMIF_FD_EVENT_READ) {
    evt |= EPOLLIN;
  }

  if (events & MEMIF_FD_EVENT_WRITE) {
    evt |= EPOLLOUT;
  }

  DLOG_IF(INFO, VLOG_IS_ON(4)) << "memif fd event: ADD fd " << fd;
  return self->event_reactor_.addFileDescriptor(
      fd, evt, [fde](const utils::Event &evt) -> int {
        int event = 0;
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

        memif_err = memif_control_fd_handler(fde.private_ctx,
                                             memif_fd_event_type_t(event));

        if (TRANSPORT_EXPECT_FALSE(memif_err != MEMIF_ERR_SUCCESS)) {
          LOG(ERROR) << "memif_control_fd_handler: "
                     << memif_strerror(memif_err);
        }

        return 0;
      });
}

uint16_t MemifConnector::bufferAlloc(long n, uint16_t qid,
                                     std::error_code &ec) {
  int err;
  uint16_t r = 0;
  /* set data pointer to shared memory and set buffer_len to shared mmeory
   * buffer len */
  err = memif_buffer_alloc(memif_connection_.conn, qid,
                           memif_connection_.tx_bufs, n, &r, buffer_size_);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    ec = make_error_code(core_error::send_buffer_allocation_failed);
  }

  memif_connection_.tx_buf_num += r;
  return r;
}

uint16_t MemifConnector::txBurst(uint16_t qid, std::error_code &ec) {
  int err = MEMIF_ERR_SUCCESS;
  ec = make_error_code(core_error::success);
  uint16_t tx = 0;

  /* inform peer memif interface about data in shared memory buffers */
  /* mark memif buffers as free */
  err = memif_tx_burst(memif_connection_.conn, qid, memif_connection_.tx_bufs,
                       memif_connection_.tx_buf_num, &tx);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    ec = make_error_code(core_error::send_failed);
  }

  memif_connection_.tx_buf_num -= tx;
  return tx;
}

void MemifConnector::scheduleSend(std::uint64_t delay) {
  if (!timer_set_) {
    timer_set_ = true;
    send_timer_.expiresFromNow(std::chrono::microseconds(delay));
    send_timer_.asyncWait(
        std::bind(&MemifConnector::sendCallback, this, std::placeholders::_1));
  }
}

void MemifConnector::sendCallback(const std::error_code &ec) {
  timer_set_ = false;

  if (TRANSPORT_EXPECT_TRUE(!ec && state_ == State::CONNECTED)) {
    doSend();
  }
}

/* informs user about connected status. private_ctx is used by user to identify
   connection (multiple connections WIP) */
int MemifConnector::onConnect(memif_conn_handle_t conn, void *private_ctx) {
  auto self = reinterpret_cast<MemifConnector *>(private_ctx);
  self->state_ = State::CONNECTED;
  memif_refill_queue(conn, 0, -1, 0);

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Memif " << self->app_name_ << " connected";

  // We are connected. Notify higher layers.
  self->io_service_.post([self]() {
    self->on_reconnect_callback_(self, make_error_code(core_error::success));
  });

  self->doSend();

  return 0;
}

/* informs user about disconnected status. private_ctx is used by user to
   identify connection (multiple connections WIP) */
int MemifConnector::onDisconnect(memif_conn_handle_t conn, void *private_ctx) {
  MemifConnector *connector = (MemifConnector *)private_ctx;
  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Memif " << connector->app_name_ << " disconnected";
  return 0;
}

void MemifConnector::threadMain() { event_reactor_.runEventLoop(200); }

int MemifConnector::onInterrupt(memif_conn_handle_t conn, void *private_ctx,
                                uint16_t qid) {
  MemifConnector *connector = (MemifConnector *)private_ctx;

  Details &c = connector->memif_connection_;
  std::weak_ptr<MemifConnector> self = connector->shared_from_this();
  std::vector<::utils::MemBuf::Ptr> v;
  std::error_code ec = make_error_code(core_error::success);

  int err = MEMIF_ERR_SUCCESS, ret_val;
  uint16_t rx = 0;

  do {
    err = memif_rx_burst(conn, qid, c.rx_bufs, max_burst, &rx);
    ret_val = err;

    if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS &&
                               err != MEMIF_ERR_NOBUF)) {
      ec = make_error_code(core_error::receive_failed);
      LOG(ERROR) << "memif_rx_burst: " << memif_strerror(err);
      goto error;
    }

    c.rx_buf_num += rx;

    if (TRANSPORT_EXPECT_FALSE(connector->io_service_.stopped())) {
      LOG(ERROR) << "socket stopped: ignoring " << rx << " packets";
      goto error;
    }

    std::size_t packet_length;
    v.reserve(rx);
    for (int i = 0; i < rx; i++) {
      auto buffer = connector->getRawBuffer();
      packet_length = (c.rx_bufs + i)->len;
      std::memcpy(buffer.first, (c.rx_bufs + i)->data, packet_length);
      auto packet = connector->getPacketFromBuffer(buffer.first, packet_length);
      v.emplace_back(std::move(packet));
    }

    /* mark memif buffers and shared memory buffers as free */
    /* free processed buffers */

    err = memif_refill_queue(conn, qid, rx, 0);

    if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
      LOG(ERROR) << "memif_buffer_free: " << memif_strerror(err);
    }

    c.rx_buf_num -= rx;

  } while (ret_val == MEMIF_ERR_NOBUF);

  connector->io_service_.post([self, buffers = std::move(v)]() {
    if (auto c = self.lock()) {
      c->receive_callback_(c.get(), buffers,
                           std::make_error_code(std::errc(0)));
    }
  });

  return 0;

error:
  err = memif_refill_queue(c.conn, qid, rx, 0);

  if (TRANSPORT_EXPECT_FALSE(err != MEMIF_ERR_SUCCESS)) {
    LOG(ERROR) << "memif_buffer_free: " << memif_strerror(err);
  }
  c.rx_buf_num -= rx;

  connector->io_service_.post([self, ec]() {
    if (auto c = self.lock()) {
      c->receive_callback_(c.get(), {}, ec);
    }
  });

  return 0;
}

void MemifConnector::close() {
  if (state_ != State::CLOSED) {
    disconnect_timer_.expiresFromNow(std::chrono::microseconds(50));
    disconnect_timer_.asyncWait([this](const std::error_code &ec) {
      deleteMemif();
      event_reactor_.stop();
    });
  }

  if (memif_worker_.joinable()) {
    memif_worker_.join();
  }
}

void MemifConnector::send(Packet &packet) { send(packet.shared_from_this()); }

void MemifConnector::send(const utils::MemBuf::Ptr &buffer) {
  {
    utils::SpinLock::Acquire locked(write_msgs_lock_);
    output_buffer_.push_back(buffer);
  }
#if CANCEL_TIMER
  scheduleSend(50);
#endif
}

int MemifConnector::doSend() {
  std::size_t max = 0;
  std::size_t size = 0;
  std::error_code ec = make_error_code(core_error::success);
  int ret = 0;
  uint64_t delay = 50;  // microseconds

  utils::SpinLock::Acquire locked(write_msgs_lock_);

  // Check if there are pending buffers to send
  if (memif_connection_.tx_buf_num > 0) {
    ret = txBurst(memif_connection_.tx_qid, ec);
    if (TRANSPORT_EXPECT_FALSE(ec.operator bool())) {
      delay = 200;
      goto done;
    }
  }

  // Continue trying to send buffers in output_buffer_
  size = output_buffer_.size();
  max = size < max_burst ? size : max_burst;

  ret = bufferAlloc(max, memif_connection_.tx_qid, ec);
  if (TRANSPORT_EXPECT_FALSE(ec.operator bool() && ret == 0)) {
    delay = 200;
    goto done;
  }

  // Fill allocated buffers and remove them from output_buffer_
  for (uint16_t i = 0; i < ret; i++) {
    auto packet = output_buffer_.front().get();
    const utils::MemBuf *current = packet;
    std::size_t offset = 0;
    uint8_t *shared_buffer =
        reinterpret_cast<uint8_t *>(memif_connection_.tx_bufs[i].data);
    do {
      std::memcpy(shared_buffer + offset, current->data(), current->length());
      offset += current->length();
      current = current->next();
    } while (current != packet);

    memif_connection_.tx_bufs[i].len = uint32_t(offset);
    output_buffer_.pop_front();
  }

  // Try to send them
  ret = txBurst(memif_connection_.tx_qid, ec);
  if (TRANSPORT_EXPECT_FALSE(ec.operator bool())) {
    LOG(ERROR) << "Tx burst failed " << ec.message();
    delay = 200;
    goto done;
  }

done:
  memif_refill_queue(memif_connection_.conn, memif_connection_.tx_qid, ret, 0);

  // If there are still packets to send, schedule another send
  if (memif_connection_.tx_buf_num > 0 || !output_buffer_.empty()) {
    scheduleSend(delay);
  }

  // If error, signal to upper layers
  if (ec.operator bool()) {
    std::weak_ptr<MemifConnector> self = shared_from_this();
    io_service_.post([self, ec]() {
      if (auto c = self.lock()) {
        c->sent_callback_(c.get(), ec);
      }
    });
  }

  return 0;
}

}  // end namespace core

}  // end namespace transport
