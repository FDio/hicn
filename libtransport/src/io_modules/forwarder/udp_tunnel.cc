/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#include <hicn/transport/utils/branch_prediction.h>
#include <io_modules/forwarder/errors.h>
#include <io_modules/forwarder/udp_tunnel.h>

#include <iostream>
#include <thread>
#include <vector>

namespace transport {
namespace core {

UdpTunnelConnector::~UdpTunnelConnector() {}

void UdpTunnelConnector::connect(const std::string &hostname, uint16_t port,
                                 const std::string &bind_address,
                                 uint16_t bind_port) {
  if (state_ == State::CLOSED) {
    state_ = State::CONNECTING;
    endpoint_iterator_ = resolver_.resolve({hostname, std::to_string(port)});
    remote_endpoint_send_ = *endpoint_iterator_;
    socket_->open(remote_endpoint_send_.protocol());

    if (!bind_address.empty() && bind_port != 0) {
      using namespace asio::ip;
      socket_->bind(
          udp::endpoint(address::from_string(bind_address), bind_port));
    }

    state_ = State::CONNECTED;

    remote_endpoint_ = Endpoint(remote_endpoint_send_);
    local_endpoint_ = Endpoint(socket_->local_endpoint());

    doRecvPacket();

#ifdef LINUX
    send_timer_.expires_from_now(std::chrono::microseconds(50));
    send_timer_.async_wait(std::bind(&UdpTunnelConnector::writeHandler, this,
                                     std::placeholders::_1));
#endif
  }
}

void UdpTunnelConnector::send(Packet &packet) {
  strand_->post([this, pkt{packet.shared_from_this()}]() {
    bool write_in_progress = !output_buffer_.empty();
    output_buffer_.push_back(std::move(pkt));
    if (TRANSPORT_EXPECT_TRUE(state_ == State::CONNECTED)) {
      if (!write_in_progress) {
        doSendPacket();
      }
    } else {
      data_available_ = true;
    }
  });
}

void UdpTunnelConnector::send(const uint8_t *packet, std::size_t len) {}

void UdpTunnelConnector::close() {
  TRANSPORT_LOGD("UDPTunnelConnector::close");
  state_ = State::CLOSED;
  bool is_socket_owned = socket_.use_count() == 1;
  if (is_socket_owned) {
    io_service_.dispatch([this]() {
      this->socket_->close();
      // on_close_callback_(shared_from_this());
    });
  }
}

void UdpTunnelConnector::doSendPacket() {
#ifdef LINUX
  send_timer_.expires_from_now(std::chrono::microseconds(50));
  send_timer_.async_wait(std::bind(&UdpTunnelConnector::writeHandler, this,
                                   std::placeholders::_1));
#else
  auto packet = output_buffer_.front().get();
  auto array = std::vector<asio::const_buffer>();

  const ::utils::MemBuf *current = packet;
  do {
    array.push_back(asio::const_buffer(current->data(), current->length()));
    current = current->next();
  } while (current != packet);

  socket_->async_send_to(
      std::move(array), remote_endpoint_send_,
      strand_->wrap([this](std::error_code ec, std::size_t length) {
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          sent_callback_(this, make_error_code(forwarder_error::success));
        } else if (ec.value() ==
                   static_cast<int>(std::errc::operation_canceled)) {
          // The connection has been closed by the application.
          return;
        } else {
          sendFailed();
          sent_callback_(this, ec);
        }

        output_buffer_.pop_front();
        if (!output_buffer_.empty()) {
          doSendPacket();
        }
      }));
#endif
}

#ifdef LINUX
void UdpTunnelConnector::writeHandler(std::error_code ec) {
  if (TRANSPORT_EXPECT_FALSE(state_ != State::CONNECTED)) {
    return;
  }

  auto len = std::min(output_buffer_.size(), std::size_t(Connector::max_burst));

  if (len) {
    int m = 0;
    for (auto &p : output_buffer_) {
      auto packet = p.get();
      ::utils::MemBuf *current = packet;
      int b = 0;
      do {
        // array.push_back(asio::const_buffer(current->data(),
        // current->length()));
        tx_iovecs_[m][b].iov_base = current->writableData();
        tx_iovecs_[m][b].iov_len = current->length();
        current = current->next();
        b++;
      } while (current != packet);

      tx_msgs_[m].msg_hdr.msg_iov = tx_iovecs_[m];
      tx_msgs_[m].msg_hdr.msg_iovlen = b;
      tx_msgs_[m].msg_hdr.msg_name = remote_endpoint_send_.data();
      tx_msgs_[m].msg_hdr.msg_namelen = remote_endpoint_send_.size();
      m++;

      if (--len == 0) {
        break;
      }
    }

    int retval = sendmmsg(socket_->native_handle(), tx_msgs_, m, MSG_DONTWAIT);
    if (retval > 0) {
      while (retval--) {
        output_buffer_.pop_front();
      }
    } else if (retval != EWOULDBLOCK && retval != EAGAIN) {
      TRANSPORT_LOGE("Error sending messages! %s %d\n", strerror(errno),
                     retval);
      return;
    }
  }

  if (!output_buffer_.empty()) {
    send_timer_.expires_from_now(std::chrono::microseconds(50));
    send_timer_.async_wait(std::bind(&UdpTunnelConnector::writeHandler, this,
                                     std::placeholders::_1));
  }
}

void UdpTunnelConnector::readHandler(std::error_code ec) {
  TRANSPORT_LOGD("UdpTunnelConnector receive packet");

  // TRANSPORT_LOGD("UdpTunnelConnector received packet length=%lu", length);
  if (TRANSPORT_EXPECT_TRUE(!ec)) {
    if (TRANSPORT_EXPECT_TRUE(state_ == State::CONNECTED)) {
      if (current_position_ == 0) {
        for (int i = 0; i < max_burst; i++) {
          auto read_buffer = getRawBuffer();
          rx_iovecs_[i][0].iov_base = read_buffer.first;
          rx_iovecs_[i][0].iov_len = read_buffer.second;
          rx_msgs_[i].msg_hdr.msg_iov = rx_iovecs_[i];
          rx_msgs_[i].msg_hdr.msg_iovlen = 1;
        }
      }

      int res = recvmmsg(socket_->native_handle(), rx_msgs_ + current_position_,
                         max_burst - current_position_, MSG_DONTWAIT, nullptr);
      if (res < 0) {
        TRANSPORT_LOGE("Error receiving messages! %s %d\n", strerror(errno),
                       res);
        return;
      }

      for (int i = 0; i < res; i++) {
        auto packet = getPacketFromBuffer(
            reinterpret_cast<uint8_t *>(
                rx_msgs_[current_position_].msg_hdr.msg_iov[0].iov_base),
            rx_msgs_[current_position_].msg_len);
        receiveSuccess(*packet);
        receive_callback_(this, *packet,
                          make_error_code(forwarder_error::success));
        ++current_position_;
      }

      doRecvPacket();
    } else {
      TRANSPORT_LOGE(
          "Error in UDP: Receiving packets from a not connected socket.");
    }
  } else if (ec.value() == static_cast<int>(std::errc::operation_canceled)) {
    TRANSPORT_LOGE("The connection has been closed by the application.");
    return;
  } else {
    if (TRANSPORT_EXPECT_TRUE(state_ == State::CONNECTED)) {
      // receive_callback_(this, *read_msg_, ec);
      TRANSPORT_LOGE("Error in UDP connector: %d %s", ec.value(),
                     ec.message().c_str());
    } else {
      TRANSPORT_LOGE("Error while not connector");
    }
  }
}
#endif

void UdpTunnelConnector::doRecvPacket() {
#ifdef LINUX
  if (state_ == State::CONNECTED) {
#if ((ASIO_VERSION / 100 % 1000) < 11)
    socket_->async_receive(asio::null_buffers(),
#else
    socket_->async_wait(asio::ip::tcp::socket::wait_read,
#endif
                        std::bind(&UdpTunnelConnector::readHandler, this,
                                  std::placeholders::_1));
  }
#else
  TRANSPORT_LOGD("UdpTunnelConnector receive packet");
  read_msg_ = getRawBuffer();
  socket_->async_receive_from(
      asio::buffer(read_msg_.first, read_msg_.second), remote_endpoint_recv_,
      [this](std::error_code ec, std::size_t length) {
        TRANSPORT_LOGD("UdpTunnelConnector received packet length=%lu", length);
        if (TRANSPORT_EXPECT_TRUE(!ec)) {
          if (TRANSPORT_EXPECT_TRUE(state_ == State::CONNECTED)) {
            auto packet = getPacketFromBuffer(read_msg_.first, length);
            receiveSuccess(*packet);
            receive_callback_(this, *packet,
                              make_error_code(forwarder_error::success));
            doRecvPacket();
          } else {
            TRANSPORT_LOGE(
                "Error in UDP: Receiving packets from a not connected socket.");
          }
        } else if (ec.value() ==
                   static_cast<int>(std::errc::operation_canceled)) {
          TRANSPORT_LOGE("The connection has been closed by the application.");
          return;
        } else {
          if (TRANSPORT_EXPECT_TRUE(state_ == State::CONNECTED)) {
            TRANSPORT_LOGE("Error in UDP connector: %d %s", ec.value(),
                           ec.message().c_str());
          } else {
            TRANSPORT_LOGE("Error while not connector");
          }
        }
      });
#endif
}

void UdpTunnelConnector::doConnect() {
  asio::async_connect(
      *socket_, endpoint_iterator_,
      [this](std::error_code ec, asio::ip::udp::resolver::iterator) {
        if (!ec) {
          state_ = State::CONNECTED;
          doRecvPacket();

          if (data_available_) {
            data_available_ = false;
            doSendPacket();
          }
        } else {
          TRANSPORT_LOGE("[Hproxy] - UDP Connection failed!!!");
          timer_.expires_from_now(std::chrono::milliseconds(500));
          timer_.async_wait(std::bind(&UdpTunnelConnector::doConnect, this));
        }
      });
}

}  // namespace core

}  // namespace transport
