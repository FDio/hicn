/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <glog/logging.h>
#include <hicn/transport/core/asio_wrapper.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#include <io_modules/loopback/local_face.h>

namespace transport {
namespace core {

Face::Face(Connector::PacketReceivedCallback &&receive_callback,
           asio::io_service &io_service, const std::string &app_name)
    : receive_callback_(std::move(receive_callback)),
      io_service_(io_service),
      name_(app_name) {}

Face::Face(const Face &other)
    : receive_callback_(other.receive_callback_),
      io_service_(other.io_service_),
      name_(other.name_) {}

Face::Face(Face &&other)
    : receive_callback_(std::move(other.receive_callback_)),
      io_service_(other.io_service_),
      name_(std::move(other.name_)) {}

Face &Face::operator=(const Face &other) {
  receive_callback_ = other.receive_callback_;
  io_service_ = other.io_service_;
  name_ = other.name_;

  return *this;
}

Face &Face::operator=(Face &&other) {
  receive_callback_ = std::move(other.receive_callback_);
  io_service_ = std::move(other.io_service_);
  name_ = std::move(other.name_);

  return *this;
}

void Face::onPacket(const Packet &packet) {
  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Sending content to local socket.";

  switch (packet->getType()) {
    case HICN_PACKET_TYPE_INTEREST:
      rescheduleOnIoService<Interest>(packet);
      break;
    case HICN_PACKET_TYPE_DATA:
      rescheduleOnIoService<ContentObject>(packet);
      break;
    default:
      /* Should not occur */
      break;
  }
}

}  // namespace core
}  // namespace transport
