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

#include <core/memif_connector.h>
#include <glog/logging.h>
#include <hicn/transport/config.h>
#include <hicn/transport/errors/not_implemented_exception.h>
#include <io_modules/memif/hicn_vapi.h>
#include <io_modules/memif/vpp_forwarder_module.h>

extern "C" {
#include <libmemif.h>
};

#define MEMIF_DEFAULT_RING_SIZE 2048
#define MEMIF_DEFAULT_RX_QUEUES 1
#define MEMIF_DEFAULT_TX_QUEUES 1
#define MEMIF_DEFAULT_BUFFER_SIZE 2048

namespace transport {

namespace core {

VPPForwarderModule::VPPForwarderModule()
    : IoModule(),
      memif_forwarder_(MemifForwarderGlobal::getInstance().getReference()),
      face_id1_(~0),
      face_id2_(~0),
      is_consumer_(false),
      connector_id_(~0),
      name_() {}

VPPForwarderModule::~VPPForwarderModule() {}

void VPPForwarderModule::init(
    Connector::PacketReceivedCallback &&receive_callback,
    Connector::PacketSentCallback &&sent_callback,
    Connector::OnCloseCallback &&close_callback,
    Connector::OnReconnectCallback &&reconnect_callback,
    asio::io_service &io_service, const std::string &app_name) {
  const auto &[id, port] = memif_forwarder_->registerLocalConnector(
      io_service, std::move(receive_callback), std::move(sent_callback),
      std::move(close_callback), std::move(reconnect_callback));

  connector_id_ = id;
  src_port_ = port;
  name_ = app_name;
}

void VPPForwarderModule::processControlMessageReply(
    utils::MemBuf &packet_buffer) {
  throw errors::NotImplementedException();
}

bool VPPForwarderModule::isControlMessage(utils::MemBuf &packet_buffer) {
  return false;
}

bool VPPForwarderModule::isConnected() {
  return memif_forwarder_->isConnected();
}

void VPPForwarderModule::send(Packet &packet) {
  IoModule::send(packet);
  memif_forwarder_->send(packet);
}

void VPPForwarderModule::send(const utils::MemBuf::Ptr &buffer) {
  IoModule::send(buffer);
  memif_forwarder_->send(buffer);
}

std::uint32_t VPPForwarderModule::getMtu() { return MemifConnector::kbuf_size; }

void VPPForwarderModule::consumerConnection() {
  CHECK(memif_forwarder_->isConnected());

  hicn_consumer_input_params input = {0};
  hicn_consumer_output_params output = {0};
  hicn_ip_address_t ip4_address;
  hicn_ip_address_t ip6_address;

  output.src4 = &ip4_address;
  output.src6 = &ip6_address;
  input.swif = memif_forwarder_->getSwIfIndex();
  input.port = src_port_;

  int ret = hicn_vapi_register_cons_app(memif_forwarder_->getVapiCtx(), &input,
                                        &output);

  if (ret < 0) {
    throw errors::RuntimeException(hicn_vapi_get_error_string(ret));
  }

  face_id1_ = output.face_id1;
  face_id2_ = output.face_id2;

  std::memcpy(inet_address_.v4.as_u8, output.src4->v4.as_u8, IPV4_ADDR_LEN);
  std::memcpy(inet6_address_.v6.as_u8, output.src6->v6.as_u8, IPV6_ADDR_LEN);
}

void VPPForwarderModule::producerConnection() {
  // Producer connection will be set when we set the first route.
}

void VPPForwarderModule::connect(bool is_consumer) {
  is_consumer_ = is_consumer;
  if (is_consumer_) {
    consumerConnection();
  }

  memif_forwarder_->getConnector(connector_id_)
      ->setRole(is_consumer ? Connector::Role::CONSUMER
                            : Connector::Role::PRODUCER);
}

void VPPForwarderModule::registerRoute(const Prefix &prefix) {
  const hicn_ip_prefix_t &addr = prefix.toIpPrefixStruct();

  hicn_ip_prefix_t producer_prefix;
  hicn_ip_address_t producer_locator;

  if (face_id1_ == uint32_t(~0)) {
    hicn_producer_input_params input;
    std::memset(&input, 0, sizeof(input));

    hicn_producer_output_params output;
    std::memset(&output, 0, sizeof(output));

    input.prefix = &producer_prefix;
    output.prod_addr = &producer_locator;

    // Here we have to ask to the actual connector what is the
    // memif_id, since this function should be called after the
    // memif creation.n
    input.swif = memif_forwarder_->getSwIfIndex();
    input.prefix->address = addr.address;
    input.prefix->family = addr.family;
    input.prefix->len = addr.len;
    input.cs_reserved = content_store_reserved_;
    input.port = src_port_;

    int ret = hicn_vapi_register_prod_app(memif_forwarder_->getVapiCtx(),
                                          &input, &output);

    if (ret < 0) {
      throw errors::RuntimeException(hicn_vapi_get_error_string(ret));
    }

    std::memcpy(inet6_address_.v6.as_u8, output.prod_addr->v6.as_u8,
                sizeof(inet6_address_));

    face_id1_ = output.face_id;
  } else {
    hicn_producer_set_route_params params;
    params.prefix = &producer_prefix;
    params.prefix->address = addr.address;
    params.prefix->family = addr.family;
    params.prefix->len = addr.len;
    params.prod_addr = &producer_locator;

    int ret = hicn_vapi_register_route(memif_forwarder_->getVapiCtx(), &params);

    if (ret < 0) {
      throw errors::RuntimeException(hicn_vapi_get_error_string(ret));
    }
  }
}

void VPPForwarderModule::closeConnection() {
  if (is_consumer_) {
    hicn_del_face_app_input_params params;
    params.face_id = face_id1_;
    hicn_vapi_face_cons_del(memif_forwarder_->getVapiCtx(), &params);
    params.face_id = face_id2_;
    hicn_vapi_face_cons_del(memif_forwarder_->getVapiCtx(), &params);
  } else {
    hicn_del_face_app_input_params params;
    params.face_id = face_id1_;
    hicn_vapi_face_prod_del(memif_forwarder_->getVapiCtx(), &params);
  }

  memif_forwarder_->deleteConnector(connector_id_);
}

extern "C" IoModule *create_module(void) { return new VPPForwarderModule(); }

}  // namespace core

}  // namespace transport
