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
#include <io_modules/memif/memif_vapi.h>
#include <io_modules/memif/vpp_forwarder_module.h>

extern "C" {
#include <libmemif.h>
};

typedef enum { MASTER = 0, SLAVE = 1 } memif_role_t;

#define MEMIF_DEFAULT_RING_SIZE 2048
#define MEMIF_DEFAULT_RX_QUEUES 1
#define MEMIF_DEFAULT_TX_QUEUES 1
#define MEMIF_DEFAULT_BUFFER_SIZE 2048

namespace transport {

namespace core {

VPPForwarderModule::VPPForwarderModule()
    : IoModule(),
      connector_(nullptr),
      memif_id_(0),
      sw_if_index_(~0),
      face_id1_(~0),
      face_id2_(~0),
      is_consumer_(false) {}

VPPForwarderModule::~VPPForwarderModule() {}

void VPPForwarderModule::init(
    Connector::PacketReceivedCallback &&receive_callback,
    Connector::PacketSentCallback &&sent_callback,
    Connector::OnCloseCallback &&close_callback,
    Connector::OnReconnectCallback &&reconnect_callback,
    asio::io_service &io_service, const std::string &app_name) {
  if (!connector_) {
    connector_ = std::make_unique<MemifConnector>(
        std::move(receive_callback), std::move(sent_callback),
        std::move(close_callback), std::move(reconnect_callback), io_service,
        app_name);
  }
}

void VPPForwarderModule::processControlMessageReply(
    utils::MemBuf &packet_buffer) {
  throw errors::NotImplementedException();
}

bool VPPForwarderModule::isControlMessage(utils::MemBuf &packet_buffer) {
  return false;
}

bool VPPForwarderModule::isConnected() { return connector_->isConnected(); };

void VPPForwarderModule::send(Packet &packet) {
  IoModule::send(packet);
  connector_->send(packet);
}

void VPPForwarderModule::send(const utils::MemBuf::Ptr &buffer) {
  counters_.tx_packets++;
  counters_.tx_bytes += buffer->length();

  // Perfect forwarding
  connector_->send(buffer);
}

std::uint32_t VPPForwarderModule::getMtu() { return interface_mtu; }

/**
 * @brief Create a memif interface in the local VPP forwarder.
 */
uint32_t VPPForwarderModule::getMemifConfiguration() {
  memif_create_params_t input_params = {0};

  int ret = memif_vapi_get_next_memif_id(VPPForwarderModule::sock_, &memif_id_);

  if (ret < 0) {
    throw errors::RuntimeException(
        "Error getting next memif id. Could not create memif interface.");
  }

  input_params.id = memif_id_;
  input_params.role = memif_role_t::MASTER;
  input_params.mode = memif_interface_mode_t::MEMIF_INTERFACE_MODE_IP;
  input_params.rx_queues = MEMIF_DEFAULT_RX_QUEUES;
  input_params.tx_queues = MEMIF_DEFAULT_TX_QUEUES;
  input_params.ring_size = MEMIF_DEFAULT_RING_SIZE;
  input_params.buffer_size = MEMIF_DEFAULT_BUFFER_SIZE;

  memif_output_params_t output_params = {0};

  ret = memif_vapi_create_memif(VPPForwarderModule::sock_, &input_params,
                                &output_params);

  if (ret < 0) {
    throw errors::RuntimeException(
        "Error creating memif interface in the local VPP forwarder.");
  }

  return output_params.sw_if_index;
}

void VPPForwarderModule::consumerConnection() {
  hicn_consumer_input_params input = {0};
  hicn_consumer_output_params output = {0};
  ip_address_t ip4_address;
  ip_address_t ip6_address;

  output.src4 = &ip4_address;
  output.src6 = &ip6_address;
  input.swif = sw_if_index_;

  int ret =
      hicn_vapi_register_cons_app(VPPForwarderModule::sock_, &input, &output);

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
  int retry = 20;

  LOG(INFO) << "Connecting to VPP through vapi.";
  vapi_error_e ret = vapi_connect_safe(&sock_, 0);

  while (ret != VAPI_OK && retry > 0) {
    LOG(ERROR) << "Error connecting to VPP through vapi. Retrying..";
    --retry;
    ret = vapi_connect_safe(&sock_, 0);
  }

  CHECK_EQ(ret, VAPI_OK)
      << "Impossible to connect to forwarder. Is VPP running?";

  LOG(INFO) << "Connected to VPP through vapi.";

  sw_if_index_ = getMemifConfiguration();

  is_consumer_ = is_consumer;
  if (is_consumer_) {
    consumerConnection();
  }

  connector_->connect(memif_id_, 0 /* is_master = false */,
                      memif_socket_filename);
  connector_->setRole(is_consumer_ ? Connector::Role::CONSUMER
                                   : Connector::Role::PRODUCER);
}

void VPPForwarderModule::registerRoute(const Prefix &prefix) {
  const ip_prefix_t &addr = prefix.toIpPrefixStruct();

  ip_prefix_t producer_prefix;
  ip_address_t producer_locator;

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
    input.swif = sw_if_index_;
    input.prefix->address = addr.address;
    input.prefix->family = addr.family;
    input.prefix->len = addr.len;
    input.cs_reserved = content_store_reserved_;

    int ret =
        hicn_vapi_register_prod_app(VPPForwarderModule::sock_, &input, &output);

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

    int ret = hicn_vapi_register_route(VPPForwarderModule::sock_, &params);

    if (ret < 0) {
      throw errors::RuntimeException(hicn_vapi_get_error_string(ret));
    }
  }
}

void VPPForwarderModule::closeConnection() {
  if (VPPForwarderModule::sock_) {
    if (is_consumer_) {
      hicn_del_face_app_input_params params;
      params.face_id = face_id1_;
      hicn_vapi_face_cons_del(VPPForwarderModule::sock_, &params);
      params.face_id = face_id2_;
      hicn_vapi_face_cons_del(VPPForwarderModule::sock_, &params);
    } else {
      hicn_del_face_app_input_params params;
      params.face_id = face_id1_;
      hicn_vapi_face_prod_del(VPPForwarderModule::sock_, &params);
    }

    connector_->close();

    if (sw_if_index_ != uint32_t(~0)) {
      int ret =
          memif_vapi_delete_memif(VPPForwarderModule::sock_, sw_if_index_);
      if (ret < 0) {
        LOG(ERROR) << "Error deleting memif with sw idx " << sw_if_index_;
      }
    }

    vapi_disconnect_safe();
    VPPForwarderModule::sock_ = nullptr;
  }
}

extern "C" IoModule *create_module(void) { return new VPPForwarderModule(); }

}  // namespace core

}  // namespace transport
