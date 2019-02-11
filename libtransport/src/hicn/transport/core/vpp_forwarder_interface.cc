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

#include <hicn/transport/config.h>

#ifdef __vpp__

#include <hicn/transport/core/hicn_binary_api.h>
#include <hicn/transport/core/memif_binary_api.h>
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/core/vpp_forwarder_interface.h>

extern "C" {
#include <memif/libmemif.h>
};

typedef enum { MASTER = 0, SLAVE = 1 } memif_role_t;

#define MEMIF_DEFAULT_RING_SIZE 2048
#define MEMIF_DEFAULT_RX_QUEUES 1
#define MEMIF_DEFAULT_TX_QUEUES 1
#define MEMIF_DEFAULT_BUFFER_SIZE 2048

namespace transport {

namespace core {

vpp_binary_api_t *VPPForwarderInterface::api_ = nullptr;
vpp_plugin_binary_api_t *VPPForwarderInterface::memif_api_ = nullptr;
vpp_plugin_binary_api_t *VPPForwarderInterface::hicn_api_ = nullptr;
std::mutex VPPForwarderInterface::global_lock_;

VPPForwarderInterface::VPPForwarderInterface(MemifConnector &connector)
    : ForwarderInterface<VPPForwarderInterface, MemifConnector>(connector),
      sw_if_index_(~0),
      face_id_(~0) {}

VPPForwarderInterface::~VPPForwarderInterface() {}

/**
 * @brief Create a memif interface in the local VPP forwarder.
 */
uint32_t VPPForwarderInterface::getMemifConfiguration() {
  memif_create_params_t input_params = {0};

  int ret = memif_binary_api_get_next_memif_id(
      VPPForwarderInterface::memif_api_, &memif_id_);

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

  ret = memif_binary_api_create_memif(VPPForwarderInterface::memif_api_,
                                      &input_params, &output_params);

  if (ret < 0) {
    throw errors::RuntimeException(
        "Error creating memif interface in the local VPP forwarder.");
  }

  return output_params.sw_if_index;
}

void VPPForwarderInterface::consumerConnection() {
  hicn_consumer_input_params input = {0};
  hicn_consumer_output_params output;
  ip_address_t ip4_address;
  ip_address_t ip6_address;

  std::memset(&output, 0, sizeof(hicn_consumer_output_params));

  output.src4 = &ip4_address;
  output.src6 = &ip6_address;

  input.swif = sw_if_index_;

  int ret = hicn_binary_api_register_cons_app(VPPForwarderInterface::hicn_api_,
                                              &input, &output);

  if (ret < 0) {
    throw errors::RuntimeException(hicn_binary_api_get_error_string(ret));
  }

  inet_address_.family = AF_INET;
  inet_address_.prefix_len = output.src4->prefix_len;
  std::memcpy(inet_address_.buffer, output.src4->buffer, IPV6_ADDR_LEN);

  inet6_address_.family = AF_INET6;
  inet6_address_.prefix_len = output.src6->prefix_len;
  std::memcpy(inet6_address_.buffer, output.src6->buffer, IPV6_ADDR_LEN);
}

void VPPForwarderInterface::producerConnection() {
  // Producer connection will be set when we set the first route.
}

void VPPForwarderInterface::connect(bool is_consumer) {
  std::lock_guard<std::mutex> connection_lock(global_lock_);

  srand(time(NULL));
  int secret = rand() % (1 << 10);
  std::stringstream app_name;
  app_name << "Libtransport_" << secret;

  if (!VPPForwarderInterface::memif_api_) {
    VPPForwarderInterface::api_ = vpp_binary_api_init(app_name.str().c_str());
  }

  VPPForwarderInterface::memif_api_ =
      memif_binary_api_init(VPPForwarderInterface::api_);

  sw_if_index_ = getMemifConfiguration();

  VPPForwarderInterface::hicn_api_ =
      hicn_binary_api_init(VPPForwarderInterface::api_);
  if (is_consumer) {
    consumerConnection();
  }

  connector_.connect(memif_id_, 0);
}

void VPPForwarderInterface::registerRoute(Prefix &prefix) {
  auto &addr = prefix.toIpAddressStruct();

  // Same ip address for input and outurt params
  ip_address_t ip_address;

  if (face_id_ == uint32_t(~0)) {
    hicn_producer_input_params input;
    std::memset(&input, 0, sizeof(input));

    hicn_producer_output_params output;
    std::memset(&output, 0, sizeof(output));

    input.prefix = &ip_address;
    output.prod_addr = &ip_address;

    // Here we have to ask to the actual connector what is the
    // memif_id, since this function should be called after the
    // memif creation.
    input.swif = sw_if_index_;
    input.prefix->as_u64[0] = addr.as_u64[0];
    input.prefix->as_u64[1] = addr.as_u64[1];
    input.prefix->family = addr.family == AF_INET6 ? AF_INET6 : AF_INET;
    input.prefix->prefix_len = addr.prefix_len;
    input.cs_reserved = content_store_reserved_;

    int ret = hicn_binary_api_register_prod_app(
        VPPForwarderInterface::hicn_api_, &input, &output);

    if (ret < 0) {
      throw errors::RuntimeException(hicn_binary_api_get_error_string(ret));
    }

    if (addr.family == AF_INET6) {
      inet6_address_.prefix_len = output.prod_addr->prefix_len;
      inet6_address_.as_u64[0] = output.prod_addr->as_u64[0];
      inet6_address_.as_u64[1] = output.prod_addr->as_u64[1];
    } else {
      inet_address_.prefix_len = output.prod_addr->prefix_len;
      // The ipv4 is written in the last 4 bytes of the ipv6 address, so we need
      // to copy from the byte 12
      inet_address_.as_u64[0] = output.prod_addr->as_u64[0];
      inet_address_.as_u64[1] = output.prod_addr->as_u64[1];
    }

    face_id_ = output.face_id;
  } else {
    hicn_producer_set_route_params params;
    params.prefix = &ip_address;
    params.prefix->as_u64[0] = addr.as_u64[0];
    params.prefix->as_u64[1] = addr.as_u64[1];
    params.prefix->family = addr.family == AF_INET6 ? AF_INET6 : AF_INET;
    params.prefix->prefix_len = addr.prefix_len;
    params.face_id = face_id_;

    int ret = hicn_binary_api_register_route(VPPForwarderInterface::hicn_api_,
                                             &params);

    if (ret < 0) {
      throw errors::RuntimeException(hicn_binary_api_get_error_string(ret));
    }
  }
}

void VPPForwarderInterface::closeConnection() {
  if (sw_if_index_ != uint32_t(~0) && VPPForwarderInterface::memif_api_) {
    int ret = memif_binary_api_delete_memif(VPPForwarderInterface::memif_api_,
                                            sw_if_index_);

    if (ret < 0) {
      TRANSPORT_LOGE("Error deleting memif with sw idx %u.", sw_if_index_);
    }
  }

  if (VPPForwarderInterface::api_) {
    vpp_binary_api_destroy(VPPForwarderInterface::api_);
  }

  connector_.close();
}

}  // namespace core

}  // namespace transport

#endif