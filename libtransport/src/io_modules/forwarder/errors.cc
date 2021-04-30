/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#include <io_modules/forwarder/errors.h>

namespace transport {
namespace core {

const std::error_category& forwarder_category() {
  static forwarder_category_impl instance;

  return instance;
}

const char* forwarder_category_impl::name() const throw() {
  return "proxy::connector::error";
}

std::string forwarder_category_impl::message(int ev) const {
  switch (static_cast<forwarder_error>(ev)) {
    case forwarder_error::success: {
      return "Success";
    }
    case forwarder_error::disconnected: {
      return "Connector is disconnected";
    }
    case forwarder_error::receive_failed: {
      return "Packet reception failed";
    }
    case forwarder_error::send_failed: {
      return "Packet send failed";
    }
    case forwarder_error::memory_allocation_error: {
      return "Impossible to allocate memory for packet pool";
    }
    case forwarder_error::invalid_connector_type: {
      return "Invalid type specified for connector.";
    }
    case forwarder_error::invalid_connector: {
      return "Created connector was invalid.";
    }
    case forwarder_error::interest_cache_miss: {
      return "interest cache miss.";
    }
    default: {
      return "Unknown connector error";
    }
  }
}
}  // namespace core
}  // namespace transport
