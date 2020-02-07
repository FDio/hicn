/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <hicn/transport/protocols/errors.h>

namespace transport {
namespace protocol {

const std::error_category& protocol_category() {
  static protocol_category_impl instance;

  return instance;
}

const char* protocol_category_impl::name() const throw() {
  return "transport::protocol::error";
}

std::string protocol_category_impl::message(int ev) const {
  switch (static_cast<protocol_error>(ev)) {
    case protocol_error::success: {
      return "Success";
    }
    case protocol_error::signature_verification_failed: {
      return "Signature verification failed.";
    }
    case protocol_error::integrity_verification_failed: {
      return "Integrity verification failed";
    }
    case protocol_error::no_verifier_provided: {
      return "Transport cannot get any verifier for the given data.";
    }
    case protocol_error::io_error: {
      return "Conectivity error between transport and local forwarder";
    }
    case protocol_error::max_retransmissions_error: {
      return "Transport protocol reached max number of retransmissions allowed "
             "for the same interest.";
    }
    case protocol_error::session_aborted: {
      return "The session has been aborted by the application.";
    }
    default: { return "Unknown protocol error"; }
  }
}

}  // namespace protocol
}  // namespace transport