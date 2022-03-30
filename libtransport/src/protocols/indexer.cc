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

#include <implementation/socket_consumer.h>
#include <protocols/errors.h>
#include <protocols/indexer.h>

namespace transport {
namespace protocol {

using namespace interface;

const constexpr uint32_t Indexer::invalid_index;

Indexer::Indexer(implementation::ConsumerSocket *socket,
                 TransportProtocol *transport)
    : socket_(socket), transport_(transport) {
  setVerifier();
}

void Indexer::setVerifier() {
  if (socket_) {
    socket_->getSocketOption(GeneralTransportOptions::VERIFIER, verifier_);
  }
}

void Indexer::applyPolicy(core::Interest &interest,
                          core::ContentObject &content_object, bool reassembly,
                          auth::VerificationPolicy policy) const {
  DCHECK(reassembly_ != nullptr);

  switch (policy) {
    case auth::VerificationPolicy::ACCEPT: {
      if (reassembly) {
        reassembly_->reassemble(content_object);
      }
      break;
    }
    case auth::VerificationPolicy::UNKNOWN:
      if (reassembly && reassembly_->reassembleUnverified()) {
        reassembly_->reassemble(content_object);
      }
      break;
    case auth::VerificationPolicy::DROP:
      transport_->onPacketDropped(
          interest, content_object,
          make_error_code(protocol_error::verification_failed));
      break;
    case auth::VerificationPolicy::ABORT: {
      transport_->onContentReassembled(
          make_error_code(protocol_error::session_aborted));
      break;
    }
  }
}

}  // end namespace protocol
}  // end namespace transport
