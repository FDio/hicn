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

#include <hicn/transport/interfaces/socket_consumer.h>
#include <protocols/errors.h>
#include <protocols/incremental_indexer_bytestream.h>
#include <protocols/transport_protocol.h>

namespace transport {
namespace protocol {

void IncrementalIndexer::onContentObject(core::Interest &interest,
                                         core::ContentObject &content_object,
                                         bool reassembly) {
  using namespace interface;

  DLOG_IF(INFO, VLOG_IS_ON(3))
      << "Received content " << content_object.getName();

  DCHECK(reassembly_);

  if (TRANSPORT_EXPECT_FALSE(content_object.isLast())) {
    final_suffix_ = content_object.getName().getSuffix();
  }

  auto ret = verifier_->verifyPackets(&content_object);

  switch (ret) {
    case auth::VerificationPolicy::ACCEPT: {
      if (reassembly) {
        reassembly_->reassemble(content_object);
      }
      break;
    }

    case auth::VerificationPolicy::UNKNOWN:
    case auth::VerificationPolicy::DROP: {
      transport_->onPacketDropped(
          interest, content_object,
          make_error_code(protocol_error::verification_failed));
      break;
    }

    case auth::VerificationPolicy::ABORT: {
      transport_->onContentReassembled(
          make_error_code(protocol_error::session_aborted));
      break;
    }
  }
}

}  // namespace protocol
}  // namespace transport
