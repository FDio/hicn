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

#include <hicn/transport/protocols/incremental_indexer.h>

#include <hicn/transport/interfaces/socket_consumer.h>

namespace transport {
namespace protocol {

void IncrementalIndexer::onContentObject(
    core::Interest::Ptr &&interest, core::ContentObject::Ptr &&content_object) {
  using namespace interface;

  if (TRANSPORT_EXPECT_FALSE(content_object->testRst())) {
    final_suffix_ = content_object->getName().getSuffix();
  }

  auto ret = verification_manager_->onPacketToVerify(*content_object);

  switch (ret) {
    case VerificationPolicy::ACCEPT_PACKET: {
      reassembly_->reassemble(std::move(content_object));
      break;
    }
    case VerificationPolicy::DROP_PACKET: {
      transport_protocol_->onPacketDropped(std::move(interest),
                                           std::move(content_object));
      break;
    }
    case VerificationPolicy::ABORT_SESSION: {
      transport_protocol_->onContentReassembled(
          make_error_code(protocol_error::session_aborted));
      break;
    }
  }
}

}  // namespace protocol
}  // namespace transport