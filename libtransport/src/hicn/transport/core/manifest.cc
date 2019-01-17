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

#include <hicn/transport/core/manifest.h>

namespace transport {

namespace core {

std::string ManifestEncoding::manifest_type = std::string("manifest_type");

std::map<ManifestType, std::string> ManifestEncoding::manifest_types = {
    {FINAL_CHUNK_NUMBER, "FinalChunkNumber"}, {NAME_LIST, "NameList"}};

std::string ManifestEncoding::final_chunk_number =
    std::string("final_chunk_number");
std::string ManifestEncoding::content_name = std::string("content_name");

}  // end namespace core

}  // end namespace transport