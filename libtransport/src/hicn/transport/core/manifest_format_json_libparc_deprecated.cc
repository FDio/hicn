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

#include <hicn/transport/core/manifest_format_json_libparc_deprecated.h>
#include <hicn/transport/core/packet.h>
#include <hicn/transport/errors/errors.h>
#include <hicn/transport/portability/transport_portability.h>

extern "C" {
#include <parc/algol/parc_Memory.h>
}

namespace transport {

namespace core {

namespace {

template <typename T>
TRANSPORT_ALWAYS_INLINE void checkPointer(T *pointer) {
  if (pointer == nullptr) {
    throw errors::NullPointerException();
  }
}

template <typename EnumType>
TRANSPORT_ALWAYS_INLINE void setValueToJson(PARCJSON *root, EnumType value) {
  parcJSON_AddInteger(root, JSONKey<EnumType>::key,
                      static_cast<int64_t>(value));
}

template <typename EnumType>
TRANSPORT_ALWAYS_INLINE EnumType getValueFromJson(PARCJSON *root) {
  checkPointer(root);

  PARCJSONValue *value = parcJSON_GetValueByName(root, JSONKey<EnumType>::key);

  EnumType ret = static_cast<EnumType>(parcJSONValue_GetInteger(value));
  // parcJSONValue_Release(&value);

  return ret;
};

}  // namespace

JSONManifestEncoder::JSONManifestEncoder() : root_(parcJSON_Create()) {
  parcJSON_Acquire(root_);
}

JSONManifestEncoder::~JSONManifestEncoder() {
  if (root_) {
    parcJSON_Release(&root_);
  }
}

TRANSPORT_ALWAYS_INLINE SONManifestEncoder &JSONManifestEncoder::encodeImpl(
    Packet &packet) {
  char *json_string = parcJSON_ToString(root_);
  packet.setPayload(reinterpret_cast<uint8_t *>(json_string),
                    std::strlen(json_string));
  parcMemory_Deallocate(&json_string);

  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &JSONManifestEncoder::clearImpl() {
  if (root_) {
    parcJSON_Release(&root_);
  }

  root_ = parcJSON_Create();

  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setHashAlgorithmImpl(HashAlgorithm algorithm) {
  setValueToJson(root_, algorithm);
  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setManifestTypeImpl(ManifestType manifest_type) {
  setValueToJson(root_, manifest_type);
  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setNextSegmentCalculationStrategyImpl(
    NextSegmentCalculationStrategy strategy) {
  setValueToJson(root_, strategy);
  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setBaseNameImpl(const core::Name &base_name) {
  parcJSON_AddString(root_, JSONKey<core::Name>::key,
                     base_name.toString().c_str());
  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::addSuffixAndHashImpl(uint32_t suffix,
                                          utils::CryptoHash &hash) {
  throw errors::NotImplementedException();
  //  PARCJSONValue *value = parcJSON_GetValueByName(root_,
  //                                                 JSONKey<SuffixHashList>::key);
  //
  //  // Create the pair to store in the array.
  //  // It will be segment number + Hash of the segment
  //  PARCJSONArray * pair = parcJSONArray_Create();
  //
  //  PARCJSONValue *v = parcJSONValue_CreateFromInteger(suffix);
  //  parcJSONArray_AddValue(pair, v);
  //  parcJSONValue_Release(&v);
  //
  //  v = parcJSONValue_CreateFromInteger(hash);
  //  parcJSONArray_AddValue(pair, v);
  //  parcJSONValue_Release(&v);
  //
  //  if (value == nullptr /* || !parcJSONValue_IsArray(value) */) {
  //    // Create the array
  //    PARCJSONArray *array = parcJSONArray_Create();
  //    parcJSON_AddArray(root_,
  //                      JSONKey<SuffixHashList>::key,
  //                      array);
  //    parcJSONArray_Release(&array);
  //
  //    value = parcJSON_GetValueByName(root_, JSONKey<SuffixHashList>::key);
  //  }
  //
  //  v = parcJSONValue_CreateFromJSONArray(pair);
  //  parcJSONArray_AddValue(parcJSONValue_GetArray(value), v);
  //  parcJSONValue_Release(&v);
  //
  //  parcJSONArray_Release(&pair);
  //  // parcJSONValue_Release(&value);

  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setIsFinalManifestImpl(bool is_last) {
  parcJSON_AddBoolean(root_, JSONKey<bool>::final_manifest, is_last);

  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setSuffixHashListImpl(
    const SuffixHashList &name_hash_list) {
  for (auto &suffix : name_hash_list) {
    addSuffixAndHashImpl(suffix.first, suffix.second);
  }

  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestDecoder::JSONManifestDecoder()
    : root_(nullptr) {}

TRANSPORT_ALWAYS_INLINE JSONManifestDecoder::~JSONManifestDecoder() {
  if (root_) {
    parcJSON_Release(&root_);
  }
}

TRANSPORT_ALWAYS_INLINE void JSONManifestDecoder::decodeImpl(
    const uint8_t *payload, std::size_t payload_size) {
  PARCBuffer *b = parcBuffer_Wrap(const_cast<uint8_t *>(payload), payload_size,
                                  0, payload_size);
  clearImpl();

  root_ = parcJSON_ParseBuffer(b);
  parcBuffer_Release(&b);

  char *str = parcJSON_ToString(root_);
}

TRANSPORT_ALWAYS_INLINE JSONManifestDecoder &JSONManifestDecoder::clearImpl() {
  if (root_) {
    parcJSON_Release(&root_);
  }

  return *this;
}

TRANSPORT_ALWAYS_INLINE ManifestType
JSONManifestDecoder::getManifestTypeImpl() const {
  return getValueFromJson<ManifestType>(root_);
}

TRANSPORT_ALWAYS_INLINE HashAlgorithm
JSONManifestDecoder::getHashAlgorithmImpl() const {
  return getValueFromJson<HashAlgorithm>(root_);
}

TRANSPORT_ALWAYS_INLINE NextSegmentCalculationStrategy
JSONManifestDecoder::getNextSegmentCalculationStrategyImpl() const {
  return getValueFromJson<NextSegmentCalculationStrategy>(root_);
}

TRANSPORT_ALWAYS_INLINE SuffixHashList
JSONManifestDecoder::getSuffixHashListImpl() {
  throw errors::NotImplementedException();
  //  SuffixHashList hash_list;
  //
  //  char * str = parcJSON_ToString(root_);
  //
  //  PARCJSONValue *value = parcJSON_GetValueByName(root_,
  //                                                 JSONKey<SuffixHashList>::key);
  //
  //  if (value == nullptr || !parcJSONValue_IsArray(value)) {
  //    throw errors::RuntimeException("Manifest does not contain suffix-hash
  //    list");
  //  }
  //
  //  PARCJSONArray *array = parcJSONValue_GetArray(value);
  //  std::size_t array_size = parcJSONArray_GetLength(array);
  //
  //  for (std::size_t i = 0; i < array_size; i++) {
  //    PARCJSONValue *v = parcJSONArray_GetValue(array, i);
  //    checkPointer(v);
  //    PARCJSONArray *a = parcJSONValue_GetArray(v);
  //    PARCJSONValue *_suffix = parcJSONArray_GetValue(a, 0);
  //    PARCJSONValue *_hash = parcJSONArray_GetValue(a, 1);
  //
  //    uint32_t value1 =
  //    static_cast<uint32_t>(parcJSONValue_GetInteger(_suffix)); uint64_t
  //    value2 = static_cast<uint64_t>(parcJSONValue_GetInteger(_hash));
  //
  //    hash_list[static_cast<uint32_t>(parcJSONValue_GetInteger(_suffix))] =
  //        static_cast<uint64_t>(parcJSONValue_GetInteger(_hash));
  //
  ////    parcJSONValue_Release(&_hash);
  ////    parcJSONValue_Release(&_suffix);
  ////    parcJSONArray_Release(&a);
  ////    parcJSONValue_Release(&v);
  //  }
  //
  ////  parcJSONArray_Release(&array);
  ////  parcJSONValue_Release(&value);
  //
  //  char * str2 = parcJSON_ToString(root_);
  //
  //  return hash_list;
}

TRANSPORT_ALWAYS_INLINE core::Name JSONManifestDecoder::getBaseNameImpl()
    const {
  checkPointer(root_);
  PARCJSONValue *value =
      parcJSON_GetValueByName(root_, JSONKey<core::Name>::key);

  PARCBuffer *b = parcJSONValue_GetString(value);
  char *string = parcBuffer_ToString(b);

  core::Name ret(string);

  // parcJSONValue_Release(&value);
  parcMemory_Deallocate(&string);

  return ret;
}

TRANSPORT_ALWAYS_INLINE bool JSONManifestDecoder::getIsFinalManifestImpl() {
  checkPointer(root_);
  PARCJSONValue *value =
      parcJSON_GetValueByName(root_, JSONKey<bool>::final_manifest);

  bool ret = parcJSONValue_GetBoolean(value);

  // parcJSONValue_Release(&value);

  return ret;
}

TRANSPORT_ALWAYS_INLINE std::size_t
JSONManifestDecoder::estimateSerializedLengthImpl(
    std::size_t number_of_entries) {
  return 0;
}

}  // end namespace core

}  // end namespace transport