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

#include <hicn/transport/core/packet.h>
#include <hicn/transport/portability/transport_portability.h>

#include <array>

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
TRANSPORT_ALWAYS_INLINE void setValueToJson(Json::Value &root, EnumType value) {
  root[JSONKey<EnumType>::key] = static_cast<uint8_t>(value);
}

template <typename EnumType>
TRANSPORT_ALWAYS_INLINE EnumType getValueFromJson(const Json::Value &root) {
  return static_cast<EnumType>(root[JSONKey<EnumType>::key].asUInt());
};

}  // namespace

JSONManifestEncoder::JSONManifestEncoder(Packet &packet) : packet_(packet) {}

JSONManifestEncoder::~JSONManifestEncoder() {}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &JSONManifestEncoder::encodeImpl() {
  Json::StreamWriterBuilder writer_builder;
  Json::StreamWriter *fast_writer = writer_builder.newStreamWriter();

  asio::streambuf strbuf;
  strbuf.prepare(1500);
  std::ostream stream(&strbuf);
  fast_writer->write(root_, &stream);

  const uint8_t *buffer = asio::buffer_cast<const uint8_t *>(strbuf.data());

  packet_.setPayload(buffer, strbuf.size());

  delete fast_writer;

  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &JSONManifestEncoder::clearImpl() {
  root_.clear();
  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setHashAlgorithmImpl(HashAlgorithm algorithm) {
  setValueToJson(root_, algorithm);
  return *this;
}

JSONManifestEncoder &JSONManifestEncoder::setManifestTypeImpl(
    ManifestType manifest_type) {
  setValueToJson(root_, manifest_type);
  return *this;
}

JSONManifestEncoder &JSONManifestEncoder::setNextSegmentCalculationStrategyImpl(
    NextSegmentCalculationStrategy strategy) {
  setValueToJson(root_, strategy);
  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setBaseNameImpl(const core::Name &base_name) {
  root_[JSONKey<core::Name>::key] = base_name.toString().c_str();
  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::addSuffixAndHashImpl(uint32_t suffix,
                                          const utils::CryptoHash &hash) {
  throw errors::NotImplementedException();
  //  Json::Value value(Json::arrayValue);
  //  value.append(Json::Value(suffix));
  //  value.append(Json::Value(Json::Value::UInt64 (hash)));
  //  root_[JSONKey<SuffixHashList>::key].append(value);

  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setIsFinalManifestImpl(bool is_last) {
  root_[JSONKey<bool>::final_manifest] = is_last;
  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setVersionImpl(ManifestVersion version) {
  setValueToJson(root_, version);
  return *this;
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setSuffixHashListImpl(
    const typename JSON::SuffixList &name_hash_list) {
  throw errors::NotImplementedException();
  //  for (auto &suffix : name_hash_list) {
  //    addSuffixAndHashImpl(suffix.first, suffix.second);
  //  }
  //
  //  return *this;
}

TRANSPORT_ALWAYS_INLINE std::size_t
JSONManifestEncoder::estimateSerializedLengthImpl(
    std::size_t number_of_entries) {
  Json::StreamWriterBuilder writer_builder;
  Json::StreamWriter *fast_writer = writer_builder.newStreamWriter();

  asio::streambuf strbuf;
  strbuf.prepare(1500);
  std::ostream stream(&strbuf);
  fast_writer->write(root_, &stream);

  return strbuf.size();
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &JSONManifestEncoder::updateImpl() {
  throw errors::NotImplementedException();
}

TRANSPORT_ALWAYS_INLINE JSONManifestEncoder &
JSONManifestEncoder::setFinalBlockNumberImpl(std::uint32_t final_block_number) {
  throw errors::NotImplementedException();
}

TRANSPORT_ALWAYS_INLINE std::size_t
JSONManifestEncoder::getManifestHeaderSizeImpl() {
  return 0;
}

JSONManifestDecoder::JSONManifestDecoder(Packet &packet) : packet_(packet) {}

JSONManifestDecoder::~JSONManifestDecoder() {}

TRANSPORT_ALWAYS_INLINE void JSONManifestDecoder::decodeImpl() {
  auto array = packet_.getPayload();
  auto payload = array.data();
  auto payload_size = array.length();

  Json::CharReaderBuilder reader_builder;
  Json::CharReader *reader = reader_builder.newCharReader();
  std::string errors;

  if (!reader->parse((char *)payload, (char *)payload + payload_size, &root_,
                     &errors)) {
    TRANSPORT_LOGE("Error parsing manifest!");
    TRANSPORT_LOGE("%s", errors.c_str());

    delete reader;

    throw errors::MalformedPacketException();
  }

  delete reader;
}

TRANSPORT_ALWAYS_INLINE JSONManifestDecoder &JSONManifestDecoder::clearImpl() {
  root_.clear();
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

TRANSPORT_ALWAYS_INLINE typename JSON::SuffixList
JSONManifestDecoder::getSuffixHashListImpl() {
  throw errors::NotImplementedException();
  //  SuffixHashList hash_list;
  //
  //  Json::Value &array = root_[JSONKey<SuffixHashList>::key];
  //
  //  for (Json::Value::ArrayIndex i = 0;
  //       i != array.size();
  //       i++) {
  //    hash_list[array[i][0].asUInt()] = array[i][1].asUInt64();
  //  }
  //
  //  return hash_list;
}

TRANSPORT_ALWAYS_INLINE core::Name JSONManifestDecoder::getBaseNameImpl()
    const {
  return core::Name(root_[JSONKey<core::Name>::key].asCString());
}

TRANSPORT_ALWAYS_INLINE bool JSONManifestDecoder::getIsFinalManifestImpl()
    const {
  return root_[JSONKey<bool>::final_manifest].asBool();
}

TRANSPORT_ALWAYS_INLINE ManifestVersion
JSONManifestDecoder::getVersionImpl() const {
  return getValueFromJson<ManifestVersion>(root_);
}

TRANSPORT_ALWAYS_INLINE uint32_t
JSONManifestDecoder::getFinalBlockNumberImpl() const {
  return 0;
}

}  // end namespace core

}  // end namespace transport
