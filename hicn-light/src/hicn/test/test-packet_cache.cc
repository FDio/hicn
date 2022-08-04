/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <gtest/gtest.h>

#include <optional>
#include <random>
#include <hicn/test/test-utils.h>

extern "C" {
#define WITH_TESTS
#include <hicn/core/packet_cache.h>
}

static constexpr unsigned CS_SIZE = 100;
static constexpr unsigned CONN_ID = 0;
static constexpr unsigned CONN_ID_2 = 1;
static constexpr unsigned MSGBUF_ID = 0;
static constexpr unsigned MSGBUF_ID_2 = 1;
static constexpr unsigned MSGBUF_ID_3 = 2;
static constexpr unsigned FIVE_SECONDS = 5000;

static constexpr int N_OPS = 50000;

class PacketCacheTest : public ::testing::Test {
 protected:
  PacketCacheTest() {
    pkt_cache = pkt_cache_create(CS_SIZE);
    int rc = hicn_name_create_from_ip_address(IPV4_ANY, 0, &name);
    EXPECT_EQ(rc, 0);
    msgbuf_pool = msgbuf_pool_create();
    msgbuf = msgbuf_create(msgbuf_pool, CONN_ID, &name);
  }

  virtual ~PacketCacheTest() {
    msgbuf_pool_free(msgbuf_pool);
    pkt_cache_free(pkt_cache);
  }

  msgbuf_t *msgbuf_create(msgbuf_pool_t *msgbuf_pool, unsigned conn_id,
                          hicn_name_t *name,
                          std::optional<Ticks> lifetime = FIVE_SECONDS) {
    msgbuf_t *msgbuf;
    msgbuf_pool_get(msgbuf_pool, &msgbuf);

    msgbuf->connection_id = conn_id;
    msgbuf_set_name(msgbuf, name);

    hicn_packet_set_format(msgbuf_get_pkbuf(msgbuf),
                           HICN_PACKET_FORMAT_IPV6_TCP);
    hicn_packet_set_type(msgbuf_get_pkbuf(msgbuf), HICN_PACKET_TYPE_INTEREST);

    hicn_packet_buffer_t *pkbuf = msgbuf_get_pkbuf(msgbuf);
    hicn_packet_set_buffer(pkbuf, msgbuf->packet, MTU, 0);

    int rc = hicn_packet_init_header(msgbuf_get_pkbuf(msgbuf), 0);
    EXPECT_EQ(rc, 0);

    // Same as 'msgbuf_set_data_expiry_time',
    // it would write in the same field
    msgbuf_set_interest_lifetime(msgbuf, *lifetime);

    return msgbuf;
  }

  hicn_name_t get_name_from_prefix(const char *prefix_str) {
    hicn_ip_address_t prefix;
    inet_pton(AF_INET6, prefix_str, (struct in6_addr *)&prefix);

    hicn_name_t name;
    int rc = hicn_name_create_from_ip_address(prefix, 0, &name);
    EXPECT_EQ(rc, 0);

    return name;
  }

  pkt_cache_t *pkt_cache;
  pkt_cache_entry_t *entry = nullptr;
  msgbuf_pool_t *msgbuf_pool;
  hicn_name_t name;
  msgbuf_t *msgbuf;
};

TEST_F(PacketCacheTest, LowLevelOperations) {
  kh_pkt_cache_prefix_t *prefix_to_suffixes = kh_init_pkt_cache_prefix();
  const hicn_name_prefix_t *prefix = hicn_name_get_prefix(&name);
  _add_suffix(prefix_to_suffixes, prefix, 1, 11);
  _add_suffix(prefix_to_suffixes, prefix, 2, 22);

  unsigned id = _get_suffix(prefix_to_suffixes, prefix, 1);
  EXPECT_EQ(id, 11UL);

  id = _get_suffix(prefix_to_suffixes, prefix, 2);
  EXPECT_EQ(id, 22UL);

  id = _get_suffix(prefix_to_suffixes, prefix, 5);
  EXPECT_EQ(id, HICN_INVALID_SUFFIX);

  _add_suffix(prefix_to_suffixes, prefix, 5, 55);
  id = _get_suffix(prefix_to_suffixes, prefix, 5);
  EXPECT_EQ(id, 55UL);

  _remove_suffix(prefix_to_suffixes, prefix, 2);
  _add_suffix(prefix_to_suffixes, prefix, 2, 222);
  id = _get_suffix(prefix_to_suffixes, prefix, 2);
  EXPECT_EQ(id, 222UL);

  _prefix_map_free(prefix_to_suffixes);
}

TEST_F(PacketCacheTest, CreatePacketCache) {
  // Check packet cache allocation
  EXPECT_NE(pkt_cache, nullptr);
  pit_t *pit = pkt_cache_get_pit(pkt_cache);
  ASSERT_NE(pit, nullptr);
  cs_t *cs = pkt_cache_get_cs(pkt_cache);
  ASSERT_NE(cs, nullptr);

  // Check sizes
  ASSERT_EQ(pkt_cache_get_size(pkt_cache), 0u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 0u);
}

TEST_F(PacketCacheTest, AddPacketCacheEntry) {
  // Add entry to the packet cache
  entry = pkt_cache_allocate(pkt_cache);
  EXPECT_NE(entry, nullptr);
  entry->name = name;
  ASSERT_EQ(pkt_cache_get_size(pkt_cache), 1u);
  pkt_cache_add_to_index(pkt_cache, entry);

  // Get entry by name
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_lookup(pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id,
                   true);
  EXPECT_NE(lookup_result, PKT_CACHE_LU_NONE);
}

TEST_F(PacketCacheTest, GetCS) {
  cs_t *cs = pkt_cache_get_cs(pkt_cache);
  ASSERT_NE(cs, nullptr);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  EXPECT_EQ(cs->type, CS_TYPE_LRU);
  EXPECT_EQ(cs->num_entries, 0);
  EXPECT_EQ(cs->lru.head, (off_t)INVALID_ENTRY_ID);
  EXPECT_EQ(cs->lru.tail, (off_t)INVALID_ENTRY_ID);
}

TEST_F(PacketCacheTest, GetPIT) {
  pit_t *pit = pkt_cache_get_pit(pkt_cache);
  ASSERT_NE(pit, nullptr);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 0u);
}

TEST_F(PacketCacheTest, LookupEmpty) {
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *entry = pkt_cache_lookup(pkt_cache, &name, msgbuf_pool,
                                              &lookup_result, &entry_id, true);

  EXPECT_EQ(lookup_result, PKT_CACHE_LU_NONE);
  EXPECT_EQ(entry, nullptr);
}

TEST_F(PacketCacheTest, AddEntryAndLookup) {
  // Add entry to the packet cache
  entry = pkt_cache_allocate(pkt_cache);
  entry->name = name;
  entry->entry_type = PKT_CACHE_PIT_TYPE;
  ASSERT_NE(entry, nullptr);
  pkt_cache_add_to_index(pkt_cache, entry);

  // Perform lookup
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id, true);

  EXPECT_TRUE(lookup_result == PKT_CACHE_LU_INTEREST_NOT_EXPIRED ||
              lookup_result == PKT_CACHE_LU_INTEREST_EXPIRED);
  EXPECT_NE(lu_entry, nullptr);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, AddToPIT) {
  // Check if entry properly created
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf, &name);
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->entry_type, PKT_CACHE_PIT_TYPE);
  EXPECT_TRUE(pit_entry_ingress_contains(&entry->u.pit_entry, CONN_ID));
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 1u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, AddToCS) {
  // Check if entry properly created
  pkt_cache_entry_t *entry =
      pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, MSGBUF_ID);
  cs_entry_t *cs_entry = &entry->u.cs_entry;
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->entry_type, PKT_CACHE_CS_TYPE);
  EXPECT_EQ(cs_entry->msgbuf_id, MSGBUF_ID);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 0u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 1u);

  // Check if CS properly updated
  cs_t *cs = pkt_cache_get_cs(pkt_cache);
  off_t entry_id = pkt_cache_get_entry_id(pkt_cache, entry);
  EXPECT_EQ(cs->num_entries, 1);
  EXPECT_EQ(cs->lru.head, entry_id);
  EXPECT_EQ(cs->lru.tail, entry_id);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_DATA_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, PitToCS) {
  // Prepare PIT entry
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf, &name);
  off_t entry_id = pkt_cache_get_entry_id(pkt_cache, entry);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 1u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  // Check if entry properly updated
  pkt_cache_pit_to_cs(pkt_cache, entry, msgbuf_pool, msgbuf, MSGBUF_ID,
                      entry_id);
  cs_entry_t *cs_entry = &entry->u.cs_entry;
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->entry_type, PKT_CACHE_CS_TYPE);
  EXPECT_EQ(cs_entry->msgbuf_id, MSGBUF_ID);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 0u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 1u);

  // Check if CS properly updated
  cs_t *cs = pkt_cache_get_cs(pkt_cache);
  entry_id = pkt_cache_get_entry_id(pkt_cache, entry);
  EXPECT_EQ(cs->num_entries, 1);
  EXPECT_EQ(cs->lru.head, entry_id);
  EXPECT_EQ(cs->lru.tail, entry_id);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_DATA_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, CsToPIT) {
  // Prepare CS entry
  pkt_cache_entry_t *entry =
      pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, MSGBUF_ID);
  off_t entry_id = pkt_cache_get_entry_id(pkt_cache, entry);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 0u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 1u);

  // Check if entry properly updated
  pkt_cache_cs_to_pit(pkt_cache, entry, msgbuf_pool, msgbuf, MSGBUF_ID,
                      entry_id);
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->entry_type, PKT_CACHE_PIT_TYPE);
  EXPECT_TRUE(pit_entry_ingress_contains(&entry->u.pit_entry, CONN_ID));
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 1u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, UpdateInPIT) {
  // Prepare PIT entry
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf, &name);
  off_t entry_id = pkt_cache_get_entry_id(pkt_cache, entry);

  hicn_name_t new_name;
  int rc = hicn_name_create_from_ip_address(IPV4_LOOPBACK, 0, &new_name);
  EXPECT_EQ(rc, 0);
  msgbuf_t *new_msgbuf = msgbuf_create(msgbuf_pool, CONN_ID_2, &new_name);

  // Check if entry properly updated
  pkt_cache_update_pit(pkt_cache, entry, new_msgbuf);
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->entry_type, PKT_CACHE_PIT_TYPE);
  EXPECT_EQ(pit_entry_ingress_contains(&entry->u.pit_entry, CONN_ID_2), true);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 1u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, UpdateInCS) {
  // Prepare CS entry
  pkt_cache_entry_t *entry =
      pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, MSGBUF_ID);
  off_t entry_id = pkt_cache_get_entry_id(pkt_cache, entry);

  hicn_name_t new_name;
  int rc = hicn_name_create_from_ip_address(IPV4_LOOPBACK, 0, &new_name);
  EXPECT_EQ(rc, 0);
  msgbuf_t *new_msgbuf = msgbuf_create(msgbuf_pool, CONN_ID_2, &new_name);

  // Check if entry properly updated
  pkt_cache_update_cs(pkt_cache, msgbuf_pool, entry, new_msgbuf, MSGBUF_ID_2);
  cs_entry_t *cs_entry = &entry->u.cs_entry;
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->entry_type, PKT_CACHE_CS_TYPE);
  EXPECT_EQ(cs_entry->msgbuf_id, MSGBUF_ID_2);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 0u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 1u);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_DATA_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, RemoveFromPIT) {
  // Prepare PIT entry
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf, &name);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 1u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  pkt_cache_pit_remove_entry(pkt_cache, entry);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 0u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_NONE);
  EXPECT_EQ(lu_entry, nullptr);
}

TEST_F(PacketCacheTest, RemoveFromCS) {
  // Prepare CS entry
  pkt_cache_entry_t *entry =
      pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, MSGBUF_ID);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 0u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 1u);

  pkt_cache_cs_remove_entry(pkt_cache, entry, msgbuf_pool, false);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 0u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  // Check if CS properly updated
  cs_t *cs = pkt_cache_get_cs(pkt_cache);
  EXPECT_EQ(cs->num_entries, 0);
  EXPECT_EQ(cs->lru.head, (off_t)INVALID_ENTRY_ID);
  EXPECT_EQ(cs->lru.tail, (off_t)INVALID_ENTRY_ID);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_NONE);
  EXPECT_EQ(lu_entry, nullptr);
}

TEST_F(PacketCacheTest, AddTwoEntriesToCS) {
  // Prepare another msgbuf
  hicn_name_t new_name;
  int rc = hicn_name_create_from_ip_address(IPV4_LOOPBACK, 0, &new_name);
  EXPECT_EQ(rc, 0);
  msgbuf_t *new_msgbuf = msgbuf_create(msgbuf_pool, CONN_ID_2, &new_name);

  pkt_cache_entry_t *entry_1 =
      pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, MSGBUF_ID);
  pkt_cache_entry_t *entry_2 =
      pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, new_msgbuf, MSGBUF_ID_2);
  off_t entry_id_1 = pkt_cache_get_entry_id(pkt_cache, entry_1);
  off_t entry_id_2 = pkt_cache_get_entry_id(pkt_cache, entry_2);

  // Check if the CS and LRU cache are properly updated
  cs_t *cs = pkt_cache_get_cs(pkt_cache);
  EXPECT_EQ(cs->num_entries, 2);
  EXPECT_EQ(cs->lru.head, entry_id_2);
  EXPECT_EQ(cs->lru.tail, entry_id_1);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 0u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 2u);
}

TEST_F(PacketCacheTest, AggregateInPIT) {
  // Prepare another msgbuf
  hicn_name_t new_name;
  int rc = hicn_name_create_from_ip_address(IPV4_LOOPBACK, 0, &new_name);
  EXPECT_EQ(rc, 0);
  msgbuf_t *new_msgbuf = msgbuf_create(msgbuf_pool, CONN_ID_2, &new_name);

  // Check if entry properly created (use sleep to get an updated ts)
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf, &name);
  Ticks old_lifetime = entry->expire_ts;
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  bool is_aggregated =
      pkt_cache_try_aggregate_in_pit(pkt_cache, entry, new_msgbuf, &name);
  Ticks new_lifetime = entry->expire_ts;

  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->entry_type, PKT_CACHE_PIT_TYPE);
  EXPECT_GT(new_lifetime, old_lifetime);
  ASSERT_EQ(is_aggregated, true);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, RetransmissionInPIT) {
  // Prepare another msgbuf (using same connection ID)
  hicn_name_t new_name;
  int rc = hicn_name_create_from_ip_address(IPV4_LOOPBACK, 0, &new_name);
  EXPECT_EQ(rc, 0);
  msgbuf_t *new_msgbuf = msgbuf_create(msgbuf_pool, CONN_ID, &new_name);

  // Check if entry properly created (use sleep to get an updated ts)
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf, &name);
  Ticks old_lifetime = entry->expire_ts;
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  bool is_aggregated =
      pkt_cache_try_aggregate_in_pit(pkt_cache, entry, new_msgbuf, &name);
  Ticks new_lifetime = entry->expire_ts;

  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->entry_type, PKT_CACHE_PIT_TYPE);
  EXPECT_GT(new_lifetime, old_lifetime);
  ASSERT_EQ(is_aggregated, false);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, LookupExpiredInterest) {
  // Prepare msgbuf with 0 as interest lifetime
  msgbuf_t *msgbuf = msgbuf_create(msgbuf_pool, CONN_ID, &name, 0);

  // Add to PIT
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf, &name);
  ASSERT_NE(entry, nullptr);

  // Wait to make the interest expire
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_lookup(pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id,
                   true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_EXPIRED);
}

TEST_F(PacketCacheTest, LookupExpiredData) {
  // Prepare msgbuf with 0 as data expiry time
  msgbuf_t *msgbuf = msgbuf_create(msgbuf_pool, CONN_ID, &name, 0);

  // Add to CS
  pkt_cache_entry_t *entry =
      pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, MSGBUF_ID);
  ASSERT_NE(entry, nullptr);

  // Wait to make the interest expire
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_lookup(pkt_cache, &name, msgbuf_pool, &lookup_result, &entry_id,
                   true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_DATA_EXPIRED);
}

TEST_F(PacketCacheTest, GetStaleEntries) {
  // Add to CS a msgbuf with immediate expiration (i.e. stale)
  msgbuf_t *msgbuf = msgbuf_create(msgbuf_pool, CONN_ID, &name, 0);
  pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, MSGBUF_ID);

  // Add to CS another msgbuf with immediate expiration (i.e. stale)
  hicn_name_t name_2;
  int rc = hicn_name_create_from_ip_address(IPV4_LOOPBACK, 0, &name_2);
  EXPECT_EQ(rc, 0);
  msgbuf_t *msgbuf_2 = msgbuf_create(msgbuf_pool, CONN_ID, &name_2, 0);
  pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf_2, MSGBUF_ID_2);

  // Add to CS a msgbuf with 5-seconds expiration (i.e. not stale)
  hicn_name_t name_3;
  rc = hicn_name_create_from_ip_address(IPV6_LOOPBACK, 0, &name_3);
  EXPECT_EQ(rc, 0);
  msgbuf_t *msgbuf_3 =
      msgbuf_create(msgbuf_pool, CONN_ID, &name_3, FIVE_SECONDS);
  pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf_3, MSGBUF_ID_3);

  size_t num_stale_entries = pkt_cache_get_num_cs_stale_entries(pkt_cache);
  EXPECT_EQ(num_stale_entries, 2u);
}

TEST_F(PacketCacheTest, GetMultipleStaleEntries) {
  hicn_ip_address_t addr;
  char name[30];
  const int NUM_STALES = 10;
  int rc;

  // Add to CS multiple msgbufs with immediate expiration (i.e. 0 seconds),
  // resulting in stale entries
  for (int i = 0; i < NUM_STALES; i++) {
    snprintf(name, 30, "b001::%d", i);
    inet_pton(AF_INET6, name, (struct in6_addr *)&addr);
    hicn_name_t name;
    rc = hicn_name_create_from_ip_address(addr, 0, &name);
    EXPECT_EQ(rc, 0);
    msgbuf_t *msgbuf = msgbuf_create(msgbuf_pool, i, &name, 0);

    pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, i);
  }

  // Add to CS multiple msgbufs with 5-seconds expiration,
  // resulting in non-stale entries
  for (int i = NUM_STALES; i < 15; i++) {
    snprintf(name, 30, "b001::%d", i);
    inet_pton(AF_INET6, name, (struct in6_addr *)&addr);
    hicn_name_t name;
    rc = hicn_name_create_from_ip_address(addr, 0, &name);
    EXPECT_EQ(rc, 0);
    msgbuf_t *msgbuf = msgbuf_create(msgbuf_pool, i, &name, FIVE_SECONDS);

    pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, i);
  }

  size_t num_stale_entries = pkt_cache_get_num_cs_stale_entries(pkt_cache);
  EXPECT_EQ(num_stale_entries, (size_t)NUM_STALES);
}

TEST_F(PacketCacheTest, PerformanceDoubleLookup) {
  hicn_name_t tmp = get_name_from_prefix("b001::0");

  auto elapsed_time_double = get_execution_time([&]() {
    kh_pkt_cache_prefix_t *prefix_to_suffixes = kh_init_pkt_cache_prefix();

    // Add to hash table
    for (int seq = 0; seq < N_OPS; seq++) {
      hicn_name_set_suffix(&tmp, seq);
      _add_suffix(prefix_to_suffixes, hicn_name_get_prefix(&tmp),
                  hicn_name_get_suffix(&tmp), hicn_name_get_suffix(&tmp));
    }

    // Read from hash table
    for (int seq = 0; seq < N_OPS; seq++) {
      hicn_name_set_suffix(&tmp, seq);
      _get_suffix(prefix_to_suffixes, hicn_name_get_prefix(&tmp), seq);
    }

    _prefix_map_free(prefix_to_suffixes);
  });
  std::cout << "Double lookup: " << elapsed_time_double << " ms\n";
}

TEST_F(PacketCacheTest, PerformanceCachedLookup) {
  hicn_name_t tmp = get_name_from_prefix("b001::0");

  auto elapsed_time_single = get_execution_time([&]() {
    kh_pkt_cache_prefix_t *prefix_to_suffixes = kh_init_pkt_cache_prefix();
    kh_pkt_cache_suffix_t *suffixes =
        _get_suffixes(prefix_to_suffixes, hicn_name_get_prefix(&tmp), true);

    // Add to hash table
    for (int seq = 0; seq < N_OPS; seq++) {
      hicn_name_set_suffix(&tmp, seq);
      __add_suffix(suffixes, hicn_name_get_suffix(&tmp),
                   hicn_name_get_suffix(&tmp));
    }

    // Read from hash table
    for (int seq = 0; seq < N_OPS; seq++) {
      hicn_name_set_suffix(&tmp, seq);
      __get_suffix(suffixes, hicn_name_get_suffix(&tmp));
    }

    _prefix_map_free(prefix_to_suffixes);
  });
  std::cout << "Cached lookup: " << elapsed_time_single << " ms\n";
}

TEST_F(PacketCacheTest, PerformanceCachedLookupRandom) {
  hicn_name_t tmp = get_name_from_prefix("b001::0");

  // Prepare random sequence numbers
  std::random_device rd;
  std::mt19937 gen(rd());
  uint32_t seqs[N_OPS];
  for (int seq = 0; seq < N_OPS; seq++) seqs[seq] = seq;
  std::shuffle(std::begin(seqs), std::end(seqs), gen);

  auto elapsed_time_single_rand = get_execution_time([&]() {
    kh_pkt_cache_prefix_t *prefix_to_suffixes = kh_init_pkt_cache_prefix();
    kh_pkt_cache_suffix_t *suffixes =
        _get_suffixes(prefix_to_suffixes, hicn_name_get_prefix(&tmp), true);

    // Add to hash table
    for (int seq = 0; seq < N_OPS; seq++) {
      hicn_name_set_suffix(&tmp, seqs[seq]);
      __add_suffix(suffixes, hicn_name_get_suffix(&tmp),
                   hicn_name_get_suffix(&tmp));
    }

    // Read from hash table
    for (int seq = 0; seq < N_OPS; seq++) {
      hicn_name_set_suffix(&tmp, seqs[seq]);
      __get_suffix(suffixes, hicn_name_get_suffix(&tmp));
    }

    _prefix_map_free(prefix_to_suffixes);
  });
  std::cout << "Cached lookup (rand): " << elapsed_time_single_rand << " ms\n";
}

TEST_F(PacketCacheTest, Clear) {
  hicn_name_t tmp_name1, tmp_name2;
  cs_t *cs = pkt_cache_get_cs(pkt_cache);

  // Create name and add to msgbuf pool
  hicn_name_copy(&tmp_name1, &name);
  hicn_name_set_suffix(&tmp_name1, 1);
  msgbuf_t *tmp_msgbuf1 = msgbuf_create(msgbuf_pool, CONN_ID_2, &tmp_name1);

  // Create (another) name and add to msgbuf pool
  hicn_name_copy(&tmp_name2, &name);
  hicn_name_set_suffix(&tmp_name2, 2);
  msgbuf_t *tmp_msgbuf2 = msgbuf_create(msgbuf_pool, CONN_ID_2, &tmp_name2);

  // Add to packet cache (2 entries in the CS, 1 in the PIT)
  pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, MSGBUF_ID);
  pkt_cache_add_to_pit(pkt_cache, tmp_msgbuf1, &tmp_name1);
  pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, tmp_msgbuf2, MSGBUF_ID_2);

  // Check stats (before clearing the packet cache)
  ASSERT_EQ(pkt_cache_get_size(pkt_cache), 3u);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 1u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 2u);
  ASSERT_EQ(cs->num_entries, 2);
  ASSERT_EQ(cs->stats.lru.countAdds, 2u);

  // Clear packet cache (i.e. remove content packets from packet cache):
  // PIT entry should still be there while CS entries are cleared
  pkt_cache_cs_clear(pkt_cache);
  cs = pkt_cache_get_cs(pkt_cache);

  // Check stats (after clearing the packet cache)
  ASSERT_EQ(pkt_cache_get_size(pkt_cache), 1u);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 1u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);
  ASSERT_EQ(cs->num_entries, 0);
  ASSERT_EQ(cs->stats.lru.countAdds, 0u);
}
