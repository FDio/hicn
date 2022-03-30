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

#include <gtest/gtest.h>

#include <thread>
#include <optional>

extern "C" {
#define WITH_TESTS
#include <hicn/core/packet_cache.h>
}

const unsigned CS_SIZE = 100;
const unsigned CONN_ID = 0;
const unsigned CONN_ID_2 = 1;
const unsigned MSGBUF_ID = 0;
const unsigned MSGBUF_ID_2 = 1;
const unsigned MSGBUF_ID_3 = 2;
const unsigned FIVE_SECONDS = 5000;
const unsigned IPV4_LEN = 32;
const unsigned IPV6_LEN = 128;

class PacketCacheTest : public ::testing::Test {
 protected:
  PacketCacheTest() {
    pkt_cache = pkt_cache_create(CS_SIZE);
    name = (Name *)malloc(sizeof(Name));
    name_CreateFromAddress(name, AF_INET, IPV4_ANY, IPV4_LEN);
    msgbuf_pool = msgbuf_pool_create();
  }
  virtual ~PacketCacheTest() {
    pkt_cache_free(pkt_cache);
    msgbuf_pool_free(msgbuf_pool);
  }

  pkt_cache_t *pkt_cache;
  pkt_cache_entry_t *entry = nullptr;
  msgbuf_pool_t *msgbuf_pool;
  Name *name;
};

msgbuf_t *msgbuf_factory(msgbuf_pool_t *msgbuf_pool, unsigned conn_id,
                         Name *name,
                         std::optional<Ticks> lifetime = FIVE_SECONDS) {
  msgbuf_t *msgbuf;
  msgbuf_pool_get(msgbuf_pool, &msgbuf);

  msgbuf->connection_id = conn_id;
  name_Copy(name, msgbuf_get_name(msgbuf));
  hicn_packet_init_header(HF_INET6_TCP,
                          (hicn_header_t *)msgbuf_get_packet(msgbuf));
  // Same as 'msgbuf_set_data_expiry_time',
  // it would write in the same field
  msgbuf_set_interest_lifetime(msgbuf, *lifetime);

  return msgbuf;
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
  entry = pkt_cache_allocate(pkt_cache, name);
  EXPECT_NE(entry, nullptr);
  ASSERT_EQ(pkt_cache_get_size(pkt_cache), 1u);

  // // Get entry by name
  Name name_key = name_key_factory(name);
  khiter_t k = kh_get_pkt_cache_name(pkt_cache->index_by_name, &name_key);
  EXPECT_NE(k, kh_end(pkt_cache->index_by_name));
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
  pkt_cache_entry_t *entry = pkt_cache_lookup(pkt_cache, name, msgbuf_pool,
                                              &lookup_result, &entry_id, true);

  EXPECT_EQ(lookup_result, PKT_CACHE_LU_NONE);
  EXPECT_EQ(entry, nullptr);
}

TEST_F(PacketCacheTest, AddEntryAndLookup) {
  // Add entry to the packet cache
  entry = pkt_cache_allocate(pkt_cache, name);
  entry->entry_type = PKT_CACHE_PIT_TYPE;
  ASSERT_NE(entry, nullptr);

  // Perform lookup
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id, true);

  EXPECT_TRUE(lookup_result == PKT_CACHE_LU_INTEREST_NOT_EXPIRED ||
              lookup_result == PKT_CACHE_LU_INTEREST_EXPIRED);
  EXPECT_NE(lu_entry, nullptr);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, AddToPIT) {
  // Prepare msgbuf
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name);

  // Check if entry properly created
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf);
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->entry_type, PKT_CACHE_PIT_TYPE);
  EXPECT_EQ(pit_entry_ingress_contains(&entry->u.pit_entry, CONN_ID), true);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 1u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, AddToCS) {
  // Prepare msgbuf
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name);

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
      pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_DATA_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, PitToCS) {
  // Prepare msgbuf and PIT entry
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name);
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf);
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
      pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_DATA_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, CsToPIT) {
  // Prepare msgbuf and CS entry
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name);
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
  EXPECT_EQ(pit_entry_ingress_contains(&entry->u.pit_entry, CONN_ID), true);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 1u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, UpdateInPIT) {
  // Prepare msgbuf and PIT entry
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name);
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf);
  off_t entry_id = pkt_cache_get_entry_id(pkt_cache, entry);

  Name new_name;
  name_CreateFromAddress(&new_name, AF_INET, IPV4_LOOPBACK, IPV4_LEN);
  msgbuf_t *new_msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID_2, &new_name);

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
      pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, UpdateInCS) {
  // Prepare msgbuf and CS entry
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name);
  pkt_cache_entry_t *entry =
      pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, MSGBUF_ID);
  off_t entry_id = pkt_cache_get_entry_id(pkt_cache, entry);

  Name new_name;
  name_CreateFromAddress(&new_name, AF_INET, IPV4_LOOPBACK, IPV4_LEN);
  msgbuf_t *new_msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID_2, &new_name);

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
      pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_DATA_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, RemoveFromPIT) {
  // Prepare msgbuf and PIT entry
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name);
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 1u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  pkt_cache_pit_remove_entry(pkt_cache, entry, name);
  ASSERT_EQ(pkt_cache_get_pit_size(pkt_cache), 0u);
  ASSERT_EQ(pkt_cache_get_cs_size(pkt_cache), 0u);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_NONE);
  EXPECT_EQ(lu_entry, nullptr);
}

TEST_F(PacketCacheTest, RemoveFromCS) {
  // Prepare msgbuf and CS entry
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name);
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
      pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_NONE);
  EXPECT_EQ(lu_entry, nullptr);
}

TEST_F(PacketCacheTest, AddTwoEntriesToCS) {
  // Prepare msgbufs
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name);
  Name new_name;
  name_CreateFromAddress(&new_name, AF_INET, IPV4_LOOPBACK, IPV4_LEN);
  msgbuf_t *new_msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID_2, &new_name);

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
  // Prepare msgbufs
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name);
  Name new_name;
  name_CreateFromAddress(&new_name, AF_INET, IPV4_LOOPBACK, IPV4_LEN);
  msgbuf_t *new_msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID_2, &new_name);

  // Check if entry properly created (use sleep to get an updated ts)
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf);
  Ticks old_lifetime = entry->expire_ts;
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  bool is_aggregated =
      pkt_cache_try_aggregate_in_pit(pkt_cache, entry, new_msgbuf);
  Ticks new_lifetime = entry->expire_ts;

  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->entry_type, PKT_CACHE_PIT_TYPE);
  EXPECT_GT(new_lifetime, old_lifetime);
  ASSERT_EQ(is_aggregated, true);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, RetransmissionInPIT) {
  // Prepare msgbufs (using same connection ID)
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name);
  Name new_name;
  name_CreateFromAddress(&new_name, AF_INET, IPV4_LOOPBACK, IPV4_LEN);
  msgbuf_t *new_msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, &new_name);

  // Check if entry properly created (use sleep to get an updated ts)
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf);
  Ticks old_lifetime = entry->expire_ts;
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  bool is_aggregated =
      pkt_cache_try_aggregate_in_pit(pkt_cache, entry, new_msgbuf);
  Ticks new_lifetime = entry->expire_ts;

  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->entry_type, PKT_CACHE_PIT_TYPE);
  EXPECT_GT(new_lifetime, old_lifetime);
  ASSERT_EQ(is_aggregated, false);

  // Check if hashtable correctly updated
  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_entry_t *lu_entry = pkt_cache_lookup(
      pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id, true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_NOT_EXPIRED);
  EXPECT_EQ(lu_entry, entry);
}

TEST_F(PacketCacheTest, LookupExpiredInterest) {
  // Prepare msgbuf with 0 as interest lifetime
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name, 0);

  // Add to PIT
  pkt_cache_entry_t *entry = pkt_cache_add_to_pit(pkt_cache, msgbuf);
  ASSERT_NE(entry, nullptr);

  // Wait to make the interest expire
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_lookup(pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id,
                   true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_INTEREST_EXPIRED);
}

TEST_F(PacketCacheTest, LookupExpiredData) {
  // Prepare msgbuf with 0 as data expiry time
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name, 0);

  // Add to CS
  pkt_cache_entry_t *entry =
      pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, MSGBUF_ID);
  ASSERT_NE(entry, nullptr);

  // Wait to make the interest expire
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  pkt_cache_lookup_t lookup_result;
  off_t entry_id;
  pkt_cache_lookup(pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id,
                   true);
  EXPECT_EQ(lookup_result, PKT_CACHE_LU_DATA_EXPIRED);
}

TEST_F(PacketCacheTest, GetStaleEntries) {
  // Add to CS a msgbuf with immediate expiration (i.e. stale)
  msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, CONN_ID, name, 0);
  pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, MSGBUF_ID);

  // Add to CS another msgbuf with immediate expiration (i.e. stale)
  Name name_2;
  name_CreateFromAddress(&name_2, AF_INET, IPV4_LOOPBACK, IPV4_LEN);
  msgbuf_t *msgbuf_2 = msgbuf_factory(msgbuf_pool, CONN_ID, &name_2, 0);
  pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf_2, MSGBUF_ID_2);

  // Add to CS a msgbuf with 5-seconds expiration (i.e. not stale)
  Name name_3;
  name_CreateFromAddress(&name_3, AF_INET6, IPV6_LOOPBACK, IPV6_LEN);
  msgbuf_t *msgbuf_3 =
      msgbuf_factory(msgbuf_pool, CONN_ID, &name_3, FIVE_SECONDS);
  pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf_3, MSGBUF_ID_3);

  size_t num_stale_entries = pkt_cache_get_num_cs_stale_entries(pkt_cache);
  EXPECT_EQ(num_stale_entries, 2u);
}

TEST_F(PacketCacheTest, GetMultipleStaleEntries) {
  ip_address_t addr;
  char name[30];
  const int NUM_STALES = 10;

  // Add to CS multiple msgbufs with immediate expiration (i.e. 0 seconds),
  // resulting in stale entries
  for (int i = 0; i < NUM_STALES; i++) {
    snprintf(name, 30, "b001::%d", i);
    inet_pton(AF_INET6, name, (struct in6_addr *)&addr);
    Name name;
    name_CreateFromAddress(&name, AF_INET6, addr, IPV6_LEN);
    msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, i, &name, 0);

    pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, i);
  }

  // Add to CS multiple msgbufs with 5-seconds expiration,
  // resulting in non-stale entries
  for (int i = NUM_STALES; i < 15; i++) {
    snprintf(name, 30, "b001::%d", i);
    inet_pton(AF_INET6, name, (struct in6_addr *)&addr);
    Name name;
    name_CreateFromAddress(&name, AF_INET6, addr, IPV6_LEN);
    msgbuf_t *msgbuf = msgbuf_factory(msgbuf_pool, i, &name, FIVE_SECONDS);

    pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, i);
  }

  size_t num_stale_entries = pkt_cache_get_num_cs_stale_entries(pkt_cache);
  EXPECT_EQ(num_stale_entries, (size_t)NUM_STALES);
}
