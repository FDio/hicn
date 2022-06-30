/*
 * Copyright (c) 20022 Cisco and/or its affiliates.
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

#define HICN_PCS_TESTING
#include "vpp.h"
#include <pcs.h>

#include <unity.h>
#include <unity_fixture.h>

/*
 *  Global PCS instance common to each test
 */
static hicn_pit_cs_t global_pcs;

TEST_GROUP (PCS);

/**
 * Default PIT elements
 */
#define MAX_PIT_ELEMENTS 1000000

/**
 * Default CS elements
 */
#define MAX_CS_ELEMENTS (MAX_PIT_ELEMENTS / 10)

TEST_SETUP (PCS)
{
  hicn_pit_cs_t *pcs = &global_pcs;
  hicn_pit_create (pcs, MAX_PIT_ELEMENTS, MAX_CS_ELEMENTS);
}

TEST_TEAR_DOWN (PCS)
{
  hicn_pit_cs_t *pcs = &global_pcs;
  hicn_pit_destroy (pcs);
}

TEST (PCS, Create)
{
  hicn_pit_cs_t *pcs = &global_pcs;

  // Check counters
  TEST_ASSERT_EQUAL (0, pcs->pcs_pit_count);
  TEST_ASSERT_EQUAL (0, pcs->pcs_cs_count);
  TEST_ASSERT_EQUAL (0, pcs->pcs_pcs_alloc);
  TEST_ASSERT_EQUAL (0, pcs->pcs_pcs_dealloc);
  TEST_ASSERT_EQUAL (MAX_PIT_ELEMENTS, pcs->max_pit_size);
  TEST_ASSERT_EQUAL (MAX_CS_ELEMENTS, pcs->policy_state.max);

  printf ("PIT entry size: %lu", sizeof (hicn_pcs_entry_t));
}

TEST (PCS, Destroy)
{
  // Global PCS instance
}

TEST (PCS, LookupEmpty)
{
  hicn_pit_cs_t *pcs = &global_pcs;

  hicn_name_t name;
  int ret = hicn_name_create ("b001::abcd", 0, &name);
  TEST_ASSERT_EQUAL (0, ret);

  hicn_pcs_entry_t *pcs_entry;
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry);

  TEST_ASSERT_EQUAL (HICN_ERROR_PCS_NOT_FOUND, ret);
  TEST_ASSERT_EQUAL (NULL, pcs_entry);
}

TEST (PCS, InsertPITEntryAndLookup)
{
  hicn_pit_cs_t *pcs = &global_pcs;

  // Add entry to the PCS
  int ret = 0;

  // Allocate name
  hicn_name_t name;
  hicn_name_create ("b001::1234", 0, &name);

  // Create PCS entry
  hicn_pcs_entry_t *pcs_entry;
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry);

  // We will not find the entry
  TEST_ASSERT_EQUAL (ret, HICN_ERROR_PCS_NOT_FOUND);
  TEST_ASSERT_EQUAL (NULL, pcs_entry);

  // Get a new PIT entry from the pool
  // TODO Check if the hicn_pcs_entry_pit_get is needed here
  pcs_entry = hicn_pcs_entry_pit_get (pcs, 0, 0);
  TEST_ASSERT_NOT_NULL (pcs_entry);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pcs_alloc (pcs), 1);

  // Insert PIT entry
  ret = hicn_pcs_pit_insert (pcs, pcs_entry, &name);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 1);
  TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), 0);

  // Lookup PIT entry
  hicn_pcs_entry_t *pcs_entry_ret = NULL;
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry_ret);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_NOT_NULL (pcs_entry_ret);
  TEST_ASSERT_EQUAL (pcs_entry, pcs_entry_ret);

  // Release PIT entry
  hicn_pcs_entry_remove_lock (pcs, pcs_entry);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pcs_dealloc (pcs), 1);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 0);
  TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), 0);

  // Lookup PIT entry again, we should not find it
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry_ret);
  TEST_ASSERT_EQUAL (HICN_ERROR_PCS_NOT_FOUND, ret);
  TEST_ASSERT_EQUAL (NULL, pcs_entry_ret);
}

TEST (PCS, InsertCSEntryAndLookup)
{
  hicn_pit_cs_t *pcs = &global_pcs;

  // Add entry to the PCS
  int ret = 0;

  // Allocate name
  hicn_name_t name;
  hicn_name_create ("b008::5555", 0, &name);

  // Create PCS entry
  hicn_pcs_entry_t *pcs_entry;
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry);

  // We will not find the entry
  TEST_ASSERT_EQUAL (ret, HICN_ERROR_PCS_NOT_FOUND);
  TEST_ASSERT_EQUAL (NULL, pcs_entry);

  // Get a buffer
  u32 buffer_index = 198274;

  // Get a new entry from the pool
  pcs_entry = hicn_pcs_entry_cs_get (pcs, 0, buffer_index);
  TEST_ASSERT_NOT_NULL (pcs_entry);
  TEST_ASSERT_EQUAL (1, hicn_pcs_get_pcs_alloc (pcs));

  // Insert CS entry
  ret = hicn_pcs_cs_insert (pcs, pcs_entry, &name);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 0);
  TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), 1);

  // Lookup CS entry
  hicn_pcs_entry_t *pcs_entry_ret = NULL;
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry_ret);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_TRUE (pcs_entry_ret->flags & HICN_PCS_ENTRY_CS_FLAG);
  TEST_ASSERT_NOT_NULL (pcs_entry_ret);
  TEST_ASSERT_EQUAL (pcs_entry, pcs_entry_ret);

  // Release CS entry
  hicn_pcs_entry_remove_lock (pcs, pcs_entry);
  TEST_ASSERT_EQUAL (1, hicn_pcs_get_pcs_dealloc (pcs));
  TEST_ASSERT_EQUAL (0, hicn_pcs_get_pit_count (pcs));
  TEST_ASSERT_EQUAL (0, hicn_pcs_get_cs_count (pcs));

  // Lookup CS entry again, we should not find it
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry_ret);
  TEST_ASSERT_EQUAL (HICN_ERROR_PCS_NOT_FOUND, ret);
  TEST_ASSERT_EQUAL (NULL, pcs_entry_ret);
}

TEST (PCS, PitToCS)
{
  hicn_pit_cs_t *pcs = &global_pcs;

  // Add entry to the PCS
  int ret = 0;

  // Allocate name
  hicn_name_t name;
  hicn_name_create ("b001::1234", 0, &name);

  // Create PCS entry
  hicn_pcs_entry_t *pcs_entry;
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry);

  // We will not find the entry
  TEST_ASSERT_EQUAL (ret, HICN_ERROR_PCS_NOT_FOUND);
  TEST_ASSERT_EQUAL (NULL, pcs_entry);

  // Get a new entry from the pool
  // TODO Check if the hicn_pcs_entry_pit_get is needed here
  pcs_entry = hicn_pcs_entry_pit_get (pcs, 0, 0);
  TEST_ASSERT_NOT_NULL (pcs_entry);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pcs_alloc (pcs), 1);

  // Insert PIT entry
  ret = hicn_pcs_pit_insert (pcs, pcs_entry, &name);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 1);
  TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), 0);

  // Lookup PIT entry
  hicn_pcs_entry_t *pcs_entry_ret = NULL;
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry_ret);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_NOT_NULL (pcs_entry_ret);
  TEST_ASSERT_EQUAL (pcs_entry, pcs_entry_ret);

  // Found the PIT entry we inserted before.
  // Double check is not a CS
  TEST_ASSERT_FALSE (pcs_entry_ret->flags & HICN_PCS_ENTRY_CS_FLAG);

  // Turn the PIT entry into a CS
  hicn_pit_to_cs (pcs, pcs_entry, /* random buffer index */ 12345);

  // Check counters
  TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 0);
  TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), 1);

  // Make sure entry is now a CS
  TEST_ASSERT_TRUE (pcs_entry_ret->flags & HICN_PCS_ENTRY_CS_FLAG);
}

TEST (PCS, CheckCSLruConsistency)
{
  hicn_pit_cs_t *pcs = &global_pcs;

  // Add entry to the PCS
  int ret = 0;

  // Allocate name
  hicn_name_t name;
  hicn_name_create ("b001::1234", 0, &name);

  // Create CS entry
  hicn_pcs_entry_t *pcs_entry;
  // Get a new entry from the pool
  // TODO Check if the hicn_pcs_entry_pit_get is needed here
  pcs_entry = hicn_pcs_entry_cs_get (pcs, 0, 0);
  TEST_ASSERT_NOT_NULL (pcs_entry);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pcs_alloc (pcs), 1);

  // Insert CS entry
  ret = hicn_pcs_cs_insert (pcs, pcs_entry, &name);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), 1);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 0);

  // Get pcs_entry index
  uint32_t pcs_entry_index = hicn_pcs_entry_get_index (pcs, pcs_entry);

  // Check LRU
  hicn_cs_policy_t *policy_state = hicn_pcs_get_policy_state (pcs);

  // Make sure MAX corresponds to what we set
  TEST_ASSERT_EQUAL (MAX_CS_ELEMENTS, hicn_cs_policy_get_max (policy_state));

  TEST_ASSERT_EQUAL (pcs_entry_index, hicn_cs_policy_get_head (policy_state));
  TEST_ASSERT_EQUAL (pcs_entry_index, hicn_cs_policy_get_tail (policy_state));
  TEST_ASSERT_EQUAL (1, hicn_cs_policy_get_count (policy_state));

  // Check pointers of the entry
  TEST_ASSERT_EQUAL (HICN_CS_POLICY_END_OF_CHAIN,
		     hicn_pcs_entry_cs_get_next (pcs_entry));
  TEST_ASSERT_EQUAL (HICN_CS_POLICY_END_OF_CHAIN,
		     hicn_pcs_entry_cs_get_prev (pcs_entry));

  // Lookup the entry itself
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry);

  // Check again the pointers of the entry
  TEST_ASSERT_EQUAL (HICN_CS_POLICY_END_OF_CHAIN,
		     hicn_pcs_entry_cs_get_next (pcs_entry));
  TEST_ASSERT_EQUAL (HICN_CS_POLICY_END_OF_CHAIN,
		     hicn_pcs_entry_cs_get_prev (pcs_entry));

  // Remove CS entry
  hicn_pcs_entry_remove_lock (pcs, pcs_entry);
  TEST_ASSERT_EQUAL (1, hicn_pcs_get_pcs_dealloc (pcs));
  TEST_ASSERT_EQUAL (0, hicn_pcs_get_pit_count (pcs));
  TEST_ASSERT_EQUAL (0, hicn_pcs_get_cs_count (pcs));

  // Check again LRU
  TEST_ASSERT_EQUAL (HICN_CS_POLICY_END_OF_CHAIN,
		     hicn_cs_policy_get_head (policy_state));
  TEST_ASSERT_EQUAL (HICN_CS_POLICY_END_OF_CHAIN,
		     hicn_cs_policy_get_tail (policy_state));
  TEST_ASSERT_EQUAL (0, hicn_cs_policy_get_count (policy_state));

  // Let's insert now 2 entries
  hicn_pcs_entry_t *pcs_entry0;
  hicn_pcs_entry_t *pcs_entry1;

  pcs_entry0 = hicn_pcs_entry_cs_get (pcs, 0, 0);
  TEST_ASSERT_NOT_NULL (pcs_entry0);
  hicn_name_t name0;
  hicn_name_create ("b001::abcd", 123, &name0);
  u32 index0 = hicn_pcs_entry_get_index (pcs, pcs_entry0);

  pcs_entry1 = hicn_pcs_entry_cs_get (pcs, 0, 0);
  TEST_ASSERT_NOT_NULL (pcs_entry1);
  hicn_name_t name1;
  hicn_name_create ("b001::9999", 321, &name1);
  u32 index1 = hicn_pcs_entry_get_index (pcs, pcs_entry1);

  // Insert CS entry
  ret = hicn_pcs_cs_insert (pcs, pcs_entry0, &name0);
  ret = hicn_pcs_cs_insert (pcs, pcs_entry1, &name1);

  // Check LRU. index1 was inserted last, so it should be at the head
  TEST_ASSERT_EQUAL (index1, hicn_cs_policy_get_head (policy_state));
  // index0 was inserted first, so it should be at the tail
  TEST_ASSERT_EQUAL (index0, hicn_cs_policy_get_tail (policy_state));
  // And count shoould be 2
  TEST_ASSERT_EQUAL (2, hicn_cs_policy_get_count (policy_state));

  // Check pointers of the entries

  // pcs_entry0 should be at the tail
  TEST_ASSERT_EQUAL (HICN_CS_POLICY_END_OF_CHAIN,
		     hicn_pcs_entry_cs_get_next (pcs_entry0));
  TEST_ASSERT_EQUAL (index1, hicn_pcs_entry_cs_get_prev (pcs_entry0));

  // pcs_entry1 should be at the head
  TEST_ASSERT_EQUAL (index0, hicn_pcs_entry_cs_get_next (pcs_entry1));
  TEST_ASSERT_EQUAL (HICN_CS_POLICY_END_OF_CHAIN,
		     hicn_pcs_entry_cs_get_prev (pcs_entry1));

  // Let's lookup for entry 0 and check if the LRU is updated correctly
  ret = hicn_pcs_lookup_one (pcs, &name0, &pcs_entry);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_EQUAL (index0, hicn_pcs_entry_get_index (pcs, pcs_entry));

  // Check pointers of the entries

  // pcs_entry1 should be at the tail
  TEST_ASSERT_EQUAL (HICN_CS_POLICY_END_OF_CHAIN,
		     hicn_pcs_entry_cs_get_next (pcs_entry1));
  TEST_ASSERT_EQUAL (index0, hicn_pcs_entry_cs_get_prev (pcs_entry1));

  // pcs_entry0 should be at the head
  TEST_ASSERT_EQUAL (index1, hicn_pcs_entry_cs_get_next (pcs_entry0));
  TEST_ASSERT_EQUAL (HICN_CS_POLICY_END_OF_CHAIN,
		     hicn_pcs_entry_cs_get_prev (pcs_entry0));

  // index0 should be now the head
  TEST_ASSERT_EQUAL (index0, hicn_cs_policy_get_head (policy_state));
  // index1 should be now the tail
  TEST_ASSERT_EQUAL (index1, hicn_cs_policy_get_tail (policy_state));
}

TEST (PCS, CheckCSLruMax)
{
  hicn_pit_cs_t *pcs = &global_pcs;
  int i, ret = 0;
  ;
  u32 pcs_entry_index = 0;
  u32 pcs_entry_index0 = 0;
  u32 pcs_entry_index1 = 0;
  hicn_pcs_entry_t *pcs_entry = NULL;
  hicn_name_t name;

  const hicn_cs_policy_t *policy_state = hicn_pcs_get_policy_state (pcs);

  for (i = 0; i < MAX_CS_ELEMENTS; i++)
    {
      // Allocate name
      ret = hicn_name_create ("b004::aaaa", i, &name);
      TEST_ASSERT_EQUAL (0, ret);

      // Create CS entry
      // Get a new entry from the pool
      // TODO Check if the hicn_pcs_entry_pit_get is needed here
      pcs_entry = hicn_pcs_entry_cs_get (pcs, 0, i);
      TEST_ASSERT_NOT_NULL (pcs_entry);
      TEST_ASSERT_EQUAL (i + 1, hicn_pcs_get_pcs_alloc (pcs));

      pcs_entry_index = hicn_pcs_entry_get_index (pcs, pcs_entry);

      if (i == 0)
	{
	  pcs_entry_index0 = pcs_entry_index;
	}

      if (i == 1)
	{
	  pcs_entry_index1 = pcs_entry_index;
	}

      // Insert CS entry
      ret = hicn_pcs_cs_insert (pcs, pcs_entry, &name);
      TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
      TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), i + 1);
      TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 0);

      // Check LRU
      TEST_ASSERT_EQUAL (pcs_entry_index,
			 hicn_cs_policy_get_head (policy_state));
      TEST_ASSERT_EQUAL (pcs_entry_index0,
			 hicn_cs_policy_get_tail (policy_state));
      TEST_ASSERT_EQUAL (i + 1, hicn_cs_policy_get_count (policy_state));
    }

  // In this moment the CS should be full
  TEST_ASSERT_EQUAL (hicn_cs_policy_get_max (policy_state),
		     hicn_cs_policy_get_count (policy_state));

  // Next insertion should:
  // - evict the tail
  // - update the head
  // - make a coffee because I am tired
  ret = hicn_name_create ("b004::aaaa", i, &name);
  TEST_ASSERT_EQUAL (0, ret);

  pcs_entry = hicn_pcs_entry_cs_get (pcs, 0, i);
  TEST_ASSERT_NOT_NULL (pcs_entry);
  TEST_ASSERT_EQUAL (i + 1, hicn_pcs_get_pcs_alloc (pcs));

  pcs_entry_index = hicn_pcs_entry_get_index (pcs, pcs_entry);

  // Insert CS entry
  ret = hicn_pcs_cs_insert (pcs, pcs_entry, &name);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), i);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 0);

  // Check LRU
  TEST_ASSERT_EQUAL (pcs_entry_index, hicn_cs_policy_get_head (policy_state));
  // pcs_entry_index1 should be have eveicted, and pcs_entry_index1 should be
  // the tail
  TEST_ASSERT_EQUAL (pcs_entry_index1, hicn_cs_policy_get_tail (policy_state));

  // Make pcs_entry_index0 was freed.
  TEST_ASSERT_TRUE (
    pool_is_free_index (pcs->pcs_entries_pool, pcs_entry_index0));
}

TEST (PCS, AddIngressFacesToPITEntry)
{
  hicn_pit_cs_t *pcs = &global_pcs;

  // Add entry to the PCS
  int ret = 0;

  // Allocate name
  hicn_name_t name;
  hicn_name_create ("b001::9876", 0, &name);

  // Create PCS entry
  hicn_pcs_entry_t *pcs_entry;
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry);

  // We will not find the entry
  TEST_ASSERT_EQUAL (ret, HICN_ERROR_PCS_NOT_FOUND);
  TEST_ASSERT_EQUAL (NULL, pcs_entry);

  // Get a new entry from the pool
  // TODO Check if the hicn_pcs_entry_pit_get is needed here
  f64 tnow = 10.0;
  pcs_entry = hicn_pcs_entry_pit_get (pcs, tnow, 0);
  TEST_ASSERT_NOT_NULL (pcs_entry);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pcs_alloc (pcs), 1);

  const u32 faceid = 20;

  // The face should not be in the PIT entry
  TEST_ASSERT_EQUAL (0, hicn_pcs_entry_pit_search (pcs_entry, faceid));

  // Add ingress face to pit entry
  hicn_pcs_entry_pit_add_face (pcs_entry, faceid);

  // Insert PIT entry
  ret = hicn_pcs_pit_insert (pcs, pcs_entry, &name);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 1);
  TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), 0);

  // Lookup PIT entry
  hicn_pcs_entry_t *pcs_entry_ret = NULL;
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry_ret);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_NOT_NULL (pcs_entry_ret);
  TEST_ASSERT_EQUAL (pcs_entry, pcs_entry_ret);

  // Check everything is fine
  ret = hicn_pcs_entry_pit_search (pcs_entry_ret, faceid);
  // Face 20 should be in the entry
  TEST_ASSERT_EQUAL (ret, 1);

  // Get faces and make sure
  // - there is only one face
  // - the face is 20
  TEST_ASSERT_EQUAL (1, hicn_pcs_entry_pit_get_n_faces (pcs_entry_ret));
  TEST_ASSERT_EQUAL (20, hicn_pcs_entry_pit_get_dpo_face (pcs_entry_ret, 0));

  // Release PIT entry
  hicn_pcs_entry_remove_lock (pcs, pcs_entry_ret);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pcs_dealloc (pcs), 1);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 0);
  TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), 0);

  // Lookup PIT entry again, we should not find it
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry_ret);
  TEST_ASSERT_EQUAL (HICN_ERROR_PCS_NOT_FOUND, ret);
  TEST_ASSERT_EQUAL (NULL, pcs_entry_ret);
}

TEST (PCS, AddIngressFacesToPitEntryCornerCases)
{
  hicn_pit_cs_t *pcs = &global_pcs;

  // Add entry to the PCS
  int ret = 0;

  // Allocate name
  hicn_name_t name;
  hicn_name_create ("b001::9876", 0, &name);

  // Create PCS entry
  hicn_pcs_entry_t *pcs_entry;
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry);

  // We will not find the entry
  TEST_ASSERT_EQUAL (ret, HICN_ERROR_PCS_NOT_FOUND);
  TEST_ASSERT_EQUAL (NULL, pcs_entry);

  // Get a new entry from the pool
  // TODO Check if the hicn_pcs_entry_pit_get is needed here
  f64 tnow = 10.0;
  pcs_entry = hicn_pcs_entry_pit_get (pcs, tnow, 0);
  TEST_ASSERT_NOT_NULL (pcs_entry);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pcs_alloc (pcs), 1);

  // Let's initialize HICN_FACE_DB_INLINE_FACES + 1 face IDs
  u32 faceids[HICN_FACE_DB_INLINE_FACES + 1];
  for (u32 i = 0; i < HICN_FACE_DB_INLINE_FACES + 1; i++)
    faceids[i] = rand () % HICN_PARAM_FACES_MAX;

  // The faces should not be in the PIT entry
  for (u32 i = 0; i < HICN_FACE_DB_INLINE_FACES + 1; i++)
    TEST_ASSERT_EQUAL (0, hicn_pcs_entry_pit_search (pcs_entry, faceids[i]));

  // Add ingress faces to pit entry
  for (u32 i = 0; i < HICN_FACE_DB_INLINE_FACES + 1; i++)
    hicn_pcs_entry_pit_add_face (pcs_entry, faceids[i]);

  // Insert PIT entry
  ret = hicn_pcs_pit_insert (pcs, pcs_entry, &name);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 1);
  TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), 0);

  // Lookup PIT entry
  hicn_pcs_entry_t *pcs_entry_ret = NULL;
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry_ret);
  TEST_ASSERT_EQUAL (HICN_ERROR_NONE, ret);
  TEST_ASSERT_NOT_NULL (pcs_entry_ret);
  TEST_ASSERT_EQUAL (pcs_entry, pcs_entry_ret);

  // Check everything is fine
  for (u32 i = 0; i < HICN_FACE_DB_INLINE_FACES + 1; i++)
    {
      ret = hicn_pcs_entry_pit_search (pcs_entry_ret, faceids[i]);
      // Face 20 should be in the entry
      TEST_ASSERT_EQUAL (1, ret);
    }

  // Get faces and make sure
  // - there are HICN_FACE_DB_INLINE_FACES + 1 faces
  // - the first HICN_FACE_DB_INLINE_FACES are stored in the PIT entry
  // - the face HICN_FACE_DB_INLINE_FACES + 1 is stored in the array of
  // additional faces, so outside PIT entry
  TEST_ASSERT_EQUAL (HICN_FACE_DB_INLINE_FACES + 1,
		     hicn_pcs_entry_pit_get_n_faces (pcs_entry_ret));
  for (u32 i = 0; i < HICN_FACE_DB_INLINE_FACES + 1; i++)
    TEST_ASSERT_EQUAL (faceids[i],
		       hicn_pcs_entry_pit_get_dpo_face (pcs_entry_ret, i));

  // Release PIT entry
  hicn_pcs_entry_remove_lock (pcs, pcs_entry_ret);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pcs_dealloc (pcs), 1);
  TEST_ASSERT_EQUAL (hicn_pcs_get_pit_count (pcs), 0);
  TEST_ASSERT_EQUAL (hicn_pcs_get_cs_count (pcs), 0);

  // Lookup PIT entry again, we should not find it
  ret = hicn_pcs_lookup_one (pcs, &name, &pcs_entry_ret);
  TEST_ASSERT_EQUAL (HICN_ERROR_PCS_NOT_FOUND, ret);
  TEST_ASSERT_EQUAL (NULL, pcs_entry_ret);
}

TEST_GROUP_RUNNER (PCS)
{
  RUN_TEST_CASE (PCS, Create)
  RUN_TEST_CASE (PCS, Destroy)
  RUN_TEST_CASE (PCS, LookupEmpty)
  RUN_TEST_CASE (PCS, InsertPITEntryAndLookup)
  RUN_TEST_CASE (PCS, InsertCSEntryAndLookup)
  RUN_TEST_CASE (PCS, PitToCS)
  RUN_TEST_CASE (PCS, CheckCSLruConsistency)
  RUN_TEST_CASE (PCS, CheckCSLruMax)
  RUN_TEST_CASE (PCS, AddIngressFacesToPITEntry)
  RUN_TEST_CASE (PCS, AddIngressFacesToPitEntryCornerCases)
}
