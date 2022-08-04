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
#include <sstream>

extern "C" {
#include <hicn/ctrl/objects.h>
#include <hicn/ctrl/data.h>
#include <hicn/ctrl/object.h>
}

#include "common.h"

namespace {

TEST_F(TestHicnLight, TestHicnLightData) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));

  int rc;
  hc_data_t* data = hc_data_create(OBJECT_TYPE_FACE);
  hc_data_set_max_size(data, 2);

  ASSERT_EQ(hc_data_get_size(data), 0) << "Initial data size should be zero";

  /* Try to allocate more than max */
  rc = hc_data_allocate(data, 5);
  ASSERT_EQ(rc, -1) << "Allocating above max_size should fail";

  /* Allocate room for two objects */
  rc = hc_data_allocate(data, 2);
  ASSERT_EQ(rc, 0) << "Allocating data the first time should succeed";

  ASSERT_EQ(hc_data_get_size(data), 0)
      << "Initial size should be 0 after allocation";

  /* Try to allocate twice */
  rc = hc_data_allocate(data, 2);
  ASSERT_EQ(rc, -1) << "Allocating data multiple times should fail";

  ASSERT_EQ(hc_data_get_size(data), 0)
      << "Size after failed push should remain unchanged";

  /* Push a first object */
  rc = hc_data_push(data, &object);
  ASSERT_EQ(rc, 0) << "First push should succeed";

  ASSERT_EQ(hc_data_get_size(data), 1)
      << "Data size first successful push should be 1";

  /* Push a second object */
  rc = hc_data_push(data, &object);
  ASSERT_EQ(rc, 0) << "Second push should succeed";

  ASSERT_EQ(hc_data_get_size(data), 2)
      << "Data size after second successful push should be 2";

  /* Push a third object, exceeding the allocated size */
  rc = hc_data_push(data, &object);
  ASSERT_EQ(rc, -1) << "Third push on full data of size 2 should fail";

  /* Clear */
  rc = hc_data_clear(data);
  ASSERT_EQ(rc, 0) << "Clear should always succeed";

  rc = hc_data_push(data, &object);
  ASSERT_EQ(rc, 0) << "Pushing element after reallocation should succeed";

  ASSERT_EQ(hc_data_get_size(data), 1) << "Size after first push should be one";
  // XXX

  /* Try to push an invalid object */
  // XXX so far NULL
  rc = hc_data_push(data, NULL);
  ASSERT_EQ(rc, -1) << "Pushing invalid element should fail";

  ASSERT_EQ(hc_data_get_size(data), 1)
      << "Size after push failure should remain unchanged";
  // XXX

  hc_data_free(data);
}

}  // namespace
