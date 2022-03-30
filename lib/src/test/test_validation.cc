/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

extern "C"
{
#include <hicn/validation.h>
}

static constexpr int BUF_SIZE = 10;

class ValidationTest : public ::testing::Test
{
};

TEST_F (ValidationTest, SymbolicName)
{
  const char symbolic_name_correct[BUF_SIZE] = "conn0";
  const char symbolic_name_empty[BUF_SIZE] = "";
  const char symbolic_name_wrong[BUF_SIZE] = "1conn0";

  EXPECT_TRUE (is_symbolic_name (symbolic_name_correct, BUF_SIZE));
  EXPECT_FALSE (is_symbolic_name (symbolic_name_empty, BUF_SIZE));
  EXPECT_FALSE (is_symbolic_name (symbolic_name_wrong, BUF_SIZE));
}

TEST_F (ValidationTest, Number)
{
  const char number_correct[BUF_SIZE] = "123";
  const char number_empty[BUF_SIZE] = "";
  const char number_wrong[BUF_SIZE] = "a123";
  const char number_wrong_2[BUF_SIZE] = "12T3";
  const char number_wrong_3[BUF_SIZE] = "a";
  const char number_wrong_negative[BUF_SIZE] = "-123";

  EXPECT_TRUE (is_number (number_correct, BUF_SIZE));
  EXPECT_FALSE (is_number (number_empty, BUF_SIZE));
  EXPECT_FALSE (is_number (number_wrong, BUF_SIZE));
  EXPECT_FALSE (is_number (number_wrong_2, BUF_SIZE));
  EXPECT_FALSE (is_number (number_wrong_3, BUF_SIZE));
  EXPECT_FALSE (is_number (number_wrong_negative, BUF_SIZE));
}