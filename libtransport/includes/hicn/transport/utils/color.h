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

#pragma once

#include <array>
#include <ostream>
#include <random>
#include <sstream>

namespace utils {

#define foreach_modifier  \
  _(RESET, 0)             \
  _(BOLD, 1)              \
  _(FG_DEFAULT, 39)       \
  _(FG_BLACK, 30)         \
  _(FG_RED, 31)           \
  _(FG_GREEN, 32)         \
  _(FG_YELLOW, 33)        \
  _(FG_BLUE, 34)          \
  _(FG_MAGENTA, 35)       \
  _(FG_CYAN, 36)          \
  _(FG_LIGHT_GRAY, 37)    \
  _(FG_DARK_GRAY, 90)     \
  _(FG_LIGHT_RED, 91)     \
  _(FG_LIGHT_GREEN, 92)   \
  _(FG_LIGHT_YELLOW, 93)  \
  _(FG_LIGHT_BLUE, 94)    \
  _(FG_LIGHT_MAGENTA, 95) \
  _(FG_LIGHT_CYAN, 96)    \
  _(FG_WHITE, 97)         \
  _(BG_RED, 41)           \
  _(BG_GREEN, 42)         \
  _(BG_BLUE, 44)          \
  _(BG_DEFAULT, 49)

class ColorModifier {
  static inline const std::size_t n_modifiers = 23;
  static inline const char format_string_start[] = "\033[";
  static inline const char format_string_end[] = "m";

 public:
  enum class Code {
#define _(name, value) name = value,
    foreach_modifier
#undef _
  };

  static inline std::array<Code, n_modifiers> code_array = {
#define _(name, value) Code::name,
      foreach_modifier
#undef _
  };

  static Code getRandomModifier() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> distr(4, 17);

    return code_array[distr(gen)];
  }

  ColorModifier(Code code) : code_(code), color_string_() {
    std::stringstream ss;
    if (std::getenv("COLORTERM") != nullptr) {
      ss << format_string_start << static_cast<int>(code_) << format_string_end;
      color_string_ = ss.str();
    }
  }

  ColorModifier() : ColorModifier(getRandomModifier()) {}

  friend std::ostream& operator<<(std::ostream& os, const ColorModifier& mod) {
    return os << mod.color_string_;
  }

 private:
  Code code_;
  std::string color_string_;
};

}  // namespace utils