/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#pragma once

#include <memory>

namespace utils {

template <typename Base>
inline std::shared_ptr<Base> shared_from_base(
    std::enable_shared_from_this<Base>* base) {
  return base->shared_from_this();
}

template <typename Base>
inline std::shared_ptr<const Base> shared_from_base(
    std::enable_shared_from_this<Base> const* base) {
  return base->shared_from_this();
}

template <typename That>
inline std::shared_ptr<That> shared_from(That* that) {
  return std::static_pointer_cast<That>(shared_from_base(that));
}

}  // namespace utils