#pragma once

#include <vector>
#include <thread>
#include <numeric>

static constexpr int N_RUNS = 100;

// Utility function for time execution calculation
template <typename F, typename... Args>
double get_execution_time(F func, Args &&...args) {
  std::vector<float> execution_times;

  for (int i = 0; i < N_RUNS; i++) {
    auto start = std::chrono::high_resolution_clock::now();
    func(std::forward<Args>(args)...);
    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> ms = end - start;
    execution_times.emplace_back(ms.count());
  }

  // Calculate average
  return std::reduce(execution_times.begin(), execution_times.end()) /
         execution_times.size();
}