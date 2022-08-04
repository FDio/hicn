#include "common.h"

std::string dump_buffer(const char *name, uint8_t *buffer, size_t size) {
  std::ostringstream oss;
  oss << "const std::vector<uint8_t> " << name << " = {";
  for (size_t i = 0; i < size; i++) {
    if (i > 0) oss << ", ";
    oss << "0x" << std::setw(2) << std::setfill('0') << std::hex
        << static_cast<int>(buffer[i]);
  }
  oss << "};" << std::endl;
  return oss.str();
}
