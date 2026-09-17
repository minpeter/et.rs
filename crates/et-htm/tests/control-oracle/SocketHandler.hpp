#pragma once
#include "Headers.hpp"
namespace et {
class SocketHandler {
 public:
  string output;
  void writeAllOrThrow(int, const char *bytes, int size, bool) { output.append(bytes, size); }
  void write(int, const char *bytes, size_t size) { output.append(bytes, size); }
};
}
