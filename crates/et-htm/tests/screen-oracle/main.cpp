// Link this against the unmodified canonical PaneScreen.cpp and libvterm.
#include "PaneScreen.hpp"
#include <iostream>
#include <sstream>
int main() {
  int cols, rows;
  std::cin >> cols >> rows;
  et::PaneScreen screen(cols, rows);
  std::string op;
  while (std::cin >> op) {
    if (op == "feed") {
      std::string hex, bytes;
      std::cin >> hex;
      for (size_t i = 0; i < hex.size(); i += 2)
        bytes.push_back(static_cast<char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
      screen.feed(bytes);
    } else if (op == "resize") {
      std::cin >> cols >> rows;
      screen.resize(cols, rows);
    } else if (op == "capture") {
      int flags, start, end;
      std::cin >> flags >> start >> end;
      auto bytes = screen.capture(flags & 1, flags & 2, start, end, flags & 4, flags & 8);
      const char* hex = "0123456789abcdef";
      for (unsigned char byte : bytes) std::cout << hex[byte >> 4] << hex[byte & 15];
      std::cout << '\n';
    } else return 2;
  }
}
