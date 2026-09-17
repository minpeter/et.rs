#include "ControlCommands.hpp"
int main() {
  et::MultiplexerState mux;
  et::ControlWriter writer;
  auto socket = make_shared<et::SocketHandler>();
  writer.setSocket(socket, 1);
  mux.setWriter(&writer);
  for (string line; getline(cin, line);) {
    if (line.rfind("oracle-keys ", 0) == 0) {
      auto words = et::controlSplitArgs(line);
      string mode = words.at(1);
      words.erase(words.begin(), words.begin() + 2);
      for (unsigned char c : et::encodeSendKeys(words, mode == "hex", mode == "literal")) printf("%02x", c);
      puts("");
      continue;
    }
    auto commands = et::splitControlCommandList(line);
    if (commands.empty()) commands.push_back(line);
    for (const auto& command : commands) {
      auto action = et::executeControlCommand(&mux, &writer, command);
      if (action != et::ControlAction::None) break;
    }
    for (unsigned char c : socket->output) printf("%02x", c);
    puts("");
    socket->output.clear();
  }
}
