// Deterministic PTY boundary only. This oracle does NOT test native PTY I/O,
// process discovery or cwd: those have real-role runtime tests.
#pragma once
#include "Headers.hpp"
namespace et {
class TerminalHandler {
 public:
  void start(const string&, int, int) {}
  void stop() {}
  void updateTerminalSize(int, int) {}
  void appendData(const string&) {}
  string pollUserTerminal() { return ""; }
  bool isRunning() { return true; }
  string foregroundCommand() { return "sh"; }
  int64_t childProcessId() { return 0; }
};
}
