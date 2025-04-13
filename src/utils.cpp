#include <iostream>

namespace utils {
void die(const std::string &message) {
  std::cerr << "Error: " << message << std::endl;
  std::exit(1);
}
} // namespace utils