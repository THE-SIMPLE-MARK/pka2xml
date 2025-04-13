#pragma once

#include <string>

namespace utils {
[[noreturn]] void die(const std::string &message);
}