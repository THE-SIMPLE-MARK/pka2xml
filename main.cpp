#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "include/command_handlers.hpp"
#include "include/main.hpp"
#include "include/utils.hpp"

namespace {

bool option_exists(char *begin[], char *end[], const std::string &option) {
  return std::find(begin, end, option) != end;
}

char *get_option_value(char *begin[], char *end[], const std::string &option) {
  auto it = std::find(begin, end, option);
  if (it != end && ++it != end) {
    return *it;
  }
  return nullptr;
}

// RAII wrapper for file operations
class FileHandler {
public:
  FileHandler(const std::string &filename, std::ios_base::openmode mode)
      : stream(filename, mode) {
    if (!stream.is_open()) {
      throw std::runtime_error("Failed to open file: " + filename);
    }
  }

  ~FileHandler() {
    if (stream.is_open()) {
      stream.close();
    }
  }

  std::fstream &get() { return stream; }

private:
  std::fstream stream;
};

// Process input file and return its contents
std::string read_file_contents(const std::string &filename) {
  FileHandler file(filename, std::ios::in | std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(file.get()),
                     std::istreambuf_iterator<char>());
}

// Write contents to output file
void write_file_contents(const std::string &filename,
                         const std::string &contents) {
  FileHandler file(filename, std::ios::out | std::ios::binary);
  file.get() << contents;
}

void print_help() {
  std::cout << R"(Usage: pka2xml [options]

Options:
  -d <in> <out>						Decrypt pka/pkt to xml
  -e <in> <out>						Encrypt xml to pka/pkt
  -f <in> <out>						Allow packet tracer file to be read by any version
  -nets <in>							Decrypt packet tracer "nets" file
  -logs <in>							Decrypt packet tracer log file
  -r <in> <name>					Modify user profile name in pka/pkt file (creates new file)
  -rb <name> <files...>		Batch modify user profile name in multiple pka/pkt files
  -rbm <in> <names...>		Create multiple variations of a file with different names
  --forge <out>						Forge authentication file to bypass login
  -v											Verbose output

Examples:
  pka2xml -d foobar.pka foobar.xml
  pka2xml -e foobar.xml foobar.pka
  pka2xml -nets $HOME/packettracer/nets
  pka2xml -logs $HOME/packettracer/pt_12.05.2020_21.07.17.338.log
  pka2xml -r file.pka "New Name"
  pka2xml -rb "New Name" file1.pka file2.pka file3.pka
  pka2xml -rbm file.pka "Name1" "Name2" "Name3"
)" << std::endl;
  std::exit(0);
}

} // namespace

int main(int argc, char *argv[]) {
  if (argc == 1) {
    print_help();
  }

  // Check for verbose flag
  bool verbose = option_exists(argv, argv + argc, "-v");

  try {
    if (option_exists(argv, argv + argc, "-d")) {
      if (argc > 3) {
        handlers::handle_decrypt(argv[2], argv[3], verbose);
      } else {
        utils::die(
            "Insufficient arguments for -d. Usage: pka2xml -d <in> <out>");
      }
    } else if (option_exists(argv, argv + argc, "-e")) {
      if (argc > 3) {
        handlers::handle_encrypt(argv[2], argv[3], verbose);
      } else {
        utils::die(
            "Insufficient arguments for -e. Usage: pka2xml -e <in> <out>");
      }
    } else if (option_exists(argv, argv + argc, "-logs")) {
      if (argc > 2) {
        handlers::handle_logs(argv[2], verbose);
      } else {
        utils::die(
            "Insufficient arguments for -logs. Usage: pka2xml -logs <in>");
      }
    } else if (option_exists(argv, argv + argc, "-nets")) {
      if (argc > 2) {
        handlers::handle_nets(argv[2], verbose);
      } else {
        utils::die(
            "Insufficient arguments for -nets. Usage: pka2xml -nets <in>");
      }
    } else if (option_exists(argv, argv + argc, "--forge")) {
      if (argc > 2) {
        handlers::handle_forge(argv[2], verbose);
      } else {
        utils::die(
            "Insufficient arguments for --forge. Usage: pka2xml --forge <out>");
      }
    } else if (option_exists(argv, argv + argc, "-f")) {
      if (argc > 3) {
        handlers::handle_fix(argv[2], argv[3], verbose);
      } else {
        utils::die(
            "Insufficient arguments for -f. Usage: pka2xml -f <in> <out>");
      }
    } else if (option_exists(argv, argv + argc, "-r")) {
      if (argc > 3) {
        handlers::handle_rename(argv[2], argv[3], verbose);
      } else {
        utils::die(
            "Insufficient arguments for -r. Usage: pka2xml -r <in> <name>");
      }
    } else if (option_exists(argv, argv + argc, "-rb")) {
      // Find the name argument index
      int name_index = 2;
      while (name_index < argc && argv[name_index][0] == '-') {
        name_index++;
      }

      if (name_index >= argc) {
        utils::die(
            "No name specified for -rb command. Usage: pka2xml -rb <name> "
            "<files...>");
      }
      if (argc <= name_index + 1) {
        utils::die(
            "No input files specified for -rb command. Usage: pka2xml -rb "
            "<name> <files...>");
      }
      handlers::handle_batch_rename(argc, argv, name_index, verbose);

    } else if (option_exists(argv, argv + argc, "-rbm")) {
      if (argc < 4) { // Need at least pka2xml -rbm <infile> <name1>
        utils::die("Insufficient arguments for -rbm. Usage: pka2xml -rbm <in> "
                   "<names...>");
      }
      handlers::handle_batch_rename_multiple(argv[2], argc, argv, verbose);
    } else {
      // If no known option matches (and argc > 1), or if only -v is present
      if (argc > 1 && !(argc == 2 && verbose)) {
        print_help();
      } else if (argc == 1) {
        print_help();
      }
    }
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  } catch (...) {
    std::cerr << "Error: Unknown error occurred during file processing"
              << std::endl;
    return 1;
  }

  return 0;
}
