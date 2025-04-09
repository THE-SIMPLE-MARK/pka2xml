#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <memory>

#include "include/pka2xml.hpp"

namespace {

// Helper function to check if an option exists in argv
bool option_exists(char* begin[], char* end[], const std::string& option) {
    return std::find(begin, end, option) != end;
}

// Helper function to get option value
char* get_option_value(char* begin[], char* end[], const std::string& option) {
    auto it = std::find(begin, end, option);
    if (it != end && ++it != end) {
        return *it;
    }
    return nullptr;
}

// Error handling function
void die(const std::string& message) {
    std::cerr << "Error: " << message << std::endl;
    std::exit(1);
}

// RAII wrapper for file operations
class FileHandler {
public:
    FileHandler(const std::string& filename, std::ios_base::openmode mode)
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

    std::fstream& get() { return stream; }

private:
    std::fstream stream;
};

// Process input file and return its contents
std::string read_file_contents(const std::string& filename) {
    FileHandler file(filename, std::ios::in | std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(file.get()),
                      std::istreambuf_iterator<char>());
}

// Write contents to output file
void write_file_contents(const std::string& filename, const std::string& contents) {
    FileHandler file(filename, std::ios::out | std::ios::binary);
    file.get() << contents;
}

void print_help() {
    std::cout << R"(Usage: pka2xml [options]

Options:
  -d <in> <out>   Decrypt pka/pkt to xml
  -e <in> <out>   Encrypt xml to pka/pkt
  -f <in> <out>   Allow packet tracer file to be read by any version
  -nets <in>      Decrypt packet tracer "nets" file
  -logs <in>      Decrypt packet tracer log file
  --forge <out>   Forge authentication file to bypass login

Examples:
  pka2xml -d foobar.pka foobar.xml
  pka2xml -e foobar.xml foobar.pka
  pka2xml -nets $HOME/packettracer/nets
  pka2xml -logs $HOME/packettracer/pt_12.05.2020_21.07.17.338.log
)" << std::endl;
    std::exit(0);
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc == 1) {
        print_help();
    }

#ifdef HAS_UI
    if (argc > 1 && std::string(argv[1]) == "gui") {
        QApplication app(argc, argv);
        Gui gui{};
        gui.show();
        return app.exec();
    }
#endif

    try {
        if (argc > 3 && option_exists(argv, argv + argc, "-d")) {
            const std::string input = read_file_contents(argv[2]);
            write_file_contents(argv[3], pka2xml::decrypt_pka(input));
        }
        else if (argc > 3 && option_exists(argv, argv + argc, "-e")) {
            const std::string input = read_file_contents(argv[2]);
            write_file_contents(argv[3], pka2xml::encrypt_pka(input));
        }
        else if (argc > 2 && option_exists(argv, argv + argc, "-logs")) {
            FileHandler file(argv[2], std::ios::in);
            std::string line;
            while (std::getline(file.get(), line)) {
                std::cout << pka2xml::decrypt_logs(line) << std::endl;
            }
        }
        else if (argc > 2 && option_exists(argv, argv + argc, "-nets")) {
            const std::string input = read_file_contents(argv[2]);
            std::cout << pka2xml::decrypt_nets(input) << std::endl;
        }
        else if (argc > 2 && option_exists(argv, argv + argc, "--forge")) {
            write_file_contents(argv[2], pka2xml::encrypt_nets("foobar~foobar~foobar~foobar~1700000000"));
        }
        else if (argc > 3 && option_exists(argv, argv + argc, "-f")) {
            const std::string input = read_file_contents(argv[2]);
            write_file_contents(argv[3], pka2xml::fix(input));
        }
        else {
            print_help();
        }
    }
    catch (const std::exception& e) {
        die(e.what());
    }
    catch (...) {
        die("Unknown error occurred during file processing");
    }

    return 0;
}
