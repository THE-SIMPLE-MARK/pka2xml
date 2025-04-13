#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "include/pka2xml.hpp"

namespace {

// Helper function to check if an option exists in argv
bool option_exists(char *begin[], char *end[], const std::string &option) {
  return std::find(begin, end, option) != end;
}

// Helper function to get option values
char *get_option_value(char *begin[], char *end[], const std::string &option) {
  auto it = std::find(begin, end, option);
  if (it != end && ++it != end) {
    return *it;
  }
  return nullptr;
}

// Error handling function
void die(const std::string &message) {
  std::cerr << "Error: " << message << std::endl;
  std::exit(1);
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
    // -d: Decrypt pka/pkt to xml
    if (argc > 3 && option_exists(argv, argv + argc, "-d")) {
      if (verbose)
        std::cout << "Reading input file: " << argv[2] << std::endl;

      const std::string input = read_file_contents(argv[2]);
      if (verbose)
        std::cout << "Writing to output file: " << argv[3] << std::endl;

      write_file_contents(argv[3], pka2xml::decrypt_pka(input));

      if (verbose)
        std::cout << "Successfully decrypted file" << std::endl;
    }
    // -e: Encrypt xml to pka/pkt
    else if (argc > 3 && option_exists(argv, argv + argc, "-e")) {
      if (verbose)
        std::cout << "Reading input file: " << argv[2] << std::endl;

      const std::string input = read_file_contents(argv[2]);
      if (verbose)
        std::cout << "Writing to output file: " << argv[3] << std::endl;

      write_file_contents(argv[3], pka2xml::encrypt_pka(input));
      if (verbose)
        std::cout << "Successfully encrypted file" << std::endl;
    }
    // -logs: Decrypt packet tracer log file line by line
    else if (argc > 2 && option_exists(argv, argv + argc, "-logs")) {
      FileHandler file(argv[2], std::ios::in);
      std::string line;

      while (std::getline(file.get(), line)) {
        std::cout << pka2xml::decrypt_logs(line) << std::endl;
      }
    }
    // -nets: Decrypt packet tracer "nets" file
    else if (argc > 2 && option_exists(argv, argv + argc, "-nets")) {
      if (verbose)
        std::cout << "Reading input file: " << argv[2] << std::endl;

      const std::string input = read_file_contents(argv[2]);
      std::cout << pka2xml::decrypt_nets(input) << std::endl;
    }
    // --forge: Forge authentication file to bypass login
    else if (argc > 2 && option_exists(argv, argv + argc, "--forge")) {
      if (verbose)
        std::cout << "Creating forged authentication file: " << argv[2]
                  << std::endl;

      write_file_contents(
          argv[2],
          pka2xml::encrypt_nets("foobar~foobar~foobar~foobar~1700000000"));

      if (verbose)
        std::cout << "Successfully created forged file" << std::endl;
    }
    // -f: Allow packet tracer file to be read by any version (fix old
    // format)
    else if (argc > 3 && option_exists(argv, argv + argc, "-f")) {
      if (verbose)
        std::cout << "Reading input file: " << argv[2] << std::endl;

      const std::string input = read_file_contents(argv[2]);

      if (verbose)
        std::cout << "Writing to output file: " << argv[3] << std::endl;
      write_file_contents(argv[3], pka2xml::fix(input));

      if (verbose)
        std::cout << "Successfully fixed file" << std::endl;
    }
    // -r: Modify user profile name in pka/pkt file (creates new file)
    else if (argc > 3 && option_exists(argv, argv + argc, "-r")) {
      try {
        // Get the input filename and extension
        std::filesystem::path input_path(argv[2]);
        if (!std::filesystem::exists(input_path)) {
          die("Input file does not exist: " + std::string(argv[2]));
        }

        std::string stem = input_path.stem().string();
        std::string extension = input_path.extension().string();
        std::string new_filename = stem + "_" + argv[3] + extension;

        if (verbose)
          std::cout << "Reading input file: " << argv[2] << std::endl;

        const std::string input = read_file_contents(argv[2]);

        if (verbose)
          std::cout << "Input file size: " << input.size() << " bytes"
                    << std::endl;

        if (verbose)
          std::cout << "Decrypting file..." << std::endl;

        std::string xml = pka2xml::decrypt_pka(input);

        if (verbose)
          std::cout << "Decrypted XML size: " << xml.size() << " bytes"
                    << std::endl;

        if (xml.empty()) {
          die("Failed to decrypt the input file");
        }

        if (verbose)
          std::cout << "Modifying user profile name to: " << argv[3]
                    << std::endl;

        xml = pka2xml::modify_user_profile(xml, argv[3], verbose);

        if (xml.empty()) {
          die("Failed to modify user profile name");
        }

        if (verbose)
          std::cout << "Encrypting and writing to new file: " << new_filename
                    << std::endl;

        write_file_contents(new_filename, pka2xml::encrypt_pka(xml));

        std::cout << "Created: " << new_filename << std::endl;
      } catch (const std::exception &e) {
        if (verbose)
          std::cerr << "Detailed error: " << e.what() << std::endl;

        die("Error processing file: " + std::string(e.what()));
      }
    }
    // -rb: Batch modify user profile name in multiple pka/pkt files
    else if (argc > 3 && option_exists(argv, argv + argc, "-rb")) {
      // Find the name argument (first non-option argument after -rb)
      int name_index = 2;
      while (name_index < argc && argv[name_index][0] == '-') {
        name_index++;
      }

      if (name_index >= argc) {
        die("No name specified for -rb command");
      }

      std::string new_name = argv[name_index];

      if (verbose)
        std::cout << "Batch processing with new name: " << new_name
                  << std::endl;

      // Process all remaining arguments as files
      int success_count = 0;
      int fail_count = 0;

      for (int i = name_index + 1; i < argc; i++) {
        try {
          std::filesystem::path input_path(argv[i]);
          if (!std::filesystem::exists(input_path)) {
            std::cerr << "Warning: Input file does not exist: " << argv[i]
                      << std::endl;
            fail_count++;
            continue;
          }

          std::string stem = input_path.stem().string();
          std::string extension = input_path.extension().string();
          std::string new_filename = stem + "_" + new_name + extension;

          if (verbose)
            std::cout << "\nProcessing file " << (i - name_index) << "/"
                      << (argc - name_index - 1) << ": " << argv[i]
                      << std::endl;

          // Read and decrypt the input file
          const std::string input = read_file_contents(argv[i]);
          std::string xml = pka2xml::decrypt_pka(input);

          if (xml.empty()) {
            std::cerr << "Error: Failed to decrypt file: " << argv[i]
                      << std::endl;

            fail_count++;
            continue;
          }

          // Modify the user profile name
          xml = pka2xml::modify_user_profile(xml, new_name, verbose);

          if (xml.empty()) {
            std::cerr << "Error: Failed to modify user profile name in file: "
                      << argv[i] << std::endl;

            fail_count++;
            continue;
          }

          // Write the modified file
          write_file_contents(new_filename, pka2xml::encrypt_pka(xml));
          if (verbose) {
            std::cout << "Successfully created: " << new_filename << std::endl;
          } else {
            std::cout << "Created: " << new_filename << std::endl;
          }
          success_count++;

        } catch (const std::exception &e) {
          std::cerr << "Error processing file " << argv[i] << ": " << e.what()
                    << std::endl;

          fail_count++;
        }
      }

      // Print summary
      std::cout << "\nProcessed " << success_count << " files";
      if (fail_count > 0) {
        std::cout << " (" << fail_count << " failed)";
      }
      std::cout << std::endl;
    }
    // -rbm: Create multiple variations of a file with different names
    else if (argc > 3 && option_exists(argv, argv + argc, "-rbm")) {
      try {
        // Get the input filename and extension
        std::filesystem::path input_path(argv[2]);
        if (!std::filesystem::exists(input_path)) {
          die("Input file does not exist: " + std::string(argv[2]));
        }

        std::string stem = input_path.stem().string();
        std::string extension = input_path.extension().string();

        if (verbose)
          std::cout << "Reading input file: " << argv[2] << std::endl;
        const std::string input = read_file_contents(argv[2]);
        if (verbose)
          std::cout << "Input file size: " << input.size() << " bytes"
                    << std::endl;

        if (verbose)
          std::cout << "Decrypting file..." << std::endl;
        std::string xml = pka2xml::decrypt_pka(input);
        if (verbose)
          std::cout << "Decrypted XML size: " << xml.size() << " bytes"
                    << std::endl;

        if (xml.empty()) {
          die("Failed to decrypt the input file");
        }

        // Process each name argument
        int success_count = 0;
        int fail_count = 0;

        for (int i = 3; i < argc; i++) {
          try {
            std::string new_name = argv[i];
            std::string new_filename = stem + "_" + new_name + extension;

            if (verbose)
              std::cout << "\nProcessing name " << (i - 2) << "/" << (argc - 3)
                        << ": " << new_name << std::endl;

            // Modify the user profile name
            std::string modified_xml =
                pka2xml::modify_user_profile(xml, new_name, verbose);

            if (modified_xml.empty()) {
              std::cerr << "Error: Failed to modify user profile name to: "
                        << new_name << std::endl;
              fail_count++;
              continue;
            }

            // Write the modified file
            write_file_contents(new_filename,
                                pka2xml::encrypt_pka(modified_xml));

            if (verbose) {
              std::cout << "Successfully created: " << new_filename
                        << std::endl;

            } else {
              std::cout << "Created: " << new_filename << std::endl;
            }
            success_count++;

          } catch (const std::exception &e) {
            std::cerr << "Error processing name " << argv[i] << ": " << e.what()
                      << std::endl;
            fail_count++;
          }
        }

        // Print summary
        std::cout << "\nCreated " << success_count << " files";
        if (fail_count > 0) {
          std::cout << " (" << fail_count << " failed)";
        }
        std::cout << std::endl;

      } catch (const std::exception &e) {
        if (verbose)
          std::cerr << "Detailed error: " << e.what() << std::endl;

        die("Error processing file: " + std::string(e.what()));
      }
    } else {
      print_help();
    }
  } catch (const std::exception &e) {
    die(e.what());
  } catch (...) {
    die("Unknown error occurred during file processing");
  }

  return 0;
}
