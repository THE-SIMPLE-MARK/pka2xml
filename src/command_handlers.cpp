#include "../include/command_handlers.hpp"
#include "../include/main.hpp"
#include "../include/utils.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

// RAII wrapper for file operations
class FileHandler {
public:
  FileHandler(const std::string &filename, std::ios_base::openmode mode)
      : stream(filename,
               mode | std::ios::binary) { // Always use binary for consistency
    if (!stream.is_open()) {
      // Use std::system_error for better file error reporting potentially
      throw std::runtime_error("Failed to open file: " + filename);
    }
  }

  ~FileHandler() = default; // Let compiler handle closing if stream is RAII
                            // std::fstream handles closing in its destructor.
  FileHandler(const FileHandler &) = delete;
  FileHandler &operator=(const FileHandler &) = delete;
  FileHandler(FileHandler &&) = delete;
  FileHandler &operator=(FileHandler &&) = delete;

  std::fstream &get() { return stream; }

private:
  std::fstream stream;
};

// Process input file and return its contents
std::string read_file_contents(const std::string &filename) {
  try {
    FileHandler file(filename, std::ios::in);
    // Efficient way to read whole file
    return std::string(std::istreambuf_iterator<char>(file.get()),
                       std::istreambuf_iterator<char>());
  } catch (const std::exception &e) {
    utils::die("Error reading file " + filename + ": " + e.what());
  }
}

// Write contents to output file
void write_file_contents(const std::string &filename,
                         const std::string &contents) {
  try {
    FileHandler file(filename, std::ios::out);
    file.get().write(contents.data(), contents.size());
    if (!file.get()) { // Check for write errors
      throw std::runtime_error("Failed to write all data to file: " + filename);
    }
  } catch (const std::exception &e) {
    utils::die("Error writing file " + filename + ": " + e.what());
  }
}

namespace handlers {

void handle_decrypt(const char *infile, const char *outfile, bool verbose) {
  if (verbose)
    std::cout << "Reading input file: " << infile << std::endl;
  const std::string input = read_file_contents(infile);
  if (verbose)
    std::cout << "Writing to output file: " << outfile << std::endl;
  write_file_contents(outfile, pka2xml::decrypt_pka(input));
  if (verbose)
    std::cout << "Successfully decrypted file" << std::endl;
}

void handle_encrypt(const char *infile, const char *outfile, bool verbose) {
  if (verbose)
    std::cout << "Reading input file: " << infile << std::endl;
  const std::string input = read_file_contents(infile);
  if (verbose)
    std::cout << "Writing to output file: " << outfile << std::endl;
  write_file_contents(outfile, pka2xml::encrypt_pka(input));
  if (verbose)
    std::cout << "Successfully encrypted file" << std::endl;
}

void handle_logs(const char *infile, bool /*verbose*/) {
  // FileHandler is RAII, no need for manual close/check
  // std::fstream handles binary/text mode automatically on different OS
  std::ifstream file(infile);
  if (!file.is_open()) {
    utils::die("Failed to open log file: " + std::string(infile));
  }
  std::string line;
  while (std::getline(file, line)) {
    std::cout << pka2xml::decrypt_logs(line) << std::endl;
  }
}

void handle_nets(const char *infile, bool verbose) {
  if (verbose)
    std::cout << "Reading input file: " << infile << std::endl;
  const std::string input = read_file_contents(infile);
  // Assuming decrypt_nets returns printable output
  std::cout << pka2xml::decrypt_nets(input) << std::endl;
}

void handle_forge(const char *outfile, bool verbose) {
  if (verbose)
    std::cout << "Creating forged authentication file: " << outfile
              << std::endl;
  // Ensure the forged string is correct
  write_file_contents(
      outfile, pka2xml::encrypt_nets("foobar~foobar~foobar~foobar~1700000000"));
  if (verbose)
    std::cout << "Successfully created forged file" << std::endl;
}

void handle_fix(const char *infile, const char *outfile, bool verbose) {
  if (verbose)
    std::cout << "Reading input file: " << infile << std::endl;
  const std::string input = read_file_contents(infile);
  if (verbose)
    std::cout << "Writing to output file: " << outfile << std::endl;
  // pka2xml::fix might modify input string, ensure it handles const correctly
  // if needed Assuming pka2xml::fix returns the fixed content
  write_file_contents(outfile, pka2xml::fix(input));
  if (verbose)
    std::cout << "Successfully fixed file" << std::endl;
}

void handle_rename(const char *infile, const char *new_name_arg, bool verbose) {
  try {
    std::filesystem::path input_path(infile);
    if (!std::filesystem::exists(input_path)) {
      // Use die for consistency
      utils::die("Input file does not exist: " + std::string(infile));
    }

    std::string stem = input_path.stem().string();
    std::string extension = input_path.extension().string();
    // Check if new_name_arg is empty?
    if (std::string(new_name_arg).empty()) {
      utils::die("New name cannot be empty.");
    }
    std::string new_filename = stem + "_" + new_name_arg + extension;

    if (verbose)
      std::cout << "Reading input file: " << infile << std::endl;
    const std::string input = read_file_contents(infile);
    if (verbose)
      std::cout << "Input file size: " << input.size() << " bytes" << std::endl;

    if (verbose)
      std::cout << "Decrypting file..." << std::endl;
    std::string xml = pka2xml::decrypt_pka(input);
    if (verbose)
      std::cout << "Decrypted XML size: " << xml.size() << " bytes"
                << std::endl;

    if (xml.empty()) {
      utils::die("Failed to decrypt the input file: " + std::string(infile));
    }

    if (verbose)
      std::cout << "Modifying user profile name to: " << new_name_arg
                << std::endl;
    xml = pka2xml::modify_user_profile(xml, new_name_arg, verbose);
    if (xml.empty()) {
      utils::die("Failed to modify user profile name in file: " +
                 std::string(infile));
    }

    if (verbose)
      std::cout << "Encrypting and writing to new file: " << new_filename
                << std::endl;
    write_file_contents(new_filename, pka2xml::encrypt_pka(xml));
    std::cout << "Created: " << new_filename << std::endl;

  } catch (const std::filesystem::filesystem_error &e) {
    utils::die("Filesystem error: " + std::string(e.what()));
  } catch (const std::exception &e) {
    // Catch specific exceptions if possible
    if (verbose)
      std::cerr << "Detailed error in rename: " << e.what() << std::endl;
    // Provide more context in die message
    utils::die("Error processing file " + std::string(infile) +
               " for rename: " + std::string(e.what()));
  }
}

void handle_batch_rename(int argc, char *argv[], int name_index, bool verbose) {
  std::string new_name = argv[name_index];
  if (new_name.empty()) {
    utils::die("New name for batch rename cannot be empty.");
  }
  if (verbose)
    std::cout << "Batch processing with new name: " << new_name << std::endl;

  int success_count = 0;
  int fail_count = 0;
  int file_count = argc - name_index - 1;

  for (int i = name_index + 1; i < argc; i++) {
    const char *current_infile = argv[i];
    if (verbose)
      std::cout << "\nProcessing file " << (i - name_index) << "/" << file_count
                << ": " << current_infile << std::endl;

    try {
      std::filesystem::path input_path(current_infile);
      if (!std::filesystem::exists(input_path)) {
        // Log warning but continue
        std::cerr << "Warning: Input file does not exist: " << current_infile
                  << std::endl;
        fail_count++;
        continue;
      }

      std::string stem = input_path.stem().string();
      std::string extension = input_path.extension().string();
      std::string new_filename = stem + "_" + new_name + extension;

      const std::string input = read_file_contents(current_infile);
      if (verbose)
        std::cout << "  Input size: " << input.size() << " bytes" << std::endl;

      std::string xml = pka2xml::decrypt_pka(input);
      if (xml.empty()) {
        std::cerr << "Error: Failed to decrypt file: " << current_infile
                  << std::endl;
        fail_count++;
        continue;
      }
      if (verbose)
        std::cout << "  Decrypted size: " << xml.size() << " bytes"
                  << std::endl;

      xml = pka2xml::modify_user_profile(xml, new_name, verbose);
      if (xml.empty()) {
        std::cerr << "Error: Failed to modify user profile name in file: "
                  << current_infile << std::endl;
        fail_count++;
        continue;
      }

      write_file_contents(new_filename, pka2xml::encrypt_pka(xml));
      if (verbose) {
        std::cout << "  Successfully created: " << new_filename << std::endl;
      } else {
        std::cout << "Created: " << new_filename << std::endl;
      }
      success_count++;

    } catch (const std::filesystem::filesystem_error &e) {
      std::cerr << "Error processing file " << current_infile
                << ": Filesystem error - " << e.what() << std::endl;
      fail_count++;
    } catch (const std::exception &e) {
      std::cerr << "Error processing file " << current_infile << ": "
                << e.what() << std::endl;
      fail_count++;
    }
  }

  // Print summary
  std::cout << "\nBatch Rename Summary: Processed " << success_count
            << " files successfully";
  if (fail_count > 0) {
    std::cout << ", " << fail_count << " failed";
  }
  std::cout << "." << std::endl;
}

void handle_batch_rename_multiple(const char *infile, int argc, char *argv[],
                                  bool verbose) {
  try {
    std::filesystem::path input_path(infile);
    if (!std::filesystem::exists(input_path)) {
      utils::die("Input file for -rbm does not exist: " + std::string(infile));
    }

    std::string stem = input_path.stem().string();
    std::string extension = input_path.extension().string();

    if (verbose)
      std::cout << "Reading base file for -rbm: " << infile << std::endl;
    const std::string input = read_file_contents(infile);
    if (verbose)
      std::cout << "  Input file size: " << input.size() << " bytes"
                << std::endl;

    std::string base_xml = pka2xml::decrypt_pka(input);
    if (base_xml.empty()) {
      utils::die("Failed to decrypt the base input file: " +
                 std::string(infile));
    }
    if (verbose)
      std::cout << "  Decrypted base XML size: " << base_xml.size() << " bytes"
                << std::endl;

    int success_count = 0;
    int fail_count = 0;
    int name_count = argc - 3;

    for (int i = 3; i < argc; i++) { // Names start from argv[3]
      const char *current_name = argv[i];
      if (std::string(current_name).empty()) {
        std::cerr << "Warning: Skipping empty name provided for -rbm."
                  << std::endl;
        fail_count++;
        continue;
      }
      if (verbose)
        std::cout << "\nProcessing name " << (i - 2) << "/" << name_count
                  << ": " << current_name << std::endl;

      try {
        std::string new_filename = stem + "_" + current_name + extension;

        // Use a copy of the base XML for modification
        std::string modified_xml =
            pka2xml::modify_user_profile(base_xml, current_name, verbose);
        if (modified_xml.empty()) {
          std::cerr << "Error: Failed to modify user profile name to: "
                    << current_name << " for base file " << infile << std::endl;
          fail_count++;
          continue;
        }

        write_file_contents(new_filename, pka2xml::encrypt_pka(modified_xml));
        if (verbose) {
          std::cout << "  Successfully created: " << new_filename << std::endl;
        } else {
          std::cout << "Created: " << new_filename << std::endl;
        }
        success_count++;

      } catch (const std::exception &e) {
        std::cerr << "Error processing name \"" << current_name
                  << "\": " << e.what() << std::endl;
        fail_count++;
      }
    }

    // Print summary
    std::cout << "\nBatch Rename Multiple Summary: Created " << success_count
              << " files successfully";
    if (fail_count > 0) {
      std::cout << ", " << fail_count << " failed/skipped";
    }
    std::cout << "." << std::endl;

  } catch (const std::filesystem::filesystem_error &e) {
    utils::die("Filesystem error during -rbm setup: " + std::string(e.what()));
  } catch (const std::exception &e) {
    if (verbose)
      std::cerr << "Detailed error in batch rename multiple: " << e.what()
                << std::endl;
    utils::die("Error processing base file " + std::string(infile) +
               " for -rbm: " + std::string(e.what()));
  }
}

} // namespace handlers