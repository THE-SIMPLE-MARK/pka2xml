#pragma once

#include "../include/utils.hpp"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace pka2xml {
std::string decrypt_pka(const std::string &input);
std::string encrypt_pka(const std::string &input);
std::string decrypt_logs(const std::string &input);
std::string decrypt_nets(const std::string &input);
std::string encrypt_nets(const std::string &input);
std::string fix(std::string input);
std::string modify_user_profile(const std::string &xml,
                                const std::string &new_name, bool verbose);
} // namespace pka2xml

std::string read_file_contents(const std::string &filename);
void write_file_contents(const std::string &filename,
                         const std::string &contents);

namespace handlers {

void handle_decrypt(const char *infile, const char *outfile, bool verbose);
void handle_encrypt(const char *infile, const char *outfile, bool verbose);
void handle_logs(const char *infile, bool verbose);
void handle_nets(const char *infile, bool verbose);
void handle_forge(const char *outfile, bool verbose);
void handle_fix(const char *infile, const char *outfile, bool verbose);
void handle_rename(const char *infile, const char *new_name_arg, bool verbose);
void handle_batch_rename(int argc, char *argv[], int name_index, bool verbose);
void handle_batch_rename_multiple(const char *infile, int argc, char *argv[],
                                  bool verbose);

} // namespace handlers