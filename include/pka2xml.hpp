#pragma once

#include <cryptopp/base64.h>
#include <cryptopp/cast.h>
#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/twofish.h>
#include <re2/re2.h>
#include <zlib.h>

#include <array>
#include <cstdlib>
#include <string>
#include <vector>
#include <iostream>

namespace pka2xml {

/**
 * @brief Uncompresses a buffer using zlib
 * 
 * The first four bytes of the input buffer must contain the uncompressed size
 * in big-endian format.
 * 
 * @param data Pointer to the compressed data
 * @param nbytes Size of the compressed data
 * @return std::string The uncompressed data
 * @throws int If decompression fails
 */
inline std::string uncompress(const unsigned char* data, int nbytes) {
    if (nbytes < 4) {
        throw Z_DATA_ERROR;
    }

    const unsigned long len = (data[0] << 24) |
                            (data[1] << 16) |
                            (data[2] << 8)  |
                            (data[3]);

    std::vector<unsigned char> buf(len);
    unsigned long actual_len = len;

    const int res = ::uncompress(buf.data(), &actual_len, data + 4, nbytes - 4);

    if (res != Z_OK) {
        throw res;
    }

    if (actual_len != len) {
        throw Z_DATA_ERROR;
    }

    return std::string(reinterpret_cast<const char*>(buf.data()), len);
}

/**
 * @brief Compresses a buffer using zlib
 * 
 * The first four bytes of the output buffer will contain the uncompressed size
 * in big-endian format.
 * 
 * @param data Pointer to the uncompressed data
 * @param nbytes Size of the uncompressed data
 * @return std::string The compressed data
 * @throws int If compression fails
 */
inline std::string compress(const unsigned char* data, int nbytes) {
    // Calculate maximum possible compressed size
    unsigned long len = nbytes + nbytes / 100 + 13;
    std::vector<unsigned char> buf(len + 4);

    // Compress the data
    const int res = ::compress2(buf.data() + 4, &len, data, nbytes, -1);
    if (res != Z_OK) {
        throw res;
    }

    // Resize buffer to actual compressed size + 4 bytes for length
    buf.resize(len + 4);

    // Store original size in first 4 bytes (big-endian)
    buf[0] = (nbytes & 0xff000000) >> 24;
    buf[1] = (nbytes & 0x00ff0000) >> 16;
    buf[2] = (nbytes & 0x0000ff00) >> 8;
    buf[3] = (nbytes & 0x000000ff);

    return std::string(reinterpret_cast<const char*>(buf.data()), buf.size());
}

/**
 * @brief Generic decryption function for Packet Tracer files
 * 
 * The decryption process consists of four stages:
 * 1. Deobfuscation: b[i] = a[l + ~i] ^ (l - i * l)
 * 2. Decryption: TwoFish/CAST256 in EAX mode
 * 3. Deobfuscation: b[i] = a[i] ^ (l - i)
 * 4. Decompression: zlib
 * 
 * @tparam Algorithm The encryption algorithm to use (TwoFish or CAST256)
 * @param input The encrypted input data
 * @param key The encryption key
 * @param iv The initialization vector
 * @return std::string The decrypted data
 */
template <typename Algorithm>
inline std::string decrypt(const std::string& input,
                          const std::array<unsigned char, 16>& key,
                          const std::array<unsigned char, 16>& iv) {
    typename CryptoPP::EAX<Algorithm>::Decryption d;
    d.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    const int length = input.size();
    std::string processed(length, '\0');
    std::string output;

    // Stage 1: Deobfuscation
    for (int i = 0; i < length; i++) {
        processed[i] = input[length + ~i] ^ (length - i * length);
    }

    // Stage 2: Decryption
    CryptoPP::StringSource ss(processed, true,
        new CryptoPP::AuthenticatedDecryptionFilter(d,
            new CryptoPP::StringSink(output)));

    // Stage 3: Deobfuscation
    for (size_t i = 0; i < output.size(); i++) {
        output[i] = output[i] ^ (output.size() - i);
    }

    // Stage 4: Decompression
    return uncompress(reinterpret_cast<const unsigned char*>(output.data()), output.size());
}

/**
 * @brief Simplified decryption function that only performs stages 1 and 2
 * 
 * @tparam Algorithm The encryption algorithm to use
 * @param input The encrypted input data
 * @param key The encryption key
 * @param iv The initialization vector
 * @return std::string The partially decrypted data
 */
template <typename Algorithm>
inline std::string decrypt2(const std::string& input,
                           const std::array<unsigned char, 16>& key,
                           const std::array<unsigned char, 16>& iv) {
    typename CryptoPP::EAX<Algorithm>::Decryption d;
    d.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    const int length = input.size();
    std::string processed(length, '\0');
    std::string output;

    // Stage 1: Deobfuscation
    for (int i = 0; i < length; i++) {
        processed[i] = input[length + ~i] ^ (length - i * length);
    }

    // Stage 2: Decryption
    CryptoPP::StringSource ss(processed, true,
        new CryptoPP::AuthenticatedDecryptionFilter(d,
            new CryptoPP::StringSink(output)));

    return output;
}

/**
 * @brief Decrypts a Packet Tracer file
 * 
 * Uses TwoFish encryption with key = {137}*16 and iv = {16}*16
 * 
 * @param input The encrypted input data
 * @return std::string The decrypted data
 */
inline std::string decrypt_pka(const std::string& input) {
    static const std::array<unsigned char, 16> key{137, 137, 137, 137, 137, 137, 137, 137,
                                                 137, 137, 137, 137, 137, 137, 137, 137};
    static const std::array<unsigned char, 16> iv{16, 16, 16, 16, 16, 16, 16, 16,
                                                16, 16, 16, 16, 16, 16, 16, 16};

    return decrypt<CryptoPP::Twofish>(input, key, iv);
}

/**
 * @brief Decrypts a Packet Tracer log file
 * 
 * The input must be base64 decoded before decryption.
 * Uses TwoFish encryption with key = {186}*16 and iv = {190}*16
 * 
 * @param input The base64 encoded and encrypted input data
 * @return std::string The decrypted data
 */
inline std::string decrypt_logs(const std::string& input) {
    static const std::array<unsigned char, 16> key{186, 186, 186, 186, 186, 186, 186, 186,
                                                 186, 186, 186, 186, 186, 186, 186, 186};
    static const std::array<unsigned char, 16> iv{190, 190, 190, 190, 190, 190, 190, 190,
                                                190, 190, 190, 190, 190, 190, 190, 190};

    std::string decoded;
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded)));

    return decrypt2<CryptoPP::Twofish>(decoded, key, iv);
}

/**
 * @brief Decrypts a Packet Tracer nets file
 * 
 * Uses TwoFish encryption with key = {186}*16 and iv = {190}*16
 * 
 * @param input The encrypted input data
 * @return std::string The decrypted data
 */
inline std::string decrypt_nets(const std::string& input) {
    static const std::array<unsigned char, 16> key{186, 186, 186, 186, 186, 186, 186, 186,
                                                 186, 186, 186, 186, 186, 186, 186, 186};
    static const std::array<unsigned char, 16> iv{190, 190, 190, 190, 190, 190, 190, 190,
                                                190, 190, 190, 190, 190, 190, 190, 190};

    return decrypt2<CryptoPP::Twofish>(input, key, iv);
}

/**
 * @brief Decrypts old format Packet Tracer files
 * 
 * Old Packet Tracer files used a simpler encryption method:
 * 1. XOR each byte with (length - position)
 * 2. Decompress with zlib
 * 
 * @param input The encrypted input data
 * @return std::string The decrypted data
 */
inline std::string decrypt_old(std::string input) {
    for (size_t i = 0; i < input.size(); i++) {
        input[i] = input[i] ^ (input.size() - i);
    }
    return uncompress(reinterpret_cast<const unsigned char*>(input.data()), input.size());
}

/**
 * @brief Encrypts data for Packet Tracer files
 * 
 * The encryption process consists of four stages:
 * 1. Compression: zlib
 * 2. Obfuscation: b[i] = a[i] ^ (l - i)
 * 3. Encryption: TwoFish/CAST256 in EAX mode
 * 4. Obfuscation: b[i] = a[l + ~i] ^ (l - i * l)
 * 
 * @tparam Algorithm The encryption algorithm to use
 * @param input The plaintext input data
 * @param key The encryption key
 * @param iv The initialization vector
 * @return std::string The encrypted data
 */
template <typename Algorithm>
inline std::string encrypt(const std::string& input,
                          const std::array<unsigned char, 16>& key,
                          const std::array<unsigned char, 16>& iv) {
    typename CryptoPP::EAX<Algorithm>::Encryption e;
    e.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    // Stage 1: Compression
    std::string compressed = compress(reinterpret_cast<const unsigned char*>(input.data()), input.size());

    // Stage 2: Obfuscation
    for (size_t i = 0; i < compressed.size(); i++) {
        compressed[i] = static_cast<unsigned char>(compressed[i] ^ key[i % key.size()]);
    }

    // Stage 3: Encryption
    std::string encrypted;
    CryptoPP::StringSource ss(compressed, true,
        new CryptoPP::AuthenticatedEncryptionFilter(e,
            new CryptoPP::StringSink(encrypted)));

    // Stage 4: Obfuscation
    const int length = encrypted.size();
    std::string output(length, '\0');
    for (size_t i = 0; i < encrypted.size(); i++) {
        output[length + ~i] = static_cast<unsigned char>(encrypted[i] ^ key[i % key.size()]);
    }

    return output;
}

/**
 * @brief Encrypts data for Packet Tracer files
 * 
 * Uses TwoFish encryption with key = {137}*16 and iv = {16}*16
 * 
 * @param input The plaintext input data
 * @return std::string The encrypted data
 */
inline std::string encrypt_pka(const std::string& input) {
    static const std::array<unsigned char, 16> key{137, 137, 137, 137, 137, 137, 137, 137,
                                                 137, 137, 137, 137, 137, 137, 137, 137};
    static const std::array<unsigned char, 16> iv{16, 16, 16, 16, 16, 16, 16, 16,
                                                16, 16, 16, 16, 16, 16, 16, 16};

    return encrypt<CryptoPP::Twofish>(input, key, iv);
}

/**
 * @brief Encrypts data for Packet Tracer nets files
 * 
 * Uses TwoFish encryption with key = {186}*16 and iv = {190}*16
 * 
 * @param input The plaintext input data
 * @return std::string The encrypted data
 */
inline std::string encrypt_nets(const std::string& input) {
    static const std::array<unsigned char, 16> key{186, 186, 186, 186, 186, 186, 186, 186,
                                                 186, 186, 186, 186, 186, 186, 186, 186};
    static const std::array<unsigned char, 16> iv{190, 190, 190, 190, 190, 190, 190, 190,
                                                190, 190, 190, 190, 190, 190, 190, 190};

    return encrypt<CryptoPP::Twofish>(input, key, iv);
}

/**
 * @brief Checks if a Packet Tracer file is in the old format
 * 
 * @param str The file contents to check
 * @return bool True if the file is in the old format
 */
inline bool is_old_pt(const std::string& str) {
    return str.size() > 0 && str[0] == '\x1f';
}

/**
 * @brief Fixes a Packet Tracer file to be readable by any version
 * 
 * @param input The file contents to fix
 * @return std::string The fixed file contents
 */
inline std::string fix(std::string input) {
    if (is_old_pt(input)) {
        return decrypt_old(input);
    }
    return input;
}

/**
 * @brief Modifies the user profile name in the XML content
 * 
 * @param xml The XML content to modify
 * @param new_name The new name to set
 * @param verbose Whether to show debug logs
 * @return std::string The modified XML content
 */
inline std::string modify_user_profile(const std::string& xml, const std::string& new_name, bool verbose = false) {
    if (xml.empty()) {
        return "";
    }

    if (verbose) {
        std::cout << "Starting modify_user_profile with XML size: " << xml.size() << std::endl;
        std::cout << "Searching for USER_PROFILE section..." << std::endl;
    }

    // Find the USER_PROFILE section
    size_t profile_start = xml.find("<USER_PROFILE>");
    size_t profile_end = xml.find("</USER_PROFILE>", profile_start);
    
    if (profile_start == std::string::npos || profile_end == std::string::npos) {
        if (verbose) std::cerr << "Error: Could not find USER_PROFILE section" << std::endl;
        return "";
    }
    
    if (verbose) {
        std::cout << "Found USER_PROFILE section at positions " << profile_start << " to " << profile_end << std::endl;
    }

    // Find the NAME tag within USER_PROFILE
    size_t name_start = xml.find("<NAME>", profile_start);
    size_t name_end = xml.find("</NAME>", name_start);
    
    if (name_start == std::string::npos || name_end == std::string::npos || name_start > profile_end) {
        if (verbose) std::cerr << "Error: Could not find NAME tag within USER_PROFILE" << std::endl;
        return "";
    }
    
    if (verbose) {
        std::cout << "Found NAME tag within USER_PROFILE at positions " << name_start << " and " << name_end << std::endl;
        std::cout << "Context around NAME tag in USER_PROFILE:" << std::endl;
        std::cout << xml.substr(name_start - 50, 100) << std::endl;
        std::cout << "Will replace with: <NAME>" << new_name << "</NAME>" << std::endl;
    }

    // Create the modified XML
    std::string result = xml;
    result.replace(name_start, name_end - name_start + 7, "<NAME>" + new_name + "</NAME>");
    
    if (verbose) {
        std::cout << "Replacement completed, verifying result..." << std::endl;
        std::cout << "Context after replacement:" << std::endl;
        std::cout << result.substr(name_start - 50, 100) << std::endl;
    }

    return result;
}

} // namespace pka2xml
