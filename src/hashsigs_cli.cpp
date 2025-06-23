#include "../include/keccak.h"
#include "../include/wotsplus.hpp"
#include <array>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace hashsigs;

// Helper function to convert hex string to bytes
template <size_t N>
std::array<uint8_t, N> hex_to_bytes_template(const std::string &hex) {
  std::array<uint8_t, N> result{};
  std::string hex_clean = hex.substr(0, 2) == "0x" ? hex.substr(2) : hex;

  for (size_t i = 0; i < N; ++i) {
    std::string byte_str = hex_clean.substr(i * 2, 2);
    result[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
  }
  return result;
}

std::array<uint8_t, 32> hex_to_bytes(const std::string &hex) {
  return hex_to_bytes_template<32>(hex);
}

// Helper function to convert bytes to hex string
std::string bytes_to_hex(const std::vector<uint8_t> &bytes) {
  std::stringstream ss;
  ss << "0x";
  for (const auto &byte : bytes) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(byte);
  }
  return ss.str();
}

std::string
bytes_to_hex(const std::array<uint8_t, constants::HASH_LEN> &bytes) {
  return bytes_to_hex(std::vector<uint8_t>(bytes.begin(), bytes.end()));
}

std::string bytes_to_hex(
    const std::vector<std::array<uint8_t, constants::HASH_LEN>> &vec_of_arr) {
  std::vector<uint8_t> flat_vec;
  for (const auto &arr : vec_of_arr) {
    flat_vec.insert(flat_vec.end(), arr.begin(), arr.end());
  }
  return bytes_to_hex(flat_vec);
}

// Keccak-256 hash function implementation
std::array<uint8_t, 32> keccak256(const std::vector<uint8_t> &data) {
  Keccak keccak(Keccak::Keccak256);
  std::string hash = keccak(data.data(), data.size());

  std::array<uint8_t, 32> result;
  for (size_t i = 0; i < 32; ++i) {
    std::string byte_str = hash.substr(i * 2, 2);
    result[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
  }
  return result;
}

void print_usage() {
  std::cout << "Usage: hashsigs_cli <command> [options]\n"
            << "Commands:\n"
            << "  generate-keypair <private_seed_hex> <public_seed_hex> - "
               "Generate a new key pair from existing seeds\n"
            << "  sign <private_key_hex> <public_seed_hex> <message_hex> - "
               "Sign a message with a "
               "private key and public seed\n"
            << "  verify <public_key_hex> <message_hex> <signature_hex> - "
               "Verify a signature\n";
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    print_usage();
    return 1;
  }

  std::string command = argv[1];
  WOTSPlus wots(keccak256);

  if (command == "generate-keypair") {
    if (argc != 4) {
      std::cerr << "Usage: " << argv[0]
                << " generate-keypair <private_seed_hex> <public_seed_hex>"
                << std::endl;
      return 1;
    }
    auto private_seed_arr = hex_to_bytes(argv[2]);
    std::vector<uint8_t> private_seed_vec(private_seed_arr.begin(),
                                          private_seed_arr.end());
    auto public_seed = hex_to_bytes(argv[3]);

    auto [public_key, private_key] =
        wots.generate_key_pair(private_seed_vec, public_seed);

    std::cout << "Public Key: "
              << bytes_to_hex(
                     std::vector<uint8_t>(public_key.begin(), public_key.end()))
              << std::endl;
    std::cout << "Private Key: " << bytes_to_hex(private_key) << std::endl;

  } else if (command == "sign") {
    if (argc < 5) {
      std::cerr << "Error: sign command requires private_key_hex, "
                   "public_seed_hex, and message_hex\n";
      return 1;
    }

    // Parse private key as vector of arrays
    std::vector<std::array<uint8_t, 32>> private_key;
    auto priv_bytes_vec = hex_to_bytes(argv[2]);
    for (size_t i = 0; i < priv_bytes_vec.size(); i += 32) {
      std::array<uint8_t, 32> segment;
      std::copy_n(priv_bytes_vec.begin() + i, 32, segment.begin());
      private_key.push_back(segment);
    }
    auto public_seed = hex_to_bytes(argv[3]);
    auto message = hex_to_bytes(argv[4]);

    auto signature = wots.sign(private_key, public_seed, message);

    std::cout << "Signature: " << bytes_to_hex(signature) << std::endl;

  } else if (command == "verify") {
    if (argc < 5) {
      std::cerr << "Error: verify command requires public_key_hex, "
                   "message_hex, and signature_hex\n";
      return 1;
    }

    std::string public_key_hex = argv[2];
    auto message = hex_to_bytes(argv[3]);
    std::string signature_hex = argv[4];

    // Parse public key
    auto public_key = hex_to_bytes_template<64>(public_key_hex);

    // Parse signature
    std::vector<std::array<uint8_t, 32>> signature;
    auto sig_bytes_vec = hex_to_bytes(signature_hex);
    for (size_t i = 0; i < sig_bytes_vec.size(); i += 32) {
      std::array<uint8_t, 32> segment;
      std::copy_n(sig_bytes_vec.begin() + i, 32, segment.begin());
      signature.push_back(segment);
    }

    bool is_valid = wots.verify(public_key, message, signature);
    std::cout << (is_valid ? "valid" : "invalid") << std::endl;

  } else {
    std::cerr << "Unknown command: " << command << std::endl;
    print_usage();
    return 1;
  }

  return 0;
}