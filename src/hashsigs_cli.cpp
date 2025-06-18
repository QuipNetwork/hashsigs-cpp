#include "../include/keccak.h"
#include "../include/public_key.hpp"
#include "../include/wotsplus.hpp"
#include <array>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace hashsigs;

// Helper function to convert hex string to bytes
std::array<uint8_t, 32> hex_to_bytes(const std::string &hex) {
  std::array<uint8_t, 32> result{};
  std::string hex_clean = hex.substr(0, 2) == "0x" ? hex.substr(2) : hex;

  for (size_t i = 0; i < 32; ++i) {
    std::string byte_str = hex_clean.substr(i * 2, 2);
    result[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
  }
  return result;
}

// Helper function to convert bytes to hex string
std::string bytes_to_hex(const std::array<uint8_t, 32> &bytes) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (uint8_t byte : bytes) {
    ss << std::setw(2) << static_cast<int>(byte);
  }
  return ss.str();
}

// Helper function to convert signature to hex string
std::string
signature_to_hex(const std::vector<std::array<uint8_t, 32>> &signature) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (const auto &segment : signature) {
    for (uint8_t byte : segment) {
      ss << std::setw(2) << static_cast<int>(byte);
    }
  }
  return ss.str();
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
            << "  generate-keypair [private_key_hex]  - Generate a new key "
               "pair (or from existing private key)\n"
            << "  sign <private_key_hex> <message_hex> - Sign a message with a "
               "private key\n"
            << "  verify <public_key_hex> <message_hex> <signature_hex> - "
               "Verify a signature\n"
            << "  generate-test-data [private_key_hex] - Generate test data "
               "for e2e tests\n"
            << "\n"
            << "Output format: pubkey signature private_key (space-separated "
               "hex strings)\n";
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    print_usage();
    return 1;
  }

  std::string command = argv[1];
  WOTSPlus wots(keccak256);

  if (command == "generate-keypair") {
    std::array<uint8_t, 32> private_key;

    if (argc >= 3) {
      // Use provided private key
      private_key = hex_to_bytes(argv[2]);
    } else {
      // Generate random private key
      std::string random_hex =
          "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
      private_key = hex_to_bytes(random_hex);
    }

    auto public_key = wots.get_public_key(private_key);

    // Convert public key to hex format (public_seed + public_key_hash)
    auto public_seed = public_key.get_public_seed();
    auto public_key_hash = public_key.get_public_key_hash();

    std::string pubkey_hex =
        bytes_to_hex(public_seed) + bytes_to_hex(public_key_hash);
    std::string private_key_hex = bytes_to_hex(private_key);

    std::cout << pubkey_hex << " " << private_key_hex << std::endl;

  } else if (command == "sign") {
    if (argc < 4) {
      std::cerr
          << "Error: sign command requires private_key_hex and message_hex\n";
      return 1;
    }

    auto private_key = hex_to_bytes(argv[2]);
    auto message = hex_to_bytes(argv[3]);

    auto signature = wots.sign(private_key, message);
    std::string signature_hex = signature_to_hex(signature);

    std::cout << signature_hex << std::endl;

  } else if (command == "verify") {
    if (argc < 5) {
      std::cerr << "Error: verify command requires public_key_hex, "
                   "message_hex, and signature_hex\n";
      return 1;
    }

    std::string public_key_hex = argv[2];
    auto message = hex_to_bytes(argv[3]);
    std::string signature_hex = argv[4];

    // Parse public key (first 32 bytes = public_seed, last 32 bytes =
    // public_key_hash)
    std::array<uint8_t, 32> public_seed =
        hex_to_bytes(public_key_hex.substr(0, 64));
    std::array<uint8_t, 32> public_key_hash =
        hex_to_bytes(public_key_hex.substr(64, 64));
    PublicKey public_key(public_seed, public_key_hash);

    // Parse signature
    std::vector<std::array<uint8_t, 32>> signature;
    for (size_t i = 0; i < signature_hex.length(); i += 64) {
      std::string segment_hex = signature_hex.substr(i, 64);
      signature.push_back(hex_to_bytes(segment_hex));
    }

    bool is_valid = wots.verify(public_key, message, signature);
    std::cout << (is_valid ? "valid" : "invalid") << std::endl;

  } else if (command == "generate-test-data") {
    std::array<uint8_t, 32> private_key;

    if (argc >= 3) {
      // Use provided private key
      private_key = hex_to_bytes(argv[2]);
    } else {
      // Generate random private key
      std::string random_hex =
          "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
      private_key = hex_to_bytes(random_hex);
    }

    auto public_key = wots.get_public_key(private_key);

    // Create a unique test message based on the private key
    // Use the first 32 bytes of the private key as the message
    std::array<uint8_t, 32> message = private_key;

    // Sign the message
    auto signature = wots.sign(private_key, message);

    // Convert to hex format
    auto public_seed = public_key.get_public_seed();
    auto public_key_hash = public_key.get_public_key_hash();
    std::string pubkey_hex =
        bytes_to_hex(public_seed) + bytes_to_hex(public_key_hash);
    std::string signature_hex = signature_to_hex(signature);
    std::string private_key_hex = bytes_to_hex(private_key);

    // Output in format expected by e2e_test.sh: pubkey signature private_key
    std::cout << pubkey_hex << " " << signature_hex << " " << private_key_hex
              << std::endl;

  } else {
    std::cerr << "Unknown command: " << command << std::endl;
    print_usage();
    return 1;
  }

  return 0;
}