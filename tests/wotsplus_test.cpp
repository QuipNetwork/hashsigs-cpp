#include "keccak.h"
#include "public_key.hpp"
#include "wotsplus.hpp"
#include <fstream>
#include <gtest/gtest.h>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>

using json = nlohmann::json;

namespace hashsigs {
namespace test {

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

// Keccak-256 hash function implementation using local Keccak
std::array<uint8_t, 32> keccak256(const std::vector<uint8_t> &data) {
  Keccak keccak(Keccak::Keccak256);
  std::string hash = keccak(data.data(), data.size());

  // Convert hex string to bytes
  std::array<uint8_t, 32> result;
  for (size_t i = 0; i < 32; ++i) {
    std::string byte_str = hash.substr(i * 2, 2);
    result[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
  }
  return result;
}

TEST(WOTSPlusTest, TestVectors) {
  // Read the test vectors file
  std::ifstream file("wotsplus_keccak256.json");
  if (!file.is_open()) {
    file.open("test_vectors/wotsplus_keccak256.json");
  }
  if (!file.is_open()) {
    file.open("tests/test_vectors/wotsplus_keccak256.json");
  }
  ASSERT_TRUE(file.is_open())
      << "Failed to open test vectors file in any of the expected locations";

  json vectors;
  file >> vectors;

  // Create WOTSPlus instance with our local Keccak implementation
  WOTSPlus wots(keccak256);

  // Iterate through each test vector
  for (const auto &[vector_name, vector] : vectors.items()) {
    std::cout << "Testing " << vector_name << std::endl;

    // Convert hex strings to bytes
    auto private_key = hex_to_bytes(vector["privateKey"].get<std::string>());
    auto message = hex_to_bytes(vector["message"].get<std::string>());
    auto expected_public_key_hex = vector["publicKey"].get<std::string>();

    // Split into public seed and public key hash
    std::array<uint8_t, 32> public_seed;
    std::array<uint8_t, 32> public_key_hash;

    std::string hex_clean = expected_public_key_hex.substr(0, 2) == "0x"
                                ? expected_public_key_hex.substr(2)
                                : expected_public_key_hex;

    for (size_t i = 0; i < 32; ++i) {
      std::string byte_str = hex_clean.substr(i * 2, 2);
      public_seed[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));

      byte_str = hex_clean.substr((i + 32) * 2, 2);
      public_key_hash[i] =
          static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
    }

    PublicKey expected_public_key(public_seed, public_key_hash);

    // Convert signature segments to bytes
    std::vector<std::array<uint8_t, 32>> expected_signature;
    for (const auto &seg : vector["signature"]) {
      expected_signature.push_back(hex_to_bytes(seg.get<std::string>()));
    }

    // Generate key pair and verify it matches expected public key
    auto public_key = wots.get_public_key(private_key);

    // Compare public key
    EXPECT_EQ(public_key.get_public_seed(),
              expected_public_key.get_public_seed())
        << "Public seed mismatch for " << vector_name;
    EXPECT_EQ(public_key.get_public_key_hash(),
              expected_public_key.get_public_key_hash())
        << "Public key hash mismatch for " << vector_name;

    // Sign message and verify signature matches expected signature
    auto signature = wots.sign(private_key, message);

    // Compare signature
    EXPECT_EQ(signature, expected_signature)
        << "Signature mismatch for " << vector_name;

    // Verify signature
    bool is_valid = wots.verify(public_key, message, signature);
    EXPECT_TRUE(is_valid) << "Signature verification failed for "
                          << vector_name;
  }
}

} // namespace test
} // namespace hashsigs