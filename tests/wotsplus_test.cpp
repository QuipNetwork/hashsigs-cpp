#include "keccak.h"
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

// Helper to convert number to byte array
std::array<uint8_t, 32> number_to_bytes(uint64_t num) {
  std::array<uint8_t, 32> bytes{};
  for (int i = 0; i < 8; ++i) {
    bytes[31 - i] = (num >> (i * 8)) & 0xFF;
  }
  return bytes;
}

TEST(WOTSPlusTest, GenerateKeyPair) {
  WOTSPlus wots(keccak256);
  auto private_seed_arr = number_to_bytes(1);
  std::vector<uint8_t> private_seed_vec(private_seed_arr.begin(),
                                        private_seed_arr.end());
  auto public_seed = number_to_bytes(2);

  auto [public_key, private_key] =
      wots.generate_key_pair(private_seed_vec, public_seed);

  EXPECT_EQ(public_key.size(), constants::PUBLIC_KEY_SIZE);
  std::array<uint8_t, 32> pk_public_seed;
  std::copy_n(public_key.begin(), 32, pk_public_seed.begin());
  EXPECT_EQ(pk_public_seed, public_seed);
}

TEST(WOTSPlusTest, FailToVerifyEmptySignature) {
  WOTSPlus wots(keccak256);
  auto private_seed_arr = number_to_bytes(1);
  std::vector<uint8_t> private_seed_vec(private_seed_arr.begin(),
                                        private_seed_arr.end());
  auto public_seed = number_to_bytes(2);

  auto [public_key, private_key] =
      wots.generate_key_pair(private_seed_vec, public_seed);

  std::array<uint8_t, 32> message{};
  for (size_t i = 0; i < message.size(); ++i) {
    message[i] = i;
  }

  std::vector<std::array<uint8_t, 32>> empty_signature(
      constants::NUM_SIGNATURE_CHUNKS, std::array<uint8_t, 32>{});

  bool is_valid = wots.verify(public_key, message, empty_signature);
  EXPECT_FALSE(is_valid);
}

TEST(WOTSPlusTest, VerifyValidSignature) {
  WOTSPlus wots(keccak256);
  auto private_seed_arr = number_to_bytes(1);
  std::vector<uint8_t> private_seed_vec(private_seed_arr.begin(),
                                        private_seed_arr.end());
  auto public_seed = number_to_bytes(2);

  auto [public_key, private_key] =
      wots.generate_key_pair(private_seed_vec, public_seed);

  std::array<uint8_t, 32> message{};
  for (size_t i = 0; i < message.size(); ++i) {
    message[i] = i;
  }

  auto signature = wots.sign(private_key, public_seed, message);
  bool is_valid = wots.verify(public_key, message, signature);
  EXPECT_TRUE(is_valid);
}

TEST(WOTSPlusTest, VerifyValidSignatureWithRandomizationElements) {
  WOTSPlus wots(keccak256);
  auto private_seed_arr = number_to_bytes(1);
  std::vector<uint8_t> private_seed_vec(private_seed_arr.begin(),
                                        private_seed_arr.end());
  auto public_seed = number_to_bytes(2);

  auto [public_key, private_key] =
      wots.generate_key_pair(private_seed_vec, public_seed);

  std::array<uint8_t, 32> message{};
  for (size_t i = 0; i < message.size(); ++i) {
    message[i] = i;
  }

  auto signature = wots.sign(private_key, public_seed, message);

  auto randomization_elements =
      wots.generate_randomization_elements(public_seed);

  std::array<uint8_t, constants::HASH_LEN> public_key_hash;
  std::copy_n(public_key.begin() + constants::HASH_LEN, constants::HASH_LEN,
              public_key_hash.begin());

  bool is_valid = wots.verify_with_randomization_elements(
      public_key_hash, message, signature, randomization_elements);
  EXPECT_TRUE(is_valid);
}

TEST(WOTSPlusTest, Keccak256TestVectors) {
  std::ifstream f("wotsplus_keccak256.json");
  json data = json::parse(f);

  WOTSPlus wots(keccak256);

  for (const auto &vector_item : data["vectors"]) {
    for (auto const &[key, vector] : vector_item.items()) {

      // Convert hex strings to bytes
      auto private_seed_array =
          hex_to_bytes(vector["privateKey"].get<std::string>());
      std::vector<uint8_t> private_seed_vec(private_seed_array.begin(),
                                            private_seed_array.end());
      auto public_seed = hex_to_bytes(vector["publicSeed"].get<std::string>());
      auto message = hex_to_bytes(vector["message"].get<std::string>());
      auto expected_public_key_hex = vector["publicKey"].get<std::string>();
      auto expected_signature_hex = vector["signature"].get<std::string>();

      // Generate key pair
      auto [public_key, private_key] =
          wots.generate_key_pair(private_seed_vec, public_seed);

      // Check public key
      std::vector<uint8_t> pk_bytes_vec(public_key.begin(), public_key.end());
      std::string pk_hex = bytes_to_hex(pk_bytes_vec);
      EXPECT_EQ(pk_hex, expected_public_key_hex);

      // Sign message
      auto signature_parts = wots.sign(private_key, public_seed, message);

      // Verify signature
      bool is_valid = wots.verify(public_key, message, signature_parts);
      EXPECT_TRUE(is_valid);

      // Verify with randomization elements
      auto randomization_elements =
          wots.generate_randomization_elements(public_seed);
      std::array<uint8_t, constants::HASH_LEN> public_key_hash;
      std::copy_n(public_key.begin() + constants::HASH_LEN, constants::HASH_LEN,
                  public_key_hash.begin());
      bool is_valid_with_rand = wots.verify_with_randomization_elements(
          public_key_hash, message, signature_parts, randomization_elements);
      EXPECT_TRUE(is_valid_with_rand);
    }
  }
}

} // namespace test
} // namespace hashsigs