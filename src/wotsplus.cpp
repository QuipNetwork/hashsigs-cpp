#include "wotsplus.hpp"
#include "constants.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace hashsigs {

WOTSPlus::WOTSPlus(HashFn hash_fn, size_t hash_len, size_t chain_len)
    : hash_fn_(std::move(hash_fn)) {}

std::array<uint8_t, constants::HASH_LEN>
WOTSPlus::prf(const std::array<uint8_t, constants::HASH_LEN> &seed,
              uint16_t index) {
  std::vector<uint8_t> input(constants::PRF_INPUT_SIZE);
  input[0] = 0x03; // prefix to domain separate
  std::copy(seed.begin(), seed.end(), input.begin() + 1);

  // Convert index to big-endian bytes
  input[input.size() - 2] = static_cast<uint8_t>(index >> 8);
  input[input.size() - 1] = static_cast<uint8_t>(index & 0xFF);

  return hash_fn_(input);
}

std::vector<std::array<uint8_t, constants::HASH_LEN>>
WOTSPlus::generate_randomization_elements(
    const std::array<uint8_t, constants::HASH_LEN> &public_seed) {
  std::vector<std::array<uint8_t, constants::HASH_LEN>> elements;
  elements.reserve(constants::NUM_SIGNATURE_CHUNKS);

  for (size_t i = 0; i < constants::NUM_SIGNATURE_CHUNKS; ++i) {
    elements.push_back(prf(public_seed, static_cast<uint16_t>(i)));
  }

  return elements;
}

std::array<uint8_t, constants::HASH_LEN>
WOTSPlus::xor_arrays(const std::array<uint8_t, constants::HASH_LEN> &a,
                     const std::array<uint8_t, constants::HASH_LEN> &b) {
  std::array<uint8_t, constants::HASH_LEN> result;
  for (size_t i = 0; i < constants::HASH_LEN; ++i) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

std::array<uint8_t, constants::HASH_LEN>
WOTSPlus::chain(const std::array<uint8_t, constants::HASH_LEN> &prev_chain_out,
                const std::vector<std::array<uint8_t, constants::HASH_LEN>>
                    &randomization_elements,
                uint16_t index, uint16_t steps) {
  std::array<uint8_t, constants::HASH_LEN> chain_out = prev_chain_out;

  for (uint16_t i = 0; i < steps; ++i) {
    auto xored = xor_arrays(chain_out, randomization_elements[index + i]);
    chain_out = hash_fn_(std::vector<uint8_t>(xored.begin(), xored.end()));
  }

  return chain_out;
}

std::vector<uint8_t> WOTSPlus::compute_message_hash_chain_indexes(
    const std::array<uint8_t, constants::MESSAGE_LEN> &message) {
  if (message.size() != constants::MESSAGE_LEN) {
    throw std::invalid_argument("Message length must be " +
                                std::to_string(constants::MESSAGE_LEN) +
                                " bytes");
  }

  std::vector<uint8_t> indexes;
  indexes.reserve(constants::NUM_SIGNATURE_CHUNKS);

  // Convert message to base-w representation
  for (size_t i = 0; i < constants::NUM_MESSAGE_CHUNKS; ++i) {
    size_t byte_idx = i / 2;
    uint8_t byte = message[byte_idx];

    if (i % 2 == 0) {
      indexes.push_back(byte >> 4); // high nibble
    } else {
      indexes.push_back(byte & 0x0F); // low nibble
    }
  }

  // Compute checksum
  uint32_t checksum = 0;
  for (uint8_t idx : indexes) {
    checksum += constants::CHAIN_LEN - 1 - idx;
  }

  // Convert checksum to base-w representation
  // Process from most significant to least significant digit
  for (size_t i = 0; i < constants::NUM_CHECKSUM_CHUNKS; ++i) {
    size_t shift =
        (constants::NUM_CHECKSUM_CHUNKS - 1 - i) * constants::LG_CHAIN_LEN;
    indexes.push_back((checksum >> shift) & (constants::CHAIN_LEN - 1));
  }

  return indexes;
}

std::pair<std::array<uint8_t, constants::PUBLIC_KEY_SIZE>,
          std::array<uint8_t, constants::HASH_LEN>>
WOTSPlus::generate_key_pair(
    const std::vector<uint8_t> &private_seed,
    const std::array<uint8_t, constants::HASH_LEN> &public_seed) {
  // Combine private_seed and public_seed
  std::vector<uint8_t> combined_seed_input;
  combined_seed_input.insert(combined_seed_input.end(), private_seed.begin(),
                             private_seed.end());
  combined_seed_input.insert(combined_seed_input.end(), public_seed.begin(),
                             public_seed.end());

  // Hash the combined seed to get the private key
  auto private_key = hash_fn_(combined_seed_input);

  // Generate randomization elements
  auto randomization_elements = generate_randomization_elements(public_seed);

  // Generate public key segments
  std::vector<uint8_t> public_key_segments;
  public_key_segments.reserve(constants::NUM_SIGNATURE_CHUNKS *
                              constants::HASH_LEN);

  for (size_t i = 0; i < constants::NUM_SIGNATURE_CHUNKS; ++i) {
    auto secret_key_segment = prf(private_key, i);
    auto public_key_segment = chain(secret_key_segment, randomization_elements,
                                    0, constants::CHAIN_LEN - 1);
    public_key_segments.insert(public_key_segments.end(),
                               public_key_segment.begin(),
                               public_key_segment.end());
  }

  auto public_key_hash = hash_fn_(public_key_segments);

  std::array<uint8_t, constants::PUBLIC_KEY_SIZE> public_key_bytes;
  std::copy(public_seed.begin(), public_seed.end(), public_key_bytes.begin());
  std::copy(public_key_hash.begin(), public_key_hash.end(),
            public_key_bytes.begin() + constants::HASH_LEN);

  return {public_key_bytes, private_key};
}

std::vector<std::array<uint8_t, constants::HASH_LEN>>
WOTSPlus::sign(const std::array<uint8_t, constants::HASH_LEN> &private_key,
               const std::array<uint8_t, constants::HASH_LEN> &public_seed,
               const std::array<uint8_t, constants::MESSAGE_LEN> &message) {
  // Generate randomization elements using the provided public_seed
  auto randomization_elements = generate_randomization_elements(public_seed);

  // Compute message hash chain indexes
  auto indexes = compute_message_hash_chain_indexes(message);

  // Generate signature
  std::vector<std::array<uint8_t, constants::HASH_LEN>> signature;
  signature.reserve(constants::NUM_SIGNATURE_CHUNKS);

  for (size_t i = 0; i < constants::NUM_SIGNATURE_CHUNKS; ++i) {
    // The private_key is now the root, so we need to expand it
    auto secret_key_segment = prf(private_key, i);

    // Chain hash the secret key segment `indexes[i]` times
    auto signature_segment =
        chain(secret_key_segment, randomization_elements, 0, indexes[i]);
    signature.push_back(signature_segment);
  }

  return signature;
}

bool WOTSPlus::verify(
    const std::array<uint8_t, constants::PUBLIC_KEY_SIZE> &public_key,
    const std::array<uint8_t, constants::MESSAGE_LEN> &message,
    const std::vector<std::array<uint8_t, constants::HASH_LEN>> &signature) {
  if (signature.size() != constants::NUM_SIGNATURE_CHUNKS) {
    return false; // Invalid signature length
  }

  // Extract public seed and hash from public key
  std::array<uint8_t, constants::HASH_LEN> public_seed;
  std::copy_n(public_key.begin(), constants::HASH_LEN, public_seed.begin());
  std::array<uint8_t, constants::HASH_LEN> public_key_hash;
  std::copy_n(public_key.begin() + constants::HASH_LEN, constants::HASH_LEN,
              public_key_hash.begin());

  // Generate randomization elements
  auto randomization_elements = generate_randomization_elements(public_seed);

  return verify_with_randomization_elements(public_key_hash, message, signature,
                                            randomization_elements);
}

bool WOTSPlus::verify_with_randomization_elements(
    const std::array<uint8_t, constants::HASH_LEN> &public_key_hash,
    const std::array<uint8_t, constants::MESSAGE_LEN> &message,
    const std::vector<std::array<uint8_t, constants::HASH_LEN>> &signature,
    const std::vector<std::array<uint8_t, constants::HASH_LEN>>
        &randomization_elements) {
  if (signature.size() != constants::NUM_SIGNATURE_CHUNKS) {
    return false;
  }

  auto indexes = compute_message_hash_chain_indexes(message);

  std::vector<std::array<uint8_t, constants::HASH_LEN>> public_key_segments;
  public_key_segments.reserve(constants::NUM_SIGNATURE_CHUNKS);

  for (size_t i = 0; i < constants::NUM_SIGNATURE_CHUNKS; ++i) {
    auto segment = chain(signature[i], randomization_elements, indexes[i],
                         constants::CHAIN_LEN - 1 - indexes[i]);
    public_key_segments.push_back(segment);
  }

  // Concatenate and hash the public key segments
  std::vector<uint8_t> segments_concatenated;
  for (const auto &segment : public_key_segments) {
    segments_concatenated.insert(segments_concatenated.end(), segment.begin(),
                                 segment.end());
  }
  auto computed_hash = hash_fn_(segments_concatenated);

  return computed_hash == public_key_hash;
}
} // namespace hashsigs