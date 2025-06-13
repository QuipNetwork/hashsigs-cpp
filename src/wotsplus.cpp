#include "wotsplus.hpp"
#include "constants.hpp"
#include <algorithm>
#include <stdexcept>
#include <vector>

namespace hashsigs {

WOTSPlus::WOTSPlus(HashFn hash_fn) : hash_fn_(std::move(hash_fn)) {}

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

  for (uint16_t i = 1; i <= steps; ++i) {
    auto xored = xor_arrays(chain_out, randomization_elements[i + index]);
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
  indexes.reserve(constants::NUM_MESSAGE_CHUNKS);

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

PublicKey WOTSPlus::get_public_key(
    const std::array<uint8_t, constants::HASH_LEN> &private_key) {
  // Generate public seed (first half of public key)
  std::array<uint8_t, constants::HASH_LEN> public_seed = prf(private_key, 0);

  // Generate randomization elements
  auto randomization_elements = generate_randomization_elements(public_seed);
  auto function_key = randomization_elements[0];

  // Generate public key segments
  std::vector<std::array<uint8_t, constants::HASH_LEN>> public_key_segments;
  public_key_segments.reserve(constants::NUM_SIGNATURE_CHUNKS);

  for (size_t i = 0; i < constants::NUM_SIGNATURE_CHUNKS; ++i) {
    // Create combined hash of function key and PRF output
    std::vector<uint8_t> to_hash(constants::HASH_LEN * 2);
    std::copy(function_key.begin(), function_key.end(), to_hash.begin());
    auto prf_output = prf(private_key, static_cast<uint16_t>(i + 1));
    std::copy(prf_output.begin(), prf_output.end(),
              to_hash.begin() + constants::HASH_LEN);

    // Generate secret key segment
    auto secret_key_segment = hash_fn_(to_hash);

    // Run chain function to get public key segment
    auto segment = chain(secret_key_segment, randomization_elements, 0,
                         constants::CHAIN_LEN - 1);
    public_key_segments.push_back(segment);
  }

  // Hash all segments together
  std::vector<uint8_t> segments_concatenated;
  segments_concatenated.reserve(constants::NUM_SIGNATURE_CHUNKS *
                                constants::HASH_LEN);

  for (const auto &segment : public_key_segments) {
    segments_concatenated.insert(segments_concatenated.end(), segment.begin(),
                                 segment.end());
  }

  std::array<uint8_t, constants::HASH_LEN> public_key_hash =
      hash_fn_(segments_concatenated);

  return PublicKey(public_seed, public_key_hash);
}

std::pair<PublicKey, std::array<uint8_t, constants::HASH_LEN>>
WOTSPlus::generate_key_pair(
    const std::array<uint8_t, constants::HASH_LEN> &private_seed) {
  // Generate private key
  std::array<uint8_t, constants::HASH_LEN> private_key =
      hash_fn_(std::vector<uint8_t>(private_seed.begin(), private_seed.end()));

  // Generate public key
  PublicKey public_key = get_public_key(private_key);

  return {public_key, private_key};
}

std::vector<std::array<uint8_t, constants::HASH_LEN>>
WOTSPlus::sign(const std::array<uint8_t, constants::HASH_LEN> &private_key,
               const std::array<uint8_t, constants::MESSAGE_LEN> &message) {
  // Generate public seed
  std::array<uint8_t, constants::HASH_LEN> public_seed = prf(private_key, 0);

  // Generate randomization elements
  auto randomization_elements = generate_randomization_elements(public_seed);
  auto function_key = randomization_elements[0];

  // Compute message hash chain indexes
  auto indexes = compute_message_hash_chain_indexes(message);

  // Generate signature
  std::vector<std::array<uint8_t, constants::HASH_LEN>> signature;
  signature.reserve(constants::NUM_SIGNATURE_CHUNKS);

  for (size_t i = 0; i < constants::NUM_SIGNATURE_CHUNKS; ++i) {
    // Create combined hash of function key and PRF output
    std::vector<uint8_t> to_hash(constants::HASH_LEN * 2);
    std::copy(function_key.begin(), function_key.end(), to_hash.begin());
    auto prf_output = prf(private_key, static_cast<uint16_t>(i + 1));
    std::copy(prf_output.begin(), prf_output.end(),
              to_hash.begin() + constants::HASH_LEN);

    // Generate secret key segment
    auto secret_key_segment = hash_fn_(to_hash);

    // Run chain function to get signature segment
    auto segment =
        chain(secret_key_segment, randomization_elements, 0, indexes[i]);
    signature.push_back(segment);
  }

  return signature;
}

bool WOTSPlus::verify(
    const PublicKey &public_key,
    const std::array<uint8_t, constants::MESSAGE_LEN> &message,
    const std::vector<std::array<uint8_t, constants::HASH_LEN>> &signature) {
  if (signature.size() != constants::NUM_SIGNATURE_CHUNKS) {
    return false;
  }

  auto randomization_elements =
      generate_randomization_elements(public_key.get_public_seed());

  return verify_with_randomization_elements(public_key.get_public_key_hash(),
                                            message, signature,
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

  // Compute message hash chain indexes
  auto indexes = compute_message_hash_chain_indexes(message);

  // Create fixed-size array for public key segments
  std::array<uint8_t, constants::SIGNATURE_SIZE> public_key_segments{};

  // Verify each signature segment
  for (size_t i = 0; i < constants::NUM_SIGNATURE_CHUNKS; ++i) {
    auto segment = chain(signature[i], randomization_elements,
                         static_cast<uint16_t>(indexes[i]),
                         constants::CHAIN_LEN - 1 - indexes[i]);

    // Copy segment into the fixed-size array
    std::copy(segment.begin(), segment.end(),
              public_key_segments.begin() + (i * constants::HASH_LEN));
  }

  // Hash all segments together
  std::array<uint8_t, constants::HASH_LEN> computed_hash =
      hash_fn_(std::vector<uint8_t>(public_key_segments.begin(),
                                    public_key_segments.end()));

  return computed_hash == public_key_hash;
}

} // namespace hashsigs