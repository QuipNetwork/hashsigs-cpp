#pragma once

#include "constants.hpp"
#include <array>
#include <functional>
#include <vector>

namespace hashsigs {

/// HashFn is a function type that takes a byte array and returns a 32-byte hash
using HashFn =
    std::function<std::array<uint8_t, 32>(const std::vector<uint8_t> &)>;

/// WOTSPlus implements the WOTS+ one-time signature scheme
/// This is a stateless signature scheme that can only be used once per key pair
/// The scheme is based on hash chains and uses a hash function to generate
/// randomization elements that are used to prevent birthday attacks
class WOTSPlus {
public:
  /// Create a new WOTSPlus instance with the specified hash function
  explicit WOTSPlus(HashFn hash_fn, size_t hash_len = 32,
                    size_t chain_len = 16);

  /// Generate a key pair from a private seed and public seed
  /// (protocol-compatible) Returns a pair containing the public key and
  /// the private key
  std::pair<std::array<uint8_t, constants::PUBLIC_KEY_SIZE>,
            std::array<uint8_t, constants::HASH_LEN>>
  generate_key_pair(
      const std::vector<uint8_t> &private_seed,
      const std::array<uint8_t, constants::HASH_LEN> &public_seed);

  /// Sign a message with a private key and public seed (protocol-compatible)
  /// Returns a vector of signature segments
  std::vector<std::array<uint8_t, constants::HASH_LEN>>
  sign(const std::array<uint8_t, constants::HASH_LEN> &private_key,
       const std::array<uint8_t, constants::HASH_LEN> &public_seed,
       const std::array<uint8_t, constants::MESSAGE_LEN> &message);

  /// Verify a signature
  /// Returns true if the signature is valid, false otherwise
  bool verify(
      const std::array<uint8_t, constants::PUBLIC_KEY_SIZE> &public_key,
      const std::array<uint8_t, constants::MESSAGE_LEN> &message,
      const std::vector<std::array<uint8_t, constants::HASH_LEN>> &signature);

  /// Generate randomization elements from public seed
  /// These elements are used in the chain function to randomize each hash
  std::vector<std::array<uint8_t, constants::HASH_LEN>>
  generate_randomization_elements(
      const std::array<uint8_t, constants::HASH_LEN> &public_seed);

  /// Verify a signature using pre-computed randomization elements
  /// This is an optimization that allows reusing the randomization elements
  /// when verifying multiple signatures with the same public seed
  bool verify_with_randomization_elements(
      const std::array<uint8_t, constants::HASH_LEN> &public_key_hash,
      const std::array<uint8_t, constants::MESSAGE_LEN> &message,
      const std::vector<std::array<uint8_t, constants::HASH_LEN>> &signature,
      const std::vector<std::array<uint8_t, constants::HASH_LEN>>
          &randomization_elements);

private:
  /// Generate randomization elements from seed and index
  /// Similar to XMSS RFC 8391 section 5.1
  /// Uses a prefix byte (0x03) to domain separate the PRF
  std::array<uint8_t, constants::HASH_LEN>
  prf(const std::array<uint8_t, constants::HASH_LEN> &seed, uint16_t index);

  /// XOR two 32-byte arrays
  static std::array<uint8_t, constants::HASH_LEN>
  xor_arrays(const std::array<uint8_t, constants::HASH_LEN> &a,
             const std::array<uint8_t, constants::HASH_LEN> &b);

  /// Chain function (c_k^i function)
  /// This is the core of WOTS+, implementing the hash chain with randomization
  /// The chain function takes the previous chain output, XORs it with a
  /// randomization element, and then hashes the result. This is repeated
  /// 'steps' times.
  std::array<uint8_t, constants::HASH_LEN>
  chain(const std::array<uint8_t, constants::HASH_LEN> &prev_chain_out,
        const std::vector<std::array<uint8_t, constants::HASH_LEN>>
            &randomization_elements,
        uint16_t index, uint16_t steps);

  /// Compute message hash chain indexes
  /// This function performs two main tasks:
  /// 1. Convert the message to base-w representation (or base of CHAIN_LEN
  /// representation)
  /// 2. Compute and append the checksum in base-w representation
  ///
  /// These numbers are used to index into each hash chain which is rooted at a
  /// secret key segment and produces a public key segment at the end of the
  /// chain. Verification of a signature means using these indexes into each
  /// hash chain to recompute the corresponding public key segment.
  std::vector<uint8_t> compute_message_hash_chain_indexes(
      const std::array<uint8_t, constants::MESSAGE_LEN> &message);

  HashFn hash_fn_;
};

} // namespace hashsigs