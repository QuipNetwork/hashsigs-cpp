#pragma once

#include "constants.hpp"
#include <array>
#include <optional>
#include <vector>

namespace hashsigs {

/// PublicKey consists of two parts:
/// 1. The public seed used to generate randomization elements
/// 2. The hash of all public key segments concatenated together
class PublicKey {
public:
    PublicKey() = default;
    PublicKey(const std::array<uint8_t, constants::HASH_LEN>& public_seed,
              const std::array<uint8_t, constants::HASH_LEN>& public_key_hash);

    /// Convert the public key to bytes
    /// Returns a byte array of size PUBLIC_KEY_SIZE containing the public seed followed by the public key hash
    std::array<uint8_t, constants::PUBLIC_KEY_SIZE> to_bytes() const;

    /// Create a PublicKey from bytes
    /// Returns std::nullopt if the input is not of the correct length
    static std::optional<PublicKey> from_bytes(const std::vector<uint8_t>& bytes);

    /// Get the public seed
    const std::array<uint8_t, constants::HASH_LEN>& get_public_seed() const { return public_seed_; }

    /// Get the public key hash
    const std::array<uint8_t, constants::HASH_LEN>& get_public_key_hash() const { return public_key_hash_; }

private:
    std::array<uint8_t, constants::HASH_LEN> public_seed_{};
    std::array<uint8_t, constants::HASH_LEN> public_key_hash_{};
};

} // namespace hashsigs 