#include "public_key.hpp"
#include <algorithm>
#include <stdexcept>

namespace hashsigs {

PublicKey::PublicKey(const std::array<uint8_t, constants::HASH_LEN>& public_seed,
                     const std::array<uint8_t, constants::HASH_LEN>& public_key_hash)
    : public_seed_(public_seed)
    , public_key_hash_(public_key_hash) {}

std::array<uint8_t, constants::PUBLIC_KEY_SIZE> PublicKey::to_bytes() const {
    std::array<uint8_t, constants::PUBLIC_KEY_SIZE> result{};
    std::copy(public_seed_.begin(), public_seed_.end(), result.begin());
    std::copy(public_key_hash_.begin(), public_key_hash_.end(), 
              result.begin() + constants::HASH_LEN);
    return result;
}

std::optional<PublicKey> PublicKey::from_bytes(const std::vector<uint8_t>& bytes) {
    if (bytes.size() != constants::PUBLIC_KEY_SIZE) {
        return std::nullopt;
    }

    std::array<uint8_t, constants::HASH_LEN> public_seed{};
    std::array<uint8_t, constants::HASH_LEN> public_key_hash{};

    std::copy(bytes.begin(), bytes.begin() + constants::HASH_LEN, public_seed.begin());
    std::copy(bytes.begin() + constants::HASH_LEN, bytes.end(), public_key_hash.begin());

    return PublicKey(public_seed, public_key_hash);
}

} // namespace hashsigs 