#pragma once

#include <cstddef>
#include <cstdint>

namespace hashsigs {

namespace constants {
/// HashLen: The WOTS+ `n` security parameter which is the size
/// of the hash function output in bytes.
/// This is 32 for keccak256 (256 / 8 = 32)
constexpr size_t HASH_LEN = 32;

/// MessageLen: The WOTS+ `m` parameter which is the size
/// of the message to be signed in bytes
/// (and also the size of our hash function)
///
/// This is 32 for keccak256 (256 / 8 = 32)
///
/// Note that this is not the message length itself as, like
/// with most signatures, we hash the message and then compute
/// the signature on the hash of the message.
constexpr size_t MESSAGE_LEN = HASH_LEN;

/// ChainLen: The WOTS+ `w`(internitz) parameter.
/// This corresponds to the number of hash chains for each public
/// key segment and the base-w representation of the message
/// and checksum.
///
/// A larger value means a smaller signature size but a longer
/// computation time.
///
/// For XMSS (rfc8391) this value is limited to 4 or 16 because
/// they simplify the algorithm and offer the best trade-offs.
constexpr size_t CHAIN_LEN = 16;

/// Calculate log2 of a number at compile time
constexpr size_t log2(size_t n) { return n <= 1 ? 0 : 1 + log2(n / 2); }

/// lg(ChainLen) so we don't calculate it (lg(16) == 4)
constexpr size_t LG_CHAIN_LEN = log2(CHAIN_LEN);

/// Calculate ceiling division at compile time
constexpr size_t div_ceil(size_t a, size_t b) { return (a + b - 1) / b; }

/// NumMessageChunks: the `len_1` parameter which is the number of
/// message chunks. This is
/// ceil(8n / lg(w)) -> ceil(8 * HASH_LEN / lg(CHAIN_LEN))
/// or ceil(32*8 / lg(16)) -> 256 / 4 = 64
/// Python:  math.ceil(32*8 / math.log(16,2))
constexpr size_t NUM_MESSAGE_CHUNKS = div_ceil(8 * HASH_LEN, LG_CHAIN_LEN);

/// NumChecksumChunks: the `len_2` parameter which is the number of
/// checksum chunks. This is
/// floor(lg(len_1 * (w - 1)) / lg(w)) + 1
/// -> floor(lg(NUM_MESSAGE_CHUNKS * (CHAIN_LEN - 1)) / lg(CHAIN_LEN)) + 1
/// -> floor(lg(64 * 15) / lg(16)) + 1 = 3
/// Python: math.floor(math.log(64 * 15, 2) / math.log(16, 2)) + 1
constexpr size_t NUM_CHECKSUM_CHUNKS =
    (log2(NUM_MESSAGE_CHUNKS * (CHAIN_LEN - 1)) / LG_CHAIN_LEN) + 1;

/// Total number of signature chunks
constexpr size_t NUM_SIGNATURE_CHUNKS =
    NUM_MESSAGE_CHUNKS + NUM_CHECKSUM_CHUNKS;

/// Size of signature in bytes
constexpr size_t SIGNATURE_SIZE = NUM_SIGNATURE_CHUNKS * HASH_LEN;

/// Size of public key in bytes
constexpr size_t PUBLIC_KEY_SIZE = HASH_LEN * 2;

/// PRF input size (prefix + seed + index)
constexpr size_t PRF_INPUT_SIZE = 1 + HASH_LEN + 2;

// Static assertions to verify our calculations
static_assert(LG_CHAIN_LEN == 4, "LG_CHAIN_LEN should be 4");
static_assert(NUM_MESSAGE_CHUNKS == 64, "NUM_MESSAGE_CHUNKS should be 64");
static_assert(NUM_CHECKSUM_CHUNKS == 3, "NUM_CHECKSUM_CHUNKS should be 3");
} // namespace constants

} // namespace hashsigs