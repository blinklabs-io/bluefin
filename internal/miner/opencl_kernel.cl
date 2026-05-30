// SPDX-License-Identifier: Apache-2.0
//
// OpenCL kernel for TUNA mining.
//
// Each work item:
//   1. Copies the (constant) CBOR-encoded TUNA state into a private buffer.
//   2. Replaces the 16-byte nonce slot at byte offset NONCE_OFFSET with a
//      per-thread nonce derived from base_nonce, get_global_id(0), and the
//      kernel "round" parameter.
//   3. Computes sha256(sha256(state)).
//   4. Computes the TUNA difficulty metrics (leading nibble zeros and
//      4-nibble difficulty number) for the resulting hash.
//   5. If the metrics meet or exceed the requested target, atomically
//      claims the single result slot and writes the matching nonce and
//      hash back to the host.
//
// The host side iterates over many "rounds" (advancing a per-batch nonce
// counter) and re-invokes the kernel until either a result is found or
// the host signals shutdown.

#define NONCE_OFFSET 4u
#define NONCE_LEN    16u
#define MAX_STATE_LEN 192u

#define H0 0x6a09e667u
#define H1 0xbb67ae85u
#define H2 0x3c6ef372u
#define H3 0xa54ff53au
#define H4 0x510e527fu
#define H5 0x9b05688cu
#define H6 0x1f83d9abu
#define H7 0x5be0cd19u

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32u - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define BSIG1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SSIG0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

__constant uint K_SHA256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void sha256_compress(uint *digest, const uint *W_in) {
    uint W[64];
    #pragma unroll
    for (uint t = 0; t < 16; t++) W[t] = W_in[t];
    #pragma unroll
    for (uint t = 16; t < 64; t++) {
        W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
    }
    uint a = digest[0], b = digest[1], c = digest[2], d = digest[3];
    uint e = digest[4], f = digest[5], g = digest[6], h = digest[7];
    #pragma unroll
    for (uint t = 0; t < 64; t++) {
        uint T1 = h + BSIG1(e) + CH(e, f, g) + K_SHA256[t] + W[t];
        uint T2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    digest[0] += a; digest[1] += b; digest[2] += c; digest[3] += d;
    digest[4] += e; digest[5] += f; digest[6] += g; digest[7] += h;
}

// SHA-256 of `data[0..len-1]`. `len` must be <= MAX_STATE_LEN.
// `digest` receives the 8-word (32-byte, big-endian per word) hash.
static void sha256_var(const uchar *data, uint len, uint *digest) {
    digest[0] = H0; digest[1] = H1; digest[2] = H2; digest[3] = H3;
    digest[4] = H4; digest[5] = H5; digest[6] = H6; digest[7] = H7;

    // Build a padded scratch buffer in private memory. We need at most
    // ceil((MAX_STATE_LEN + 9) / 64) * 64 bytes.
    uchar buf[((MAX_STATE_LEN + 9 + 63) / 64) * 64];
    uint padded_len = ((len + 9 + 63) / 64) * 64;

    for (uint i = 0; i < len; i++) buf[i] = data[i];
    buf[len] = 0x80;
    for (uint i = len + 1; i < padded_len - 8; i++) buf[i] = 0;
    ulong bit_len = (ulong)len * 8;
    buf[padded_len - 8] = (uchar)(bit_len >> 56);
    buf[padded_len - 7] = (uchar)(bit_len >> 48);
    buf[padded_len - 6] = (uchar)(bit_len >> 40);
    buf[padded_len - 5] = (uchar)(bit_len >> 32);
    buf[padded_len - 4] = (uchar)(bit_len >> 24);
    buf[padded_len - 3] = (uchar)(bit_len >> 16);
    buf[padded_len - 2] = (uchar)(bit_len >> 8);
    buf[padded_len - 1] = (uchar)(bit_len);

    uint blocks = padded_len / 64;
    for (uint b = 0; b < blocks; b++) {
        uint W[16];
        #pragma unroll
        for (uint t = 0; t < 16; t++) {
            uint p = b * 64 + t * 4;
            W[t] = ((uint)buf[p] << 24) | ((uint)buf[p + 1] << 16) |
                   ((uint)buf[p + 2] << 8) | (uint)buf[p + 3];
        }
        sha256_compress(digest, W);
    }
}

// SHA-256 of an exactly-32-byte input given as 8 big-endian words. Used
// for the second pass of the double-SHA256.
static void sha256_32(const uint *in_words, uint *digest) {
    digest[0] = H0; digest[1] = H1; digest[2] = H2; digest[3] = H3;
    digest[4] = H4; digest[5] = H5; digest[6] = H6; digest[7] = H7;

    uint W[16];
    #pragma unroll
    for (uint t = 0; t < 8; t++) W[t] = in_words[t];
    W[8]  = 0x80000000u;
    W[9]  = 0; W[10] = 0; W[11] = 0; W[12] = 0; W[13] = 0; W[14] = 0;
    W[15] = 256u; // length in bits
    sha256_compress(digest, W);
}

// Compute TUNA difficulty metrics (leading nibble zeros + 16-bit
// difficulty number) from the 32-byte big-endian hash given as 8 words.
// Mirrors the host-side getDifficulty(). Reads past the end of the hash
// are treated as zero so the lookahead bytes (i+1, i+2) cannot run off
// the 8-word buffer.
static inline uchar tuna_byte(const uint *hash_words, uint i) {
    if (i >= 32) return 0;
    return (uchar)((hash_words[i >> 2] >> (24u - 8u * (i & 3u))) & 0xffu);
}

static void tuna_difficulty(const uint *hash_words, uint *out_lz, uint *out_diff) {
    uint lz = 0;
    uint diff = 0;
    for (uint i = 0; i < 32; i++) {
        uchar c = tuna_byte(hash_words, i);
        if (c == 0) {
            lz += 2;
            continue;
        }
        if ((c & 0xf0u) == 0) {
            lz += 1;
            uchar c1 = tuna_byte(hash_words, i + 1);
            uchar c2 = tuna_byte(hash_words, i + 2);
            diff = (uint)c * 4096u + (uint)c1 * 16u + ((uint)c2 / 16u);
        } else {
            uchar c1 = tuna_byte(hash_words, i + 1);
            diff = (uint)c * 256u + (uint)c1;
        }
        *out_lz = lz;
        *out_diff = diff;
        return;
    }
    *out_lz = 32;
    *out_diff = 0;
}

// Result slot layout (uints):
//   [0] : found flag (0 = empty, 1 = claimed)
//   [1..4]   : matching 16-byte nonce, byte 0 in MSB of word 1
//   [5..12]  : matching 32-byte hash, big-endian words
__kernel void tuna_search(
    __global const uchar *state_in,
    const uint state_len,
    __global const uchar *base_nonce,
    const uint round_seed,
    const uint target_leading_zeros,
    const uint target_difficulty,
    __global uint *result)
{
    const uint gid = (uint)get_global_id(0);

    // Per-thread private state copy.
    uchar state[MAX_STATE_LEN];
    for (uint i = 0; i < state_len; i++) state[i] = state_in[i];

    // Per-thread nonce: copy base_nonce, then perturb 8 bytes with gid
    // and round_seed so every (gid, round) pair is unique.
    uchar nonce[NONCE_LEN];
    for (uint i = 0; i < NONCE_LEN; i++) nonce[i] = base_nonce[i];
    nonce[0] ^= (uchar)(gid >> 24);
    nonce[1] ^= (uchar)(gid >> 16);
    nonce[2] ^= (uchar)(gid >> 8);
    nonce[3] ^= (uchar)(gid);
    nonce[4] ^= (uchar)(round_seed >> 24);
    nonce[5] ^= (uchar)(round_seed >> 16);
    nonce[6] ^= (uchar)(round_seed >> 8);
    nonce[7] ^= (uchar)(round_seed);

    // Splice the per-thread nonce into the state buffer.
    for (uint i = 0; i < NONCE_LEN; i++) {
        state[NONCE_OFFSET + i] = nonce[i];
    }

    // Double SHA-256.
    uint digest1[8];
    sha256_var(state, state_len, digest1);
    uint digest2[8];
    sha256_32(digest1, digest2);

    // TUNA difficulty check.
    uint lz, diff;
    tuna_difficulty(digest2, &lz, &diff);
    bool meets = (lz > target_leading_zeros) ||
                 (lz == target_leading_zeros && diff < target_difficulty);
    if (!meets) {
        return;
    }

    // Atomically claim the single result slot.
    if (atomic_cmpxchg(&result[0], 0u, 1u) != 0u) {
        return;
    }
    // Write nonce as 4 big-endian words.
    for (uint w = 0; w < 4; w++) {
        result[1 + w] = ((uint)nonce[w * 4] << 24) |
                        ((uint)nonce[w * 4 + 1] << 16) |
                        ((uint)nonce[w * 4 + 2] << 8) |
                        (uint)nonce[w * 4 + 3];
    }
    // Write hash as 8 big-endian words.
    for (uint w = 0; w < 8; w++) {
        result[5 + w] = digest2[w];
    }
}
