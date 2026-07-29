#ifndef HASHER_HPP
#define HASHER_HPP

#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <array>
#include <iostream>

namespace Hasher {

// MD5 implementation class
class MD5 {
public:
    MD5() { reset(); }

    void update(const uint8_t* input, size_t length) {
        size_t index = (count[0] >> 3) & 0x3F;
        if ((count[0] += (length << 3)) < (length << 3)) {
            count[1]++;
        }
        count[1] += (length >> 29);

        size_t partLen = 64 - index;
        size_t i = 0;

        if (length >= partLen) {
            std::copy(input, input + partLen, buffer.begin() + index);
            transform(buffer.data());

            for (i = partLen; i + 63 < length; i += 64) {
                transform(input + i);
            }
            index = 0;
        }

        std::copy(input + i, input + length, buffer.begin() + index);
    }

    std::string finalize() {
        std::array<uint8_t, 8> bits;
        encode(bits.data(), count.data(), 8);

        size_t index = (count[0] >> 3) & 0x3F;
        size_t padLen = (index < 56) ? (56 - index) : (120 - index);
        
        static const std::array<uint8_t, 64> PADDING = []() {
            std::array<uint8_t, 64> p{};
            p[0] = 0x80;
            return p;
        }();

        update(PADDING.data(), padLen);
        update(bits.data(), 8);

        std::array<uint8_t, 16> digest;
        encode(digest.data(), state.data(), 16);

        std::stringstream ss;
        for (int i = 0; i < 16; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }
        return ss.str();
    }

private:
    std::array<uint32_t, 4> state;
    std::array<uint32_t, 2> count;
    std::array<uint8_t, 64> buffer;

    void reset() {
        state[0] = 0x67452301;
        state[1] = 0xefcdab89;
        state[2] = 0x98badcfe;
        state[3] = 0x10325476;
        count[0] = count[1] = 0;
        buffer.fill(0);
    }

    void transform(const uint8_t block[64]) {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        std::array<uint32_t, 16> x;
        decode(x.data(), block, 64);

        // Round 1
        #define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
        #define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
        #define H(x, y, z) ((x) ^ (y) ^ (z))
        #define I(x, y, z) ((y) ^ ((x) | (~z)))
        #define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
        #define FF(a, b, c, d, x, s, ac) { \
            (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
            (a) = ROTATE_LEFT ((a), (s)); \
            (a) += (b); \
        }
        #define GG(a, b, c, d, x, s, ac) { \
            (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
            (a) = ROTATE_LEFT ((a), (s)); \
            (a) += (b); \
        }
        #define HH(a, b, c, d, x, s, ac) { \
            (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
            (a) = ROTATE_LEFT ((a), (s)); \
            (a) += (b); \
        }
        #define II(a, b, c, d, x, s, ac) { \
            (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
            (a) = ROTATE_LEFT ((a), (s)); \
            (a) += (b); \
        }

        FF(a, b, c, d, x[0], 7, 0xd76aa478);
        FF(d, a, b, c, x[1], 12, 0xe8c7b756);
        FF(c, d, a, b, x[2], 17, 0x242070db);
        FF(b, c, d, a, x[3], 22, 0xc1bdceee);
        FF(a, b, c, d, x[4], 7, 0xf57c0faf);
        FF(d, a, b, c, x[5], 12, 0x4787c62a);
        FF(c, d, a, b, x[6], 17, 0xa8304613);
        FF(b, c, d, a, x[7], 22, 0xfd469501);
        FF(a, b, c, d, x[8], 7, 0x698098d8);
        FF(d, a, b, c, x[9], 12, 0x8b44f7af);
        FF(c, d, a, b, x[10], 17, 0xffff5bb1);
        FF(b, c, d, a, x[11], 22, 0x895cd7be);
        FF(a, b, c, d, x[12], 7, 0x6b901122);
        FF(d, a, b, c, x[13], 12, 0xfd987193);
        FF(c, d, a, b, x[14], 17, 0xa679438e);
        FF(b, c, d, a, x[15], 22, 0x49b40821);

        GG(a, b, c, d, x[1], 5, 0xf61e2562);
        GG(d, a, b, c, x[6], 9, 0xc040b340);
        GG(c, d, a, b, x[11], 14, 0x265e5a51);
        GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);
        GG(a, b, c, d, x[5], 5, 0xd62f105d);
        GG(d, a, b, c, x[10], 9,  0x2441453);
        GG(c, d, a, b, x[15], 14, 0xd8a1e681);
        GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);
        GG(a, b, c, d, x[9], 5, 0x21e1cde6);
        GG(d, a, b, c, x[14], 9, 0xc33707d6);
        GG(c, d, a, b, x[3], 14, 0xf4d50d87);
        GG(b, c, d, a, x[8], 20, 0x455a14ed);
        GG(a, b, c, d, x[13], 5, 0xa9e3e905);
        GG(d, a, b, c, x[2], 9, 0xfcefa3f8);
        GG(c, d, a, b, x[7], 14, 0x676f02d9);
        GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

        HH(a, b, c, d, x[5], 4, 0xfffa3942);
        HH(d, a, b, c, x[8], 11, 0x8771f681);
        HH(c, d, a, b, x[11], 16, 0x6d9d6122);
        HH(b, c, d, a, x[14], 23, 0xfde5380c);
        HH(a, b, c, d, x[1], 4, 0xa4beea44);
        HH(d, a, b, c, x[4], 11, 0x4bdecfa9);
        HH(c, d, a, b, x[7], 16, 0xf6bb4b60);
        HH(b, c, d, a, x[10], 23, 0xbebfbc70);
        HH(a, b, c, d, x[13], 4, 0x289b7ec6);
        HH(d, a, b, c, x[0], 11, 0xeaa127fa);
        HH(c, d, a, b, x[3], 16, 0xd4ef3085);
        HH(b, c, d, a, x[6], 23,  0x4881d05);
        HH(a, b, c, d, x[9], 4, 0xd9d4d039);
        HH(d, a, b, c, x[12], 11, 0xe6db99e5);
        HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
        HH(b, c, d, a, x[2], 23, 0xc4ac5665);

        II(a, b, c, d, x[0], 6, 0xf4292244);
        II(d, a, b, c, x[7], 10, 0x432aff97);
        II(c, d, a, b, x[14], 15, 0xab9423a7);
        II(b, c, d, a, x[5], 21, 0xfc93a039);
        II(a, b, c, d, x[12], 6, 0x655b59c3);
        II(d, a, b, c, x[3], 10, 0x8f0ccc92);
        II(c, d, a, b, x[10], 15, 0xffeff47d);
        II(b, c, d, a, x[1], 21, 0x85845dd1);
        II(a, b, c, d, x[8], 6, 0x6fa87e4f);
        II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
        II(c, d, a, b, x[6], 15, 0xa3014314);
        II(b, c, d, a, x[13], 21, 0x4e0811a1);
        II(a, b, c, d, x[4], 6, 0xf7537e82);
        II(d, a, b, c, x[11], 10, 0xbd3af235);
        II(c, d, a, b, x[2], 15, 0x2ad7d2bb);
        II(b, c, d, a, x[9], 21, 0xeb86d391);

        #undef F
        #undef G
        #undef H
        #undef I
        #undef ROTATE_LEFT
        #undef FF
        #undef GG
        #undef HH
        #undef II

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    static void encode(uint8_t* output, const uint32_t* input, size_t len) {
        for (size_t i = 0, j = 0; j < len; i++, j += 4) {
            output[j]   = (uint8_t)(input[i] & 0xff);
            output[j+1] = (uint8_t)((input[i] >> 8) & 0xff);
            output[j+2] = (uint8_t)((input[i] >> 16) & 0xff);
            output[j+3] = (uint8_t)((input[i] >> 24) & 0xff);
        }
    }

    static void decode(uint32_t* output, const uint8_t* input, size_t len) {
        for (size_t i = 0, j = 0; j < len; i++, j += 4) {
            output[i] = ((uint32_t)input[j]) | 
                        (((uint32_t)input[j+1]) << 8) | 
                        (((uint32_t)input[j+2]) << 16) | 
                        (((uint32_t)input[j+3]) << 24);
        }
    }
};

// SHA-256 implementation class
class SHA256 {
public:
    SHA256() { reset(); }

    void update(const uint8_t* data, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            m_data[m_blocklen++] = data[i];
            if (m_blocklen == 64) {
                transform();
                m_bitlen += 512;
                m_blocklen = 0;
            }
        }
    }

    std::string finalize() {
        uint64_t i = m_blocklen;
        if (m_blocklen < 56) {
            m_data[i++] = 0x80;
            while (i < 56) {
                m_data[i++] = 0x00;
            }
        } else {
            m_data[i++] = 0x80;
            while (i < 64) {
                m_data[i++] = 0x00;
            }
            transform();
            std::fill(m_data.begin(), m_data.begin() + 56, 0);
        }

        m_bitlen += m_blocklen * 8;
        m_data[63] = (uint8_t)(m_bitlen & 0xFF);
        m_data[62] = (uint8_t)((m_bitlen >> 8) & 0xFF);
        m_data[61] = (uint8_t)((m_bitlen >> 16) & 0xFF);
        m_data[60] = (uint8_t)((m_bitlen >> 24) & 0xFF);
        m_data[59] = (uint8_t)((m_bitlen >> 32) & 0xFF);
        m_data[58] = (uint8_t)((m_bitlen >> 40) & 0xFF);
        m_data[57] = (uint8_t)((m_bitlen >> 48) & 0xFF);
        m_data[56] = (uint8_t)((m_bitlen >> 56) & 0xFF);
        transform();

        std::stringstream ss;
        for (int i = 0; i < 8; ++i) {
            ss << std::hex << std::setw(8) << std::setfill('0') << m_state[i];
        }
        return ss.str();
    }

private:
    std::array<uint8_t, 64> m_data;
    uint32_t m_blocklen;
    uint64_t m_bitlen;
    std::array<uint32_t, 8> m_state;

    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    void reset() {
        m_blocklen = 0;
        m_bitlen = 0;
        m_state[0] = 0x6a09e667;
        m_state[1] = 0xbb67ae85;
        m_state[2] = 0x3c6ef372;
        m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f;
        m_state[5] = 0x9b05688c;
        m_state[6] = 0x1f83d9ab;
        m_state[7] = 0x5be0cd19;
    }

    static inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    void transform() {
        uint32_t a, b, c, d, e, f, g, h, t1, t2;
        std::array<uint32_t, 64> w;

        for (int i = 0, j = 0; i < 16; ++i, j += 4) {
            w[i] = ((uint32_t)m_data[j] << 24) | ((uint32_t)m_data[j + 1] << 16) |
                   ((uint32_t)m_data[j + 2] << 8) | ((uint32_t)m_data[j + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        a = m_state[0];
        b = m_state[1];
        c = m_state[2];
        d = m_state[3];
        e = m_state[4];
        f = m_state[5];
        g = m_state[6];
        h = m_state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t ep1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            t1 = h + ep1 + ch + K[i] + w[i];
            uint32_t ep0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            t2 = ep0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        m_state[0] += a;
        m_state[1] += b;
        m_state[2] += c;
        m_state[3] += d;
        m_state[4] += e;
        m_state[5] += f;
        m_state[6] += g;
        m_state[7] += h;
    }
};

// Computes MD5 and SHA-256 for a file
struct FileHashes {
    std::string md5;
    std::string sha256;
};

inline FileHashes hashFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Warning: Could not open file for hashing: " << filepath << std::endl;
        return { "FILE_NOT_FOUND", "FILE_NOT_FOUND" };
    }

    MD5 md5;
    SHA256 sha256;
    char buffer[4096];

    while (file.read(buffer, sizeof(buffer))) {
        md5.update(reinterpret_cast<const uint8_t*>(buffer), file.gcount());
        sha256.update(reinterpret_cast<const uint8_t*>(buffer), file.gcount());
    }
    if (file.gcount() > 0) {
        md5.update(reinterpret_cast<const uint8_t*>(buffer), file.gcount());
        sha256.update(reinterpret_cast<const uint8_t*>(buffer), file.gcount());
    }

    return { md5.finalize(), sha256.finalize() };
}

} // namespace Hasher

#endif // HASHER_HPP
