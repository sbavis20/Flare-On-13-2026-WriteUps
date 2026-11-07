// ToxicMiner solver: modified SHA-256d key derivation + RC4
// Build: gcc -O3 -march=native -o solve solve.c
// Usage: ./solve            -> print test vectors for serial 0 and 1
//        ./solve START END  -> search serials in [START, END)
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// Standard SHA-256 K[0..31], but K[0] and K[1] swapped (as in the binary)
static const uint32_t K[32] = {
    0x71374491, 0x428a2f98, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967};

static const uint32_t IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

// 256 bytes at 0x1401bd270 (these are just the SHA-256 K table bytes, little-endian)
static uint8_t T[256];

// 51 bytes at 0x1401bd3b0
static const uint8_t CT[51] = {
    0xf4, 0xf9, 0x65, 0x9f, 0x31, 0xf3, 0xda, 0x5c, 0xf1, 0x37, 0xa1, 0xb8, 0xcf, 0x90, 0xa1, 0x58, 0x1e,
    0xeb, 0xe4, 0x99, 0xa7, 0xc1, 0x1b, 0x15, 0x02, 0xaf, 0x74, 0x63, 0xd3, 0xb2, 0x19, 0x28, 0x66, 0xde,
    0x3d, 0xe9, 0x71, 0x63, 0xe7, 0x75, 0xdf, 0xe4, 0xab, 0x61, 0x6f, 0xb9, 0x0c, 0x27, 0x89, 0xfc, 0x87};

// FUN_140135240 (called with swap = 0)
static void transform(uint32_t st[8], const uint32_t m[16]) {
    uint32_t w[32];
    for (int i = 0; i < 16; i++) w[i] = m[i];
    for (int i = 16; i < 32; i++)  // schedule only extended to 32 words
        w[i] = w[i - 16] + (ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 7] +
               (ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10));

    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 32; i++) {  // 32 rounds, not 64
        uint32_t ch = ((f + g) & e) ^ g;               // standard: ((f ^ g) & e) ^ g
        uint32_t mj = ((b & c) + (c & a)) ^ (a & b);   // standard: (a&b) ^ (a&c) ^ (b&c)
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ch + K[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;

    // tail scramble on word 0
    uint32_t inner;
    memcpy(&inner, (uint8_t *)st + (st[1] % 28), 4);
    st[0] ^= T[st[0] & 0xff] ^ inner;
}

// FUN_140134ca0(serial, 0x0b501e7e, out)
static void derive_key(uint32_t serial, uint8_t key[16]) {
    uint32_t h1[8], h2[8];
    memcpy(h1, IV, 32);
    memcpy(h2, IV, 32);
    uint32_t m1[16] = {serial, 0x0b501e7e, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40};
    transform(h1, m1);
    uint32_t m2[16] = {h1[0], h1[1], h1[2], h1[3], h1[4], h1[5], h1[6], h1[7],
                       0x80000000, 0, 0, 0, 0, 0, 0, 0x100};
    transform(h2, m2);
    memcpy(key, h2, 16);  // raw little-endian bytes of the first 4 state words
}

// FUN_140134d70 = plain RC4. Returns 1 if every output byte is printable ASCII.
static int rc4_printable(const uint8_t key[16], uint8_t out[52]) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = i;
    for (int i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + key[i & 15]) & 0xff;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    }
    int i = 0, j = 0;
    for (int n = 0; n < 51; n++) {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
        out[n] = CT[n] ^ S[(S[i] + S[j]) & 0xff];
        if (out[n] < 0x20 || out[n] > 0x7e) return 0;  // early exit
    }
    out[51] = 0;
    return 1;
}

int main(int argc, char **argv) {
    FILE *f = fopen("sbox.bin", "rb");
    if (!f || fread(T, 1, 256, f) != 256) { fprintf(stderr, "need sbox.bin\n"); return 1; }
    fclose(f);

    uint8_t key[16], pt[52];
    if (argc < 3) {
        for (uint32_t s = 0; s < 2; s++) {
            derive_key(s, key);
            printf("serial %08x -> key ", s);
            for (int i = 0; i < 16; i++) printf("%02x", key[i]);
            printf("\n");
        }
        return 0;
    }
    uint64_t start = strtoull(argv[1], 0, 0), end = strtoull(argv[2], 0, 0);
    for (uint64_t s = start; s < end; s++) {
        derive_key((uint32_t)s, key);
        if (rc4_printable(key, pt)) {
            printf("serial=%08llX  flag=%s\n", (unsigned long long)s, (char *)pt);
            fflush(stdout);
        }
    }
    return 0;
}
