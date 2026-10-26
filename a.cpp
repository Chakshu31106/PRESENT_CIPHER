
#include <bits/stdc++.h>
using namespace std;

using u64 = uint64_t;
using u128 = unsigned __int128;

// PRESENT 4-bit S-box
const int SBOX[16] = {
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
};

// Inverse S-box
const int INV_SBOX[16] = {
    0x5, 0xE, 0xF, 0x8,
    0xC, 0x1, 0x2, 0xD,
    0xB, 0x4, 0x6, 0x3,
    0x0, 0x7, 0x9, 0xA
};

// Apply S-box to all 16 nibbles
u64 sBoxLayer(u64 state) {
    u64 result = 0;

    for (int i = 0; i < 16; i++) {
        u64 nibble = (state >> (4 * i)) & 0xFULL;
        result |= (u64)SBOX[nibble] << (4 * i);
    }

    return result;
}

// Apply inverse S-box to all 16 nibbles
u64 inverseSBoxLayer(u64 state) {
    u64 result = 0;

    for (int i = 0; i < 16; i++) {
        u64 nibble = (state >> (4 * i)) & 0xFULL;
        result |= (u64)INV_SBOX[nibble] << (4 * i);
    }

    return result;
}

// PRESENT P-layer
// Input bit i moves to position P(i).
u64 pLayer(u64 state) {
    u64 result = 0;

    for (int i = 0; i < 64; i++) {
        int destination;

        if (i == 63)
            destination = 63;
        else
            destination = (16 * i) % 63;

        u64 bit = (state >> i) & 1ULL;
        result |= bit << destination;
    }

    return result;
}

// Inverse P-layer
u64 inversePLayer(u64 state) {
    u64 result = 0;

    for (int i = 0; i < 64; i++) {
        int destination;

        if (i == 63)
            destination = 63;
        else
            destination = (16 * i) % 63;

        u64 bit = (state >> destination) & 1ULL;
        result |= bit << i;
    }

    return result;
}

// Generate 32 round keys for PRESENT-80
array<u64, 32> generateRoundKeys(u128 key) {
    array<u64, 32> roundKeys{};

    const u128 MASK80 = (((u128)1 << 80) - 1);

    for (int round = 1; round <= 32; round++) {
        // Extract the leftmost 64 bits as the round key
        roundKeys[round - 1] = (u64)(key >> 16);

        if (round == 32)
            break;

        // 1. Rotate the 80-bit key register left by 61
        key = ((key << 61) | (key >> 19)) & MASK80;

        // 2. Apply S-box to the leftmost nibble
        int topNibble = (int)((key >> 76) & 0xFULL);

        key &= ~((u128)0xFULL << 76);
        key |= (u128)SBOX[topNibble] << 76;

        // 3. XOR round counter into bits 19..15
        key ^= (u128)round << 15;
    }

    return roundKeys;
}

// Encryption
u64 encrypt(u64 plaintext, const array<u64, 32>& roundKeys) {
    u64 state = plaintext;

    for (int round = 0; round < 31; round++) {
        state ^= roundKeys[round]; // AddRoundKey
        state = sBoxLayer(state);  // Substitution
        state = pLayer(state);     // Permutation
    }

    // Final AddRoundKey using K32
    state ^= roundKeys[31];

    return state;
}

// Decryption
u64 decrypt(u64 ciphertext, const array<u64, 32>& roundKeys) {
    u64 state = ciphertext ^ roundKeys[31];

    for (int round = 30; round >= 0; round--) {
        state = inversePLayer(state);
        state = inverseSBoxLayer(state);
        state ^= roundKeys[round];
    }

    return state;
}

int main() {
    // Standard PRESENT-80 test vector
    // Key       = 00000000000000000000 (80 bits)
    // Plaintext = 0000000000000000 (64 bits)
    // Expected ciphertext = 5579C1387B228445

    u128 key = 0;
    u64 plaintext = 1232123134532345;

    auto roundKeys = generateRoundKeys(key);

    u64 ciphertext = encrypt(plaintext, roundKeys);
    u64 recovered = decrypt(ciphertext, roundKeys);

    cout << uppercase << hex << setfill('0');

    cout << "Plaintext : "
         << setw(16) << plaintext << '\n';

    cout << "Ciphertext: "
         << setw(16) << ciphertext << '\n';

    cout << "Decrypted : "
         << setw(16) << recovered << '\n';

    return 0;
}
