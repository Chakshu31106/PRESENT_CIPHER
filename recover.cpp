
#include <bits/stdc++.h>
using namespace std;

using u64 = uint64_t;
using i64 = int64_t;
using u128 = unsigned __int128;

const int ROUNDS = 6;

const int M = 1 << 16; 

// ALPHA selects a plaintext bit.
const u64 ALPHA = 0x200000ULL;
//BETA selects four bits in the internal state before the 6th S-box.
const u64 BETA  = 0x20002000200020ULL;

// PRESENT S-box.
const int SBOX[16] = {
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
};

int INV_SBOX[16];

// Active BETA nibbles, numbered from the least significant nibble.
const int ACTIVE[4] = {1, 5, 9, 13};

// Combined S-box + P-layer lookup table.

//This table stores precomputed results for combining the S-box layer and P-layer.

// There are four 16-bit chunks in a 64-bit state.
// Each 16-bit chunk has (2^{16}=65,536) possible values.
u64 SP[4][1 << 16];

int parity64(u64 x) {
    return __builtin_parityll(x);
}
// it tells where the bit moves during PRESENT p layer

int pBit(int i) {
    if (i == 63) return 63;
    return (16 * i) % 63;
}

void initSBoxes() {
    for (int i = 0; i < 16; i++) {
        INV_SBOX[SBOX[i]] = i;
    }
}

// Precompute S-box + P-layer for each 16-bit chunk.
void initSPTable() {
    for (int chunk = 0; chunk < 4; chunk++) {
        //The inner loop considers every possible 16-bit value for that chunk.
        for (int value = 0; value < (1 << 16); value++) {
            u64 result = 0;

            for (int local = 0; local < 4; local++) {
                //extracts one nibble.
                int nibble = (value >> (4 * local)) & 15;
                int substituted = SBOX[nibble];
                //This calculates the nibble's position in the full 64-bit state.
                int absoluteNibble = 4 * chunk + local;

                for (int b = 0; b < 4; b++) {
                    if ((substituted >> b) & 1) {
                        int sourceBit = 4 * absoluteNibble + b;
                        int destinationBit = pBit(sourceBit);

                        result |= 1ULL << destinationBit;
                    }
                }
            }
            //stores the result in the lookup table.
            SP[chunk][value] = result;
        }
    }
}

u64 sBoxPermutation(u64 state) {
    return SP[0][state & 0xFFFFULL]
         | SP[1][(state >> 16) & 0xFFFFULL]
         | SP[2][(state >> 32) & 0xFFFFULL]
         | SP[3][(state >> 48) & 0xFFFFULL];
}


// PRESENT-80 key schedule
// Returns K1 ... K32.

array<u64, 32> generateRoundKeys(u128 masterKey) {
    const u128 MASK80 = ((u128)1 << 80) - 1; //11111.......11

    array<u64, 32> roundKeys{};

    for (int r = 0; r < 32; r++) {
        roundKeys[r] = (u64)(masterKey >> 16);

        if (r == 31) break;

        // Rotate the 80-bit register left by 61.
        masterKey =
            ((masterKey << 61) & MASK80) |
            (masterKey >> 19);

        // Substitute the most significant nibble.
        int top = (int)((masterKey >> 76) & 15);

        masterKey &= ~((u128)15 << 76);
        masterKey |= (u128)SBOX[top] << 76;

        // XOR round counter into bits 19..15.
        masterKey ^= (u128)(r + 1) << 15;
    }

    return roundKeys;
}

//Why do we need full encryption if the attack uses six rounds?

// To check that our PRESENT implementation behaves correctly. The code compares its result against a known standard test vector before running the attack.
u64 encryptFull(u64 plaintext, const array<u64, 32>& keys) {
    u64 state = plaintext;

    for (int r = 0; r < 31; r++) {
        state ^= keys[r];
        state = sBoxPermutation(state);
    }
    state ^= keys[31];
    //The final state is returned as the ciphertext.
    return state;
}

// the 6 round encryption ----->
u64 encryptReduced(u64 plaintext, const array<u64, 32>& keys) {
    u64 state = plaintext;
    for (int r = 0; r < ROUNDS; r++) {
        state ^= keys[r];
        state = sBoxPermutation(state);
    }

    state ^= keys[ROUNDS];
    return state;
}

// Extract the four ciphertext nibbles corresponding to the
// S-box outputs at positions 1, 5, 9 and 13 BEFORE the P-layer.

//This function takes a 64-bit value and extracts 16 selected bits---->
uint16_t packSelectedBits(u64 state) {
    uint16_t packed = 0;

    for (int j = 0; j < 4; j++) {
        int p = ACTIVE[j];

        // visist the 4 bits each of the nibble
        for (int b = 0; b < 4; b++) {
            // bit position after the p layer
            int destinationBit = pBit(4 * p + b);
            // this extracts that one bit from the state
            int bit = (state >> destinationBit) & 1ULL;

            //This puts the extracted bit into the correct position of the 16-bit packed value.
            packed |= (uint16_t)(bit << (4 * j + b));
        }
    }
    return packed;
}


// Given the four selected S-box output nibbles:

// 1. Invert each nibble's S-box.
// 2. Evaluate the BETA parity on the recovered state.

// This evaluates the selected output-side approximation.

int evaluateBetaParity(uint16_t x) {
    u64 state = 0;

    for (int j = 0; j < 4; j++) {
        int nibble = (x >> (4 * j)) & 15;
        int recovered = INV_SBOX[nibble];

        state |= (u64)recovered << (4 * ACTIVE[j]);
    }
    return parity64(state & BETA);
}

// Fast Walsh-Hadamard transform ------>
void fwht(vector<i64>& a) {
    int n = (int)a.size();

    // n here is = 2^16
    for (int len = 1; len < n; len <<= 1) {
        // len goes to 1,2,4,8,16,.....32768

        for (int i = 0; i < n; i += 2 * len) {
            for (int j = 0; j < len; j++) {
                i64 x = a[i + j];
                i64 y = a[i + j + len];

                a[i + j]       = x + y;
                a[i + j + len] = x - y;
            }
        }
    }
}

void printGuess(uint32_t guess) {
    cout << "0x"
         << hex << uppercase
         << setw(4) << setfill('0') << guess
         << dec << setfill(' ');
}

// Main attack

int main(int argc, char* argv[]) {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    // Default to 2^24 plaintext-ciphertext pairs.
    int logN = 24;

    if (argc >= 2) {
        logN = stoi(argv[1]);
    }

    if (logN < 1 || logN > 25) {
        cerr << "Usage: ./attack [logN], where 1 <= logN <= 25\n";
        return 1;
    }

    const u64 N = 1ULL << logN;

    initSBoxes();
    initSPTable();

    // Verify the full cipher implementation first.
    // Standard PRESENT-80 vector:
    // key        = 00000000000000000000
    // plaintext  = 0000000000000000
    // ciphertext = 5579C1387B228445

    array<u64, 32> zeroKeys = generateRoundKeys((u128)0);
    u64 testCiphertext = encryptFull(0, zeroKeys);

    if (testCiphertext != 0x5579C1387B228445ULL) {
        cerr << "ERROR: PRESENT known-answer test failed.\n";
        cerr << "Got: 0x" << hex << uppercase
             << testCiphertext << dec << '\n';
        return 1;
    }

    cout << "PRESENT-80 known-answer test: PASS\n";

    //This creates a 64-bit pseudorandom-number generator with a fixed seed.
    mt19937_64 rng(0xC0FFEE123456789ULL);

    // Generate a random 80-bit master key.
    u128 masterKey =
    // here we are taking 16 random bits and placing those bits in position 64 - 79
    //and rng() provides the remaining 64 bits then taking or of them to get 80bit value
        ((u128)(rng() & 0xFFFFULL) << 64) |
        (u128)rng();
        

    array<u64, 32> keys = generateRoundKeys(masterKey);

    cout << "\nSingle-trail PRESENT-80 linear attack\n";
    cout << "Reduced rounds: " << ROUNDS << '\n';
    cout << "Data pairs: 2^" << logN << " = " << N << '\n';
    cout << "Key guesses: " << M << "\n\n";

    // T[v] accumulates (-1)^parity(ALPHA & plaintext)
    // for pairs with the same packed ciphertext value v.

    vector<i64> T(M, 0);

    // Phase 1: Collect plaintext-ciphertext pairs.

    for (u64 i = 0; i < N; i++){
        u64 plaintext = rng();
        u64 ciphertext = encryptReduced(plaintext, keys);

        uint16_t v = packSelectedBits(ciphertext);

        int inputParity = parity64(plaintext & ALPHA);

        T[v] += inputParity ? -1 : 1;
    }

    cout << "Data generation complete.\n";

    // Phase 2: Build the parity-sign table.
    // F[x] = (-1)^evaluateBetaParity(x)

    vector<i64> F(M);

    for (int x = 0; x < M; x++) {
        F[x] = evaluateBetaParity((uint16_t)x) ? -1 : 1;
    }
    // Phase 3: Score all guesses using XOR convolution.

    // score[g] = sum_v T[v] * F[v XOR g]
    
    // FWHT reduces the scoring cost from O(2^32)
    // to O(16 * 2^16).

    vector<i64> A = T;
    vector<i64> B = F;

    fwht(A);
    fwht(B);

    for (int i = 0; i < M; i++) {
        A[i] *= B[i];
    }

    fwht(A);

    vector<pair<i64, uint32_t>> ranked;
    ranked.reserve(M);

    for (uint32_t g = 0; g < M; g++) {
        i64 signedScore = A[g] / M;
        ranked.push_back({llabs(signedScore), g});
    }

    sort(ranked.rbegin(), ranked.rend());
    // Phase 4: Simulation validation.
    //
    // In a real attack, the true key is unknown.
    // Here it is known because this program generated it.

    uint16_t correctGuess = packSelectedBits(keys[ROUNDS]);

    int correctRank = -1;
    i64 correctScore = 0;

    for (int i = 0; i < M; i++) {
        if (ranked[i].second == correctGuess) {
            correctRank = i + 1;
            correctScore = ranked[i].first;
            break;
        }
    }

    cout << "\nTop 10 guesses:\n";

    for (int i = 0; i < min(10, M); i++) {
        cout << setw(2) << (i + 1) << ". Guess = ";
        printGuess(ranked[i].second);
        cout << ", absolute score = " << ranked[i].first << '\n';
    }

    cout << "\nCorrect selected K7 bits: ";
    printGuess(correctGuess);
    cout << '\n';

    cout << "Correct guess absolute score: "
         << correctScore << '\n';

    cout << "Correct guess observed correlation magnitude: "
         << fixed << setprecision(8)
         << (double)correctScore / (double)N << '\n';

    cout << "Rank of correct guess: "
         << correctRank << " / " << M << '\n';

    cout << "\nNote: the correct guess is printed only for "
            "simulation validation.\n";

    return 0;
}
