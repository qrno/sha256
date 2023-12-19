
#include <iomanip>
#include <array>
#include <vector>
#include <cstdint>
#include <bitset>
#include <span>
#include <bit>

using std::byte;
using digest = std::array<uint, 8>;

uint CH(uint x, uint y, uint z) { return (x & y) ^ ((~x) & z); }
uint MAJ(uint x, uint y, uint z) { return (x & y) ^ (x & z) ^ (y & z); }

uint BSIG0(uint x) { return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22); }
uint BSIG1(uint x) { return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25); }

uint SSIG0(uint x) { return std::rotr(x,  7) ^ std::rotr(x, 18) ^ (x >>  3); }
uint SSIG1(uint x) { return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10); }

static constexpr std::array<uint, 64> K{
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
  0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
  0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
  0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
  0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
  0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static constexpr digest H_init {
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
};

std::vector<byte> pad_message(std::vector<byte> const& A) {
  auto B = A;
  B.reserve(64);

  B.push_back(byte{0b10000000});
  if (size(B) <= 56) B.resize(56);
  while (8 * ssize(B) % 512 != 448)
    B.push_back(byte{0});

  unsigned long long len = 8*size(A);
  for (int i = 7; i >= 0; i--)
    B.push_back((byte)(len >> (i*8)));

  return B;
}

digest perform_hash(std::vector<byte> const& A) {
  std::vector<std::array<uint, 16>> M;
  for (uint i = 0; i < size(A)/64; i++) {
    M.push_back(std::array<uint, 16>());
    for (uint j = 0; j < 16; j++) {
      for (uint k = 0; k < 4; k++) {
        M.back()[j] = M.back()[j] << 8;
        M.back()[j] |= (uint)A[i*64 + j*4 + k];
      }
    }
  }

  auto H = H_init;

  for (uint i = 0; i < size(M); i++) {
    std::array<uint, 64> W;
    for (uint t = 0; t < 16; t++) {
      W[t] = M[i][t];
    }
    for (uint t = 16; t < 64; t++) {
      W[t] = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16];
    }

    uint a = H[0];
    uint b = H[1];
    uint c = H[2];
    uint d = H[3];
    uint e = H[4];
    uint f = H[5];
    uint g = H[6];
    uint h = H[7];

    for (uint t = 0; t < 64; t++) {
      uint T1 = h + BSIG1(e) + CH(e, f, g) + K[t] + W[t];
      uint T2 = BSIG0(a) + MAJ(a,b,c);

      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
  }

  return H;
}

digest sha256(std::string const& s) {
  std::vector<byte> v(size(s));
  for (int i = 0; i < size(s); i++)
    v[i] = (byte)s[i];
  auto padded = pad_message(v);
  return perform_hash(padded);
}

int main() {
  digest best;
  std::fill(begin(best), end(best), 0xffffffff);

  for (unsigned long long i = 0; i < 1e7; i++) {
    digest h = sha256("quirino " + std::to_string(i));
    if (h < best) {
      best = h;
      std::cout << std::dec << std::setfill(' ') << std::setw(14) << i << " -> ";
      for (auto const& val : h) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << val << ' ';
      }
      std::cout << '\n';
    }
  }
}
