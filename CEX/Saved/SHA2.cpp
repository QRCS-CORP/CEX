#include "SHA2.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_DIGEST

using Tools::IntegerTools;
using Tools::MemoryTools;

//~~~SHA2 K Constants~~~//

const std::vector<uint> SHA2::SHA2256_RC64
{
	0x428A2F98UL, 0x71374491UL, 0xB5C0FBCFUL, 0xE9B5DBA5UL, 0x3956C25BUL, 0x59F111F1UL, 0x923F82A4UL, 0xAB1C5ED5UL,
	0xD807AA98UL, 0x12835B01UL, 0x243185BEUL, 0x550C7DC3UL, 0x72BE5D74UL, 0x80DEB1FEUL, 0x9BDC06A7UL, 0xC19BF174UL,
	0xE49B69C1UL, 0xEFBE4786UL, 0x0FC19DC6UL, 0x240CA1CCUL, 0x2DE92C6FUL, 0x4A7484AAUL, 0x5CB0A9DCUL, 0x76F988DAUL,
	0x983E5152UL, 0xA831C66DUL, 0xB00327C8UL, 0xBF597FC7UL, 0xC6E00BF3UL, 0xD5A79147UL, 0x06CA6351UL, 0x14292967UL,
	0x27B70A85UL, 0x2E1B2138UL, 0x4D2C6DFCUL, 0x53380D13UL, 0x650A7354UL, 0x766A0ABBUL, 0x81C2C92EUL, 0x92722C85UL,
	0xA2BFE8A1UL, 0xA81A664BUL, 0xC24B8B70UL, 0xC76C51A3UL, 0xD192E819UL, 0xD6990624UL, 0xF40E3585UL, 0x106AA070UL,
	0x19A4C116UL, 0x1E376C08UL, 0x2748774CUL, 0x34B0BCB5UL, 0x391C0CB3UL, 0x4ED8AA4AUL, 0x5B9CCA4FUL, 0x682E6FF3UL,
	0x748F82EEUL, 0x78A5636FUL, 0x84C87814UL, 0x8CC70208UL, 0x90BEFFFAUL, 0xA4506CEBUL, 0xBEF9A3F7UL, 0xC67178F2UL
};

const std::vector<ulong> SHA2::SHA2512_RC80
{
	0X428A2F98D728AE22ULL, 0X7137449123EF65CDULL, 0XB5C0FBCFEC4D3B2FULL, 0XE9B5DBA58189DBBCULL, 0X3956C25BF348B538ULL, 0X59F111F1B605D019ULL, 0X923F82A4AF194F9BULL, 0XAB1C5ED5DA6D8118ULL,
	0XD807AA98A3030242ULL, 0X12835B0145706FBEULL, 0X243185BE4EE4B28CULL, 0X550C7DC3D5FFB4E2ULL, 0X72BE5D74F27B896FULL, 0X80DEB1FE3B1696B1ULL, 0X9BDC06A725C71235ULL, 0XC19BF174CF692694ULL,
	0XE49B69C19EF14AD2ULL, 0XEFBE4786384F25E3ULL, 0X0FC19DC68B8CD5B5ULL, 0X240CA1CC77AC9C65ULL, 0X2DE92C6F592B0275ULL, 0X4A7484AA6EA6E483ULL, 0X5CB0A9DCBD41FBD4ULL, 0X76F988DA831153B5ULL,
	0X983E5152EE66DFABULL, 0XA831C66D2DB43210ULL, 0XB00327C898FB213FULL, 0XBF597FC7BEEF0EE4ULL, 0XC6E00BF33DA88FC2ULL, 0XD5A79147930AA725ULL, 0X06CA6351E003826FULL, 0X142929670A0E6E70ULL,
	0X27B70A8546D22FFCULL, 0X2E1B21385C26C926ULL, 0X4D2C6DFC5AC42AEDULL, 0X53380D139D95B3DFULL, 0X650A73548BAF63DEULL, 0X766A0ABB3C77B2A8ULL, 0X81C2C92E47EDAEE6ULL, 0X92722C851482353BULL,
	0XA2BFE8A14CF10364ULL, 0XA81A664BBC423001ULL, 0XC24B8B70D0F89791ULL, 0XC76C51A30654BE30ULL, 0XD192E819D6EF5218ULL, 0XD69906245565A910ULL, 0XF40E35855771202AULL, 0X106AA07032BBD1B8ULL,
	0X19A4C116B8D2D0C8ULL, 0X1E376C085141AB53ULL, 0X2748774CDF8EEB99ULL, 0X34B0BCB5E19B48A8ULL, 0X391C0CB3C5C95A63ULL, 0X4ED8AA4AE3418ACBULL, 0X5B9CCA4F7763E373ULL, 0X682E6FF3D6B2B8A3ULL,
	0X748F82EE5DEFB2FCULL, 0X78A5636F43172F60ULL, 0X84C87814A1F0AB72ULL, 0X8CC702081A6439ECULL, 0X90BEFFFA23631E28ULL, 0XA4506CEBDE82BDE9ULL, 0XBEF9A3F7B2C67915ULL, 0XC67178F2E372532BULL,
	0XCA273ECEEA26619CULL, 0XD186B8C721C0C207ULL, 0XEADA7DD6CDE0EB1EULL, 0XF57D4F7FEE6ED178ULL, 0X06F067AA72176FBAULL, 0X0A637DC5A2C898A6ULL, 0X113F9804BEF90DAEULL, 0X1B710B35131C471BULL,
	0X28DB77F523047D84ULL, 0X32CAAB7B40C72493ULL, 0X3C9EBE0A15C9BEBCULL, 0X431D67C49C100D4CULL, 0X4CC5D4BECB3E42B6ULL, 0X597F299CFC657E2AULL, 0X5FCB6FAB3AD6FAECULL, 0X6C44198C4A475817ULL
};

const std::vector<uint> SHA2::SHA2256State =
{
	0x6A09E667UL,
	0xBB67AE85UL,
	0x3C6EF372UL,
	0xA54FF53AUL,
	0x510E527FUL,
	0x9B05688CUL,
	0x1F83D9ABUL,
	0x5BE0CD19UL
};

const std::vector<ulong> SHA2::SHA384State =
{
	0xCBBB9D5DC1059ED8ULL,
	0x629A292A367CD507ULL,
	0x9159015A3070DD17ULL,
	0x152FECD8F70E5939ULL,
	0x67332667FFC00B31ULL,
	0x8EB44A8768581511ULL,
	0xDB0C2E0D64F98FA7ULL,
	0x47B5481DBEFA4FA4ULL
};

const std::vector<ulong> SHA2::SHA2512State =
{
	0x6A09E667F3BCC908ULL,
	0xBB67AE8584CAA73BULL,
	0x3C6EF372FE94F82BULL,
	0xA54FF53A5F1D36F1ULL,
	0x510E527FADE682D1ULL,
	0x9B05688C2B3E6C1FULL,
	0x1F83D9ABFB41BD6BULL,
	0x5BE0CD19137E2179ULL
};

//~~~Public Functions~~~//

//~~~SHA2-256~~~//


void SHA2::PermuteR64P512C(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State)
{
	std::array<uint, 8> A;
	std::array<uint, 64> W;
	size_t i;
	size_t j;

	MemoryTools::Copy(State, 0, A, 0, State.size() * sizeof(uint));

#if defined(CEX_IS_LITTLE_ENDIAN)
	for (i = 0; i < 16; ++i)
	{
		W[i] = IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)));
	}
#else
	MemoryTools::Copy(Input, InOffset, W, 0, A.size() * sizeof(uint));
#endif

	for (i = 16; i < 64; i++)
	{
		W[i] = Theta1(W[i - 2]) + W[i - 7] + Theta0(W[i - 15]) + W[i - 16];
	}

	j = 0;

	for (i = 0; i < 8; ++i)
	{
		Round256(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], SHA2256_RC64[j], W[j]);
		++j;
		Round256(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], SHA2256_RC64[j], W[j]);
		++j;
		Round256(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], SHA2256_RC64[j], W[j]);
		++j;
		Round256(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], SHA2256_RC64[j], W[j]);
		++j;
		Round256(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], SHA2256_RC64[j], W[j]);
		++j;
		Round256(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], SHA2256_RC64[j], W[j]);
		++j;
		Round256(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], SHA2256_RC64[j], W[j]);
		++j;
		Round256(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], SHA2256_RC64[j], W[j]);
		++j;
	}

	State[0] += A[0];
	State[1] += A[1];
	State[2] += A[2];
	State[3] += A[3];
	State[4] += A[4];
	State[5] += A[5];
	State[6] += A[6];
	State[7] += A[7];
}

void SHA2::PermuteR64P512U(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State)
{
	uint A;
	uint B;
	uint C;
	uint D;
	uint E;
	uint F;
	uint G;
	uint H;
	uint R;
	uint W0;
	uint W1;
	uint W2;
	uint W3;
	uint W4;
	uint W5;
	uint W6;
	uint W7;
	uint W8;
	uint W9;
	uint W10;
	uint W11;
	uint W12;
	uint W13;
	uint W14;
	uint W15;

	A = State[0];
	B = State[1];
	C = State[2];
	D = State[3];
	E = State[4];
	F = State[5];
	G = State[6];
	H = State[7];

	W0 = IntegerTools::BeBytesTo32(Input, InOffset);
	W1 = IntegerTools::BeBytesTo32(Input, InOffset + 4);
	W2 = IntegerTools::BeBytesTo32(Input, InOffset + 8);
	W3 = IntegerTools::BeBytesTo32(Input, InOffset + 12);
	W4 = IntegerTools::BeBytesTo32(Input, InOffset + 16);
	W5 = IntegerTools::BeBytesTo32(Input, InOffset + 20);
	W6 = IntegerTools::BeBytesTo32(Input, InOffset + 24);
	W7 = IntegerTools::BeBytesTo32(Input, InOffset + 28);
	W8 = IntegerTools::BeBytesTo32(Input, InOffset + 32);
	W9 = IntegerTools::BeBytesTo32(Input, InOffset + 36);
	W10 = IntegerTools::BeBytesTo32(Input, InOffset + 40);
	W11 = IntegerTools::BeBytesTo32(Input, InOffset + 44);
	W12 = IntegerTools::BeBytesTo32(Input, InOffset + 48);
	W13 = IntegerTools::BeBytesTo32(Input, InOffset + 52);
	W14 = IntegerTools::BeBytesTo32(Input, InOffset + 56);
	W15 = IntegerTools::BeBytesTo32(Input, InOffset + 60);

	R = H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + W0 + 0x428A2F98UL;
	D += R;
	H = R + ((((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
	R = G + (((D >> 6) | (D << 26)) ^ ((D >> 11) | (D << 21)) ^ ((D >> 25) | (D << 7))) + ((D & E) ^ (~D & F)) + W1 + 0x71374491UL;
	C += R;
	G = R + ((((H >> 2) | (H << 30)) ^ ((H >> 13) | (H << 19)) ^ ((H >> 22) | (H << 10))) + ((H & A) ^ (H & B) ^ (A & B)));
	R = F + (((C >> 6) | (C << 26)) ^ ((C >> 11) | (C << 21)) ^ ((C >> 25) | (C << 7))) + ((C & D) ^ (~C & E)) + W2 + 0xB5C0FBCFUL;
	B += R;
	F = R + ((((G >> 2) | (G << 30)) ^ ((G >> 13) | (G << 19)) ^ ((G >> 22) | (G << 10))) + ((G & H) ^ (G & A) ^ (H & A)));
	R = E + (((B >> 6) | (B << 26)) ^ ((B >> 11) | (B << 21)) ^ ((B >> 25) | (B << 7))) + ((B & C) ^ (~B & D)) + W3 + 0xE9B5DBA5UL;
	A += R;
	E = R + ((((F >> 2) | (F << 30)) ^ ((F >> 13) | (F << 19)) ^ ((F >> 22) | (F << 10))) + ((F & G) ^ (F & H) ^ (G & H)));
	R = D + (((A >> 6) | (A << 26)) ^ ((A >> 11) | (A << 21)) ^ ((A >> 25) | (A << 7))) + ((A & B) ^ (~A & C)) + W4 + 0x3956C25BUL;
	H += R;
	D = R + ((((E >> 2) | (E << 30)) ^ ((E >> 13) | (E << 19)) ^ ((E >> 22) | (E << 10))) + ((E & F) ^ (E & G) ^ (F & G)));
	R = C + (((H >> 6) | (H << 26)) ^ ((H >> 11) | (H << 21)) ^ ((H >> 25) | (H << 7))) + ((H & A) ^ (~H & B)) + W5 + 0x59F111F1UL;
	G += R;
	C = R + ((((D >> 2) | (D << 30)) ^ ((D >> 13) | (D << 19)) ^ ((D >> 22) | (D << 10))) + ((D & E) ^ (D & F) ^ (E & F)));
	R = B + (((G >> 6) | (G << 26)) ^ ((G >> 11) | (G << 21)) ^ ((G >> 25) | (G << 7))) + ((G & H) ^ (~G & A)) + W6 + 0x923F82A4UL;
	F += R;
	B = R + ((((C >> 2) | (C << 30)) ^ ((C >> 13) | (C << 19)) ^ ((C >> 22) | (C << 10))) + ((C & D) ^ (C & E) ^ (D & E)));
	R = A + (((F >> 6) | (F << 26)) ^ ((F >> 11) | (F << 21)) ^ ((F >> 25) | (F << 7))) + ((F & G) ^ (~F & H)) + W7 + 0xAB1C5ED5UL;
	E += R;
	A = R + ((((B >> 2) | (B << 30)) ^ ((B >> 13) | (B << 19)) ^ ((B >> 22) | (B << 10))) + ((B & C) ^ (B & D) ^ (C & D)));
	R = H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + W8 + 0xD807AA98UL;
	D += R;
	H = R + ((((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
	R = G + (((D >> 6) | (D << 26)) ^ ((D >> 11) | (D << 21)) ^ ((D >> 25) | (D << 7))) + ((D & E) ^ (~D & F)) + W9 + 0x12835B01UL;
	C += R;
	G = R + ((((H >> 2) | (H << 30)) ^ ((H >> 13) | (H << 19)) ^ ((H >> 22) | (H << 10))) + ((H & A) ^ (H & B) ^ (A & B)));
	R = F + (((C >> 6) | (C << 26)) ^ ((C >> 11) | (C << 21)) ^ ((C >> 25) | (C << 7))) + ((C & D) ^ (~C & E)) + W10 + 0x243185BEUL;
	B += R;
	F = R + ((((G >> 2) | (G << 30)) ^ ((G >> 13) | (G << 19)) ^ ((G >> 22) | (G << 10))) + ((G & H) ^ (G & A) ^ (H & A)));
	R = E + (((B >> 6) | (B << 26)) ^ ((B >> 11) | (B << 21)) ^ ((B >> 25) | (B << 7))) + ((B & C) ^ (~B & D)) + W11 + 0x550C7DC3UL;
	A += R;
	E = R + ((((F >> 2) | (F << 30)) ^ ((F >> 13) | (F << 19)) ^ ((F >> 22) | (F << 10))) + ((F & G) ^ (F & H) ^ (G & H)));
	R = D + (((A >> 6) | (A << 26)) ^ ((A >> 11) | (A << 21)) ^ ((A >> 25) | (A << 7))) + ((A & B) ^ (~A & C)) + W12 + 0x72BE5D74UL;
	H += R;
	D = R + ((((E >> 2) | (E << 30)) ^ ((E >> 13) | (E << 19)) ^ ((E >> 22) | (E << 10))) + ((E & F) ^ (E & G) ^ (F & G)));
	R = C + (((H >> 6) | (H << 26)) ^ ((H >> 11) | (H << 21)) ^ ((H >> 25) | (H << 7))) + ((H & A) ^ (~H & B)) + W13 + 0x80DEB1FEUL;
	G += R;
	C = R + ((((D >> 2) | (D << 30)) ^ ((D >> 13) | (D << 19)) ^ ((D >> 22) | (D << 10))) + ((D & E) ^ (D & F) ^ (E & F)));
	R = B + (((G >> 6) | (G << 26)) ^ ((G >> 11) | (G << 21)) ^ ((G >> 25) | (G << 7))) + ((G & H) ^ (~G & A)) + W14 + 0x9BDC06A7UL;
	F += R;
	B = R + ((((C >> 2) | (C << 30)) ^ ((C >> 13) | (C << 19)) ^ ((C >> 22) | (C << 10))) + ((C & D) ^ (C & E) ^ (D & E)));
	R = A + (((F >> 6) | (F << 26)) ^ ((F >> 11) | (F << 21)) ^ ((F >> 25) | (F << 7))) + ((F & G) ^ (~F & H)) + W15 + 0xC19BF174UL;
	E += R;
	A = R + ((((B >> 2) | (B << 30)) ^ ((B >> 13) | (B << 19)) ^ ((B >> 22) | (B << 10))) + ((B & C) ^ (B & D) ^ (C & D)));

	W0 += (((W14 >> 17) | (W14 << 15)) ^ ((W14 >> 19) | (W14 << 13)) ^ (W14 >> 10)) + W9 + (((W1 >> 7) | (W1 << 25)) ^ ((W1 >> 18) | (W1 << 14)) ^ (W1 >> 3));
	R = H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + W0 + 0xE49B69C1UL;
	D += R;
	H = R + ((((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
	W1 += (((W15 >> 17) | (W15 << 15)) ^ ((W15 >> 19) | (W15 << 13)) ^ (W15 >> 10)) + W10 + (((W2 >> 7) | (W2 << 25)) ^ ((W2 >> 18) | (W2 << 14)) ^ (W2 >> 3));
	R = G + (((D >> 6) | (D << 26)) ^ ((D >> 11) | (D << 21)) ^ ((D >> 25) | (D << 7))) + ((D & E) ^ (~D & F)) + W1 + 0xEFBE4786UL;
	C += R;
	G = R + ((((H >> 2) | (H << 30)) ^ ((H >> 13) | (H << 19)) ^ ((H >> 22) | (H << 10))) + ((H & A) ^ (H & B) ^ (A & B)));
	W2 += (((W0 >> 17) | (W0 << 15)) ^ ((W0 >> 19) | (W0 << 13)) ^ (W0 >> 10)) + W11 + (((W3 >> 7) | (W3 << 25)) ^ ((W3 >> 18) | (W3 << 14)) ^ (W3 >> 3));
	R = F + (((C >> 6) | (C << 26)) ^ ((C >> 11) | (C << 21)) ^ ((C >> 25) | (C << 7))) + ((C & D) ^ (~C & E)) + W2 + 0x0FC19DC6UL;
	B += R;
	F = R + ((((G >> 2) | (G << 30)) ^ ((G >> 13) | (G << 19)) ^ ((G >> 22) | (G << 10))) + ((G & H) ^ (G & A) ^ (H & A)));
	W3 += (((W1 >> 17) | (W1 << 15)) ^ ((W1 >> 19) | (W1 << 13)) ^ (W1 >> 10)) + W12 + (((W4 >> 7) | (W4 << 25)) ^ ((W4 >> 18) | (W4 << 14)) ^ (W4 >> 3));
	R = E + (((B >> 6) | (B << 26)) ^ ((B >> 11) | (B << 21)) ^ ((B >> 25) | (B << 7))) + ((B & C) ^ (~B & D)) + W3 + 0x240CA1CCUL;
	A += R;
	E = R + ((((F >> 2) | (F << 30)) ^ ((F >> 13) | (F << 19)) ^ ((F >> 22) | (F << 10))) + ((F & G) ^ (F & H) ^ (G & H)));
	W4 += (((W2 >> 17) | (W2 << 15)) ^ ((W2 >> 19) | (W2 << 13)) ^ (W2 >> 10)) + W13 + (((W5 >> 7) | (W5 << 25)) ^ ((W5 >> 18) | (W5 << 14)) ^ (W5 >> 3));
	R = D + (((A >> 6) | (A << 26)) ^ ((A >> 11) | (A << 21)) ^ ((A >> 25) | (A << 7))) + ((A & B) ^ (~A & C)) + W4 + 0x2DE92C6FUL;
	H += R;
	D = R + ((((E >> 2) | (E << 30)) ^ ((E >> 13) | (E << 19)) ^ ((E >> 22) | (E << 10))) + ((E & F) ^ (E & G) ^ (F & G)));
	W5 += (((W3 >> 17) | (W3 << 15)) ^ ((W3 >> 19) | (W3 << 13)) ^ (W3 >> 10)) + W14 + (((W6 >> 7) | (W6 << 25)) ^ ((W6 >> 18) | (W6 << 14)) ^ (W6 >> 3));
	R = C + (((H >> 6) | (H << 26)) ^ ((H >> 11) | (H << 21)) ^ ((H >> 25) | (H << 7))) + ((H & A) ^ (~H & B)) + W5 + 0x4A7484AAUL;
	G += R;
	C = R + ((((D >> 2) | (D << 30)) ^ ((D >> 13) | (D << 19)) ^ ((D >> 22) | (D << 10))) + ((D & E) ^ (D & F) ^ (E & F)));
	W6 += (((W4 >> 17) | (W4 << 15)) ^ ((W4 >> 19) | (W4 << 13)) ^ (W4 >> 10)) + W15 + (((W7 >> 7) | (W7 << 25)) ^ ((W7 >> 18) | (W7 << 14)) ^ (W7 >> 3));
	R = B + (((G >> 6) | (G << 26)) ^ ((G >> 11) | (G << 21)) ^ ((G >> 25) | (G << 7))) + ((G & H) ^ (~G & A)) + W6 + 0x5CB0A9DCUL;
	F += R;
	B = R + ((((C >> 2) | (C << 30)) ^ ((C >> 13) | (C << 19)) ^ ((C >> 22) | (C << 10))) + ((C & D) ^ (C & E) ^ (D & E)));
	W7 += (((W5 >> 17) | (W5 << 15)) ^ ((W5 >> 19) | (W5 << 13)) ^ (W5 >> 10)) + W0 + (((W8 >> 7) | (W8 << 25)) ^ ((W8 >> 18) | (W8 << 14)) ^ (W8 >> 3));
	R = A + (((F >> 6) | (F << 26)) ^ ((F >> 11) | (F << 21)) ^ ((F >> 25) | (F << 7))) + ((F & G) ^ (~F & H)) + W7 + 0x76F988DAUL;
	E += R;
	A = R + ((((B >> 2) | (B << 30)) ^ ((B >> 13) | (B << 19)) ^ ((B >> 22) | (B << 10))) + ((B & C) ^ (B & D) ^ (C & D)));
	W8 += (((W6 >> 17) | (W6 << 15)) ^ ((W6 >> 19) | (W6 << 13)) ^ (W6 >> 10)) + W1 + (((W9 >> 7) | (W9 << 25)) ^ ((W9 >> 18) | (W9 << 14)) ^ (W9 >> 3));
	R = H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + W8 + 0x983E5152UL;
	D += R;
	H = R + ((((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
	W9 += (((W7 >> 17) | (W7 << 15)) ^ ((W7 >> 19) | (W7 << 13)) ^ (W7 >> 10)) + W2 + (((W10 >> 7) | (W10 << 25)) ^ ((W10 >> 18) | (W10 << 14)) ^ (W10 >> 3));
	R = G + (((D >> 6) | (D << 26)) ^ ((D >> 11) | (D << 21)) ^ ((D >> 25) | (D << 7))) + ((D & E) ^ (~D & F)) + W9 + 0xA831C66DUL;
	C += R;
	G = R + ((((H >> 2) | (H << 30)) ^ ((H >> 13) | (H << 19)) ^ ((H >> 22) | (H << 10))) + ((H & A) ^ (H & B) ^ (A & B)));
	W10 += (((W8 >> 17) | (W8 << 15)) ^ ((W8 >> 19) | (W8 << 13)) ^ (W8 >> 10)) + W3 + (((W11 >> 7) | (W11 << 25)) ^ ((W11 >> 18) | (W11 << 14)) ^ (W11 >> 3));
	R = F + (((C >> 6) | (C << 26)) ^ ((C >> 11) | (C << 21)) ^ ((C >> 25) | (C << 7))) + ((C & D) ^ (~C & E)) + W10 + 0xB00327C8UL;
	B += R;
	F = R + ((((G >> 2) | (G << 30)) ^ ((G >> 13) | (G << 19)) ^ ((G >> 22) | (G << 10))) + ((G & H) ^ (G & A) ^ (H & A)));
	W11 += (((W9 >> 17) | (W9 << 15)) ^ ((W9 >> 19) | (W9 << 13)) ^ (W9 >> 10)) + W4 + (((W12 >> 7) | (W12 << 25)) ^ ((W12 >> 18) | (W12 << 14)) ^ (W12 >> 3));
	R = E + (((B >> 6) | (B << 26)) ^ ((B >> 11) | (B << 21)) ^ ((B >> 25) | (B << 7))) + ((B & C) ^ (~B & D)) + W11 + 0xBF597FC7UL;
	A += R;
	E = R + ((((F >> 2) | (F << 30)) ^ ((F >> 13) | (F << 19)) ^ ((F >> 22) | (F << 10))) + ((F & G) ^ (F & H) ^ (G & H)));
	W12 += (((W10 >> 17) | (W10 << 15)) ^ ((W10 >> 19) | (W10 << 13)) ^ (W10 >> 10)) + W5 + (((W13 >> 7) | (W13 << 25)) ^ ((W13 >> 18) | (W13 << 14)) ^ (W13 >> 3));
	R = D + (((A >> 6) | (A << 26)) ^ ((A >> 11) | (A << 21)) ^ ((A >> 25) | (A << 7))) + ((A & B) ^ (~A & C)) + W12 + 0xC6E00BF3UL;
	H += R;
	D = R + ((((E >> 2) | (E << 30)) ^ ((E >> 13) | (E << 19)) ^ ((E >> 22) | (E << 10))) + ((E & F) ^ (E & G) ^ (F & G)));
	W13 += (((W11 >> 17) | (W11 << 15)) ^ ((W11 >> 19) | (W11 << 13)) ^ (W11 >> 10)) + W6 + (((W14 >> 7) | (W14 << 25)) ^ ((W14 >> 18) | (W14 << 14)) ^ (W14 >> 3));
	R = C + (((H >> 6) | (H << 26)) ^ ((H >> 11) | (H << 21)) ^ ((H >> 25) | (H << 7))) + ((H & A) ^ (~H & B)) + W13 + 0xD5A79147UL;
	G += R;
	C = R + ((((D >> 2) | (D << 30)) ^ ((D >> 13) | (D << 19)) ^ ((D >> 22) | (D << 10))) + ((D & E) ^ (D & F) ^ (E & F)));
	W14 += (((W12 >> 17) | (W12 << 15)) ^ ((W12 >> 19) | (W12 << 13)) ^ (W12 >> 10)) + W7 + (((W15 >> 7) | (W15 << 25)) ^ ((W15 >> 18) | (W15 << 14)) ^ (W15 >> 3));
	R = B + (((G >> 6) | (G << 26)) ^ ((G >> 11) | (G << 21)) ^ ((G >> 25) | (G << 7))) + ((G & H) ^ (~G & A)) + W14 + 0x06CA6351UL;
	F += R;
	B = R + ((((C >> 2) | (C << 30)) ^ ((C >> 13) | (C << 19)) ^ ((C >> 22) | (C << 10))) + ((C & D) ^ (C & E) ^ (D & E)));
	W15 += (((W13 >> 17) | (W13 << 15)) ^ ((W13 >> 19) | (W13 << 13)) ^ (W13 >> 10)) + W8 + (((W0 >> 7) | (W0 << 25)) ^ ((W0 >> 18) | (W0 << 14)) ^ (W0 >> 3));
	R = A + (((F >> 6) | (F << 26)) ^ ((F >> 11) | (F << 21)) ^ ((F >> 25) | (F << 7))) + ((F & G) ^ (~F & H)) + W15 + 0x14292967UL;
	E += R;
	A = R + ((((B >> 2) | (B << 30)) ^ ((B >> 13) | (B << 19)) ^ ((B >> 22) | (B << 10))) + ((B & C) ^ (B & D) ^ (C & D)));

	W0 += (((W14 >> 17) | (W14 << 15)) ^ ((W14 >> 19) | (W14 << 13)) ^ (W14 >> 10)) + W9 + (((W1 >> 7) | (W1 << 25)) ^ ((W1 >> 18) | (W1 << 14)) ^ (W1 >> 3));
	R = H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + W0 + 0x27B70A85UL;
	D += R;
	H = R + ((((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
	W1 += (((W15 >> 17) | (W15 << 15)) ^ ((W15 >> 19) | (W15 << 13)) ^ (W15 >> 10)) + W10 + (((W2 >> 7) | (W2 << 25)) ^ ((W2 >> 18) | (W2 << 14)) ^ (W2 >> 3));
	R = G + (((D >> 6) | (D << 26)) ^ ((D >> 11) | (D << 21)) ^ ((D >> 25) | (D << 7))) + ((D & E) ^ (~D & F)) + W1 + 0x2E1B2138UL;
	C += R;
	G = R + ((((H >> 2) | (H << 30)) ^ ((H >> 13) | (H << 19)) ^ ((H >> 22) | (H << 10))) + ((H & A) ^ (H & B) ^ (A & B)));
	W2 += (((W0 >> 17) | (W0 << 15)) ^ ((W0 >> 19) | (W0 << 13)) ^ (W0 >> 10)) + W11 + (((W3 >> 7) | (W3 << 25)) ^ ((W3 >> 18) | (W3 << 14)) ^ (W3 >> 3));
	R = F + (((C >> 6) | (C << 26)) ^ ((C >> 11) | (C << 21)) ^ ((C >> 25) | (C << 7))) + ((C & D) ^ (~C & E)) + W2 + 0x4D2C6DFCUL;
	B += R;
	F = R + ((((G >> 2) | (G << 30)) ^ ((G >> 13) | (G << 19)) ^ ((G >> 22) | (G << 10))) + ((G & H) ^ (G & A) ^ (H & A)));
	W3 += (((W1 >> 17) | (W1 << 15)) ^ ((W1 >> 19) | (W1 << 13)) ^ (W1 >> 10)) + W12 + (((W4 >> 7) | (W4 << 25)) ^ ((W4 >> 18) | (W4 << 14)) ^ (W4 >> 3));
	R = E + (((B >> 6) | (B << 26)) ^ ((B >> 11) | (B << 21)) ^ ((B >> 25) | (B << 7))) + ((B & C) ^ (~B & D)) + W3 + 0x53380D13UL;
	A += R;
	E = R + ((((F >> 2) | (F << 30)) ^ ((F >> 13) | (F << 19)) ^ ((F >> 22) | (F << 10))) + ((F & G) ^ (F & H) ^ (G & H)));
	W4 += (((W2 >> 17) | (W2 << 15)) ^ ((W2 >> 19) | (W2 << 13)) ^ (W2 >> 10)) + W13 + (((W5 >> 7) | (W5 << 25)) ^ ((W5 >> 18) | (W5 << 14)) ^ (W5 >> 3));
	R = D + (((A >> 6) | (A << 26)) ^ ((A >> 11) | (A << 21)) ^ ((A >> 25) | (A << 7))) + ((A & B) ^ (~A & C)) + W4 + 0x650A7354UL;
	H += R;
	D = R + ((((E >> 2) | (E << 30)) ^ ((E >> 13) | (E << 19)) ^ ((E >> 22) | (E << 10))) + ((E & F) ^ (E & G) ^ (F & G)));
	W5 += (((W3 >> 17) | (W3 << 15)) ^ ((W3 >> 19) | (W3 << 13)) ^ (W3 >> 10)) + W14 + (((W6 >> 7) | (W6 << 25)) ^ ((W6 >> 18) | (W6 << 14)) ^ (W6 >> 3));
	R = C + (((H >> 6) | (H << 26)) ^ ((H >> 11) | (H << 21)) ^ ((H >> 25) | (H << 7))) + ((H & A) ^ (~H & B)) + W5 + 0x766A0ABBUL;
	G += R;
	C = R + ((((D >> 2) | (D << 30)) ^ ((D >> 13) | (D << 19)) ^ ((D >> 22) | (D << 10))) + ((D & E) ^ (D & F) ^ (E & F)));
	W6 += (((W4 >> 17) | (W4 << 15)) ^ ((W4 >> 19) | (W4 << 13)) ^ (W4 >> 10)) + W15 + (((W7 >> 7) | (W7 << 25)) ^ ((W7 >> 18) | (W7 << 14)) ^ (W7 >> 3));
	R = B + (((G >> 6) | (G << 26)) ^ ((G >> 11) | (G << 21)) ^ ((G >> 25) | (G << 7))) + ((G & H) ^ (~G & A)) + W6 + 0x81C2C92EUL;
	F += R;
	B = R + ((((C >> 2) | (C << 30)) ^ ((C >> 13) | (C << 19)) ^ ((C >> 22) | (C << 10))) + ((C & D) ^ (C & E) ^ (D & E)));
	W7 += (((W5 >> 17) | (W5 << 15)) ^ ((W5 >> 19) | (W5 << 13)) ^ (W5 >> 10)) + W0 + (((W8 >> 7) | (W8 << 25)) ^ ((W8 >> 18) | (W8 << 14)) ^ (W8 >> 3));
	R = A + (((F >> 6) | (F << 26)) ^ ((F >> 11) | (F << 21)) ^ ((F >> 25) | (F << 7))) + ((F & G) ^ (~F & H)) + W7 + 0x92722C85UL;
	E += R;
	A = R + ((((B >> 2) | (B << 30)) ^ ((B >> 13) | (B << 19)) ^ ((B >> 22) | (B << 10))) + ((B & C) ^ (B & D) ^ (C & D)));
	W8 += (((W6 >> 17) | (W6 << 15)) ^ ((W6 >> 19) | (W6 << 13)) ^ (W6 >> 10)) + W1 + (((W9 >> 7) | (W9 << 25)) ^ ((W9 >> 18) | (W9 << 14)) ^ (W9 >> 3));
	R = H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + W8 + 0xA2BFE8A1UL;
	D += R;
	H = R + ((((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
	W9 += (((W7 >> 17) | (W7 << 15)) ^ ((W7 >> 19) | (W7 << 13)) ^ (W7 >> 10)) + W2 + (((W10 >> 7) | (W10 << 25)) ^ ((W10 >> 18) | (W10 << 14)) ^ (W10 >> 3));
	R = G + (((D >> 6) | (D << 26)) ^ ((D >> 11) | (D << 21)) ^ ((D >> 25) | (D << 7))) + ((D & E) ^ (~D & F)) + W9 + 0xA81A664BUL;
	C += R;
	G = R + ((((H >> 2) | (H << 30)) ^ ((H >> 13) | (H << 19)) ^ ((H >> 22) | (H << 10))) + ((H & A) ^ (H & B) ^ (A & B)));
	W10 += (((W8 >> 17) | (W8 << 15)) ^ ((W8 >> 19) | (W8 << 13)) ^ (W8 >> 10)) + W3 + (((W11 >> 7) | (W11 << 25)) ^ ((W11 >> 18) | (W11 << 14)) ^ (W11 >> 3));
	R = F + (((C >> 6) | (C << 26)) ^ ((C >> 11) | (C << 21)) ^ ((C >> 25) | (C << 7))) + ((C & D) ^ (~C & E)) + W10 + 0xC24B8B70UL;
	B += R;
	F = R + ((((G >> 2) | (G << 30)) ^ ((G >> 13) | (G << 19)) ^ ((G >> 22) | (G << 10))) + ((G & H) ^ (G & A) ^ (H & A)));
	W11 += (((W9 >> 17) | (W9 << 15)) ^ ((W9 >> 19) | (W9 << 13)) ^ (W9 >> 10)) + W4 + (((W12 >> 7) | (W12 << 25)) ^ ((W12 >> 18) | (W12 << 14)) ^ (W12 >> 3));
	R = E + (((B >> 6) | (B << 26)) ^ ((B >> 11) | (B << 21)) ^ ((B >> 25) | (B << 7))) + ((B & C) ^ (~B & D)) + W11 + 0xC76C51A3UL;
	A += R;
	E = R + ((((F >> 2) | (F << 30)) ^ ((F >> 13) | (F << 19)) ^ ((F >> 22) | (F << 10))) + ((F & G) ^ (F & H) ^ (G & H)));
	W12 += (((W10 >> 17) | (W10 << 15)) ^ ((W10 >> 19) | (W10 << 13)) ^ (W10 >> 10)) + W5 + (((W13 >> 7) | (W13 << 25)) ^ ((W13 >> 18) | (W13 << 14)) ^ (W13 >> 3));
	R = D + (((A >> 6) | (A << 26)) ^ ((A >> 11) | (A << 21)) ^ ((A >> 25) | (A << 7))) + ((A & B) ^ (~A & C)) + W12 + 0xD192E819UL;
	H += R;
	D = R + ((((E >> 2) | (E << 30)) ^ ((E >> 13) | (E << 19)) ^ ((E >> 22) | (E << 10))) + ((E & F) ^ (E & G) ^ (F & G)));
	W13 += (((W11 >> 17) | (W11 << 15)) ^ ((W11 >> 19) | (W11 << 13)) ^ (W11 >> 10)) + W6 + (((W14 >> 7) | (W14 << 25)) ^ ((W14 >> 18) | (W14 << 14)) ^ (W14 >> 3));
	R = C + (((H >> 6) | (H << 26)) ^ ((H >> 11) | (H << 21)) ^ ((H >> 25) | (H << 7))) + ((H & A) ^ (~H & B)) + W13 + 0xD6990624UL;
	G += R;
	C = R + ((((D >> 2) | (D << 30)) ^ ((D >> 13) | (D << 19)) ^ ((D >> 22) | (D << 10))) + ((D & E) ^ (D & F) ^ (E & F)));
	W14 += (((W12 >> 17) | (W12 << 15)) ^ ((W12 >> 19) | (W12 << 13)) ^ (W12 >> 10)) + W7 + (((W15 >> 7) | (W15 << 25)) ^ ((W15 >> 18) | (W15 << 14)) ^ (W15 >> 3));
	R = B + (((G >> 6) | (G << 26)) ^ ((G >> 11) | (G << 21)) ^ ((G >> 25) | (G << 7))) + ((G & H) ^ (~G & A)) + W14 + 0xF40E3585UL;
	F += R;
	B = R + ((((C >> 2) | (C << 30)) ^ ((C >> 13) | (C << 19)) ^ ((C >> 22) | (C << 10))) + ((C & D) ^ (C & E) ^ (D & E)));
	W15 += (((W13 >> 17) | (W13 << 15)) ^ ((W13 >> 19) | (W13 << 13)) ^ (W13 >> 10)) + W8 + (((W0 >> 7) | (W0 << 25)) ^ ((W0 >> 18) | (W0 << 14)) ^ (W0 >> 3));
	R = A + (((F >> 6) | (F << 26)) ^ ((F >> 11) | (F << 21)) ^ ((F >> 25) | (F << 7))) + ((F & G) ^ (~F & H)) + W15 + 0x106AA070UL;
	E += R;
	A = R + ((((B >> 2) | (B << 30)) ^ ((B >> 13) | (B << 19)) ^ ((B >> 22) | (B << 10))) + ((B & C) ^ (B & D) ^ (C & D)));

	W0 += (((W14 >> 17) | (W14 << 15)) ^ ((W14 >> 19) | (W14 << 13)) ^ (W14 >> 10)) + W9 + (((W1 >> 7) | (W1 << 25)) ^ ((W1 >> 18) | (W1 << 14)) ^ (W1 >> 3));
	R = H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + W0 + 0x19A4C116UL;
	D += R;
	H = R + ((((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
	W1 += (((W15 >> 17) | (W15 << 15)) ^ ((W15 >> 19) | (W15 << 13)) ^ (W15 >> 10)) + W10 + (((W2 >> 7) | (W2 << 25)) ^ ((W2 >> 18) | (W2 << 14)) ^ (W2 >> 3));
	R = G + (((D >> 6) | (D << 26)) ^ ((D >> 11) | (D << 21)) ^ ((D >> 25) | (D << 7))) + ((D & E) ^ (~D & F)) + W1 + 0x1E376C08UL;
	C += R;
	G = R + ((((H >> 2) | (H << 30)) ^ ((H >> 13) | (H << 19)) ^ ((H >> 22) | (H << 10))) + ((H & A) ^ (H & B) ^ (A & B)));
	W2 += (((W0 >> 17) | (W0 << 15)) ^ ((W0 >> 19) | (W0 << 13)) ^ (W0 >> 10)) + W11 + (((W3 >> 7) | (W3 << 25)) ^ ((W3 >> 18) | (W3 << 14)) ^ (W3 >> 3));
	R = F + (((C >> 6) | (C << 26)) ^ ((C >> 11) | (C << 21)) ^ ((C >> 25) | (C << 7))) + ((C & D) ^ (~C & E)) + W2 + 0x2748774CUL;
	B += R;
	F = R + ((((G >> 2) | (G << 30)) ^ ((G >> 13) | (G << 19)) ^ ((G >> 22) | (G << 10))) + ((G & H) ^ (G & A) ^ (H & A)));
	W3 += (((W1 >> 17) | (W1 << 15)) ^ ((W1 >> 19) | (W1 << 13)) ^ (W1 >> 10)) + W12 + (((W4 >> 7) | (W4 << 25)) ^ ((W4 >> 18) | (W4 << 14)) ^ (W4 >> 3));
	R = E + (((B >> 6) | (B << 26)) ^ ((B >> 11) | (B << 21)) ^ ((B >> 25) | (B << 7))) + ((B & C) ^ (~B & D)) + W3 + 0x34B0BCB5UL;
	A += R;
	E = R + ((((F >> 2) | (F << 30)) ^ ((F >> 13) | (F << 19)) ^ ((F >> 22) | (F << 10))) + ((F & G) ^ (F & H) ^ (G & H)));
	W4 += (((W2 >> 17) | (W2 << 15)) ^ ((W2 >> 19) | (W2 << 13)) ^ (W2 >> 10)) + W13 + (((W5 >> 7) | (W5 << 25)) ^ ((W5 >> 18) | (W5 << 14)) ^ (W5 >> 3));
	R = D + (((A >> 6) | (A << 26)) ^ ((A >> 11) | (A << 21)) ^ ((A >> 25) | (A << 7))) + ((A & B) ^ (~A & C)) + W4 + 0x391C0CB3UL;
	H += R;
	D = R + ((((E >> 2) | (E << 30)) ^ ((E >> 13) | (E << 19)) ^ ((E >> 22) | (E << 10))) + ((E & F) ^ (E & G) ^ (F & G)));
	W5 += (((W3 >> 17) | (W3 << 15)) ^ ((W3 >> 19) | (W3 << 13)) ^ (W3 >> 10)) + W14 + (((W6 >> 7) | (W6 << 25)) ^ ((W6 >> 18) | (W6 << 14)) ^ (W6 >> 3));
	R = C + (((H >> 6) | (H << 26)) ^ ((H >> 11) | (H << 21)) ^ ((H >> 25) | (H << 7))) + ((H & A) ^ (~H & B)) + W5 + 0x4ED8AA4AUL;
	G += R;
	C = R + ((((D >> 2) | (D << 30)) ^ ((D >> 13) | (D << 19)) ^ ((D >> 22) | (D << 10))) + ((D & E) ^ (D & F) ^ (E & F)));
	W6 += (((W4 >> 17) | (W4 << 15)) ^ ((W4 >> 19) | (W4 << 13)) ^ (W4 >> 10)) + W15 + (((W7 >> 7) | (W7 << 25)) ^ ((W7 >> 18) | (W7 << 14)) ^ (W7 >> 3));
	R = B + (((G >> 6) | (G << 26)) ^ ((G >> 11) | (G << 21)) ^ ((G >> 25) | (G << 7))) + ((G & H) ^ (~G & A)) + W6 + 0x5B9CCA4FUL;
	F += R;
	B = R + ((((C >> 2) | (C << 30)) ^ ((C >> 13) | (C << 19)) ^ ((C >> 22) | (C << 10))) + ((C & D) ^ (C & E) ^ (D & E)));
	W7 += (((W5 >> 17) | (W5 << 15)) ^ ((W5 >> 19) | (W5 << 13)) ^ (W5 >> 10)) + W0 + (((W8 >> 7) | (W8 << 25)) ^ ((W8 >> 18) | (W8 << 14)) ^ (W8 >> 3));
	R = A + (((F >> 6) | (F << 26)) ^ ((F >> 11) | (F << 21)) ^ ((F >> 25) | (F << 7))) + ((F & G) ^ (~F & H)) + W7 + 0x682E6FF3UL;
	E += R;
	A = R + ((((B >> 2) | (B << 30)) ^ ((B >> 13) | (B << 19)) ^ ((B >> 22) | (B << 10))) + ((B & C) ^ (B & D) ^ (C & D)));
	W8 += (((W6 >> 17) | (W6 << 15)) ^ ((W6 >> 19) | (W6 << 13)) ^ (W6 >> 10)) + W1 + (((W9 >> 7) | (W9 << 25)) ^ ((W9 >> 18) | (W9 << 14)) ^ (W9 >> 3));
	R = H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + W8 + 0x748F82EEUL;
	D += R;
	H = R + ((((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
	W9 += (((W7 >> 17) | (W7 << 15)) ^ ((W7 >> 19) | (W7 << 13)) ^ (W7 >> 10)) + W2 + (((W10 >> 7) | (W10 << 25)) ^ ((W10 >> 18) | (W10 << 14)) ^ (W10 >> 3));
	R = G + (((D >> 6) | (D << 26)) ^ ((D >> 11) | (D << 21)) ^ ((D >> 25) | (D << 7))) + ((D & E) ^ (~D & F)) + W9 + 0x78A5636FUL;
	C += R;
	G = R + ((((H >> 2) | (H << 30)) ^ ((H >> 13) | (H << 19)) ^ ((H >> 22) | (H << 10))) + ((H & A) ^ (H & B) ^ (A & B)));
	W10 += (((W8 >> 17) | (W8 << 15)) ^ ((W8 >> 19) | (W8 << 13)) ^ (W8 >> 10)) + W3 + (((W11 >> 7) | (W11 << 25)) ^ ((W11 >> 18) | (W11 << 14)) ^ (W11 >> 3));
	R = F + (((C >> 6) | (C << 26)) ^ ((C >> 11) | (C << 21)) ^ ((C >> 25) | (C << 7))) + ((C & D) ^ (~C & E)) + W10 + 0x84C87814UL;
	B += R;
	F = R + ((((G >> 2) | (G << 30)) ^ ((G >> 13) | (G << 19)) ^ ((G >> 22) | (G << 10))) + ((G & H) ^ (G & A) ^ (H & A)));
	W11 += (((W9 >> 17) | (W9 << 15)) ^ ((W9 >> 19) | (W9 << 13)) ^ (W9 >> 10)) + W4 + (((W12 >> 7) | (W12 << 25)) ^ ((W12 >> 18) | (W12 << 14)) ^ (W12 >> 3));
	R = E + (((B >> 6) | (B << 26)) ^ ((B >> 11) | (B << 21)) ^ ((B >> 25) | (B << 7))) + ((B & C) ^ (~B & D)) + W11 + 0x8CC70208UL;
	A += R;
	E = R + ((((F >> 2) | (F << 30)) ^ ((F >> 13) | (F << 19)) ^ ((F >> 22) | (F << 10))) + ((F & G) ^ (F & H) ^ (G & H)));
	W12 += (((W10 >> 17) | (W10 << 15)) ^ ((W10 >> 19) | (W10 << 13)) ^ (W10 >> 10)) + W5 + (((W13 >> 7) | (W13 << 25)) ^ ((W13 >> 18) | (W13 << 14)) ^ (W13 >> 3));
	R = D + (((A >> 6) | (A << 26)) ^ ((A >> 11) | (A << 21)) ^ ((A >> 25) | (A << 7))) + ((A & B) ^ (~A & C)) + W12 + 0x90BEFFFAUL;
	H += R;
	D = R + ((((E >> 2) | (E << 30)) ^ ((E >> 13) | (E << 19)) ^ ((E >> 22) | (E << 10))) + ((E & F) ^ (E & G) ^ (F & G)));
	W13 += (((W11 >> 17) | (W11 << 15)) ^ ((W11 >> 19) | (W11 << 13)) ^ (W11 >> 10)) + W6 + (((W14 >> 7) | (W14 << 25)) ^ ((W14 >> 18) | (W14 << 14)) ^ (W14 >> 3));
	R = C + (((H >> 6) | (H << 26)) ^ ((H >> 11) | (H << 21)) ^ ((H >> 25) | (H << 7))) + ((H & A) ^ (~H & B)) + W13 + 0xA4506CEBUL;
	G += R;
	C = R + ((((D >> 2) | (D << 30)) ^ ((D >> 13) | (D << 19)) ^ ((D >> 22) | (D << 10))) + ((D & E) ^ (D & F) ^ (E & F)));
	W14 += (((W12 >> 17) | (W12 << 15)) ^ ((W12 >> 19) | (W12 << 13)) ^ (W12 >> 10)) + W7 + (((W15 >> 7) | (W15 << 25)) ^ ((W15 >> 18) | (W15 << 14)) ^ (W15 >> 3));
	R = B + (((G >> 6) | (G << 26)) ^ ((G >> 11) | (G << 21)) ^ ((G >> 25) | (G << 7))) + ((G & H) ^ (~G & A)) + W14 + 0xBEF9A3F7UL;
	F += R;
	B = R + ((((C >> 2) | (C << 30)) ^ ((C >> 13) | (C << 19)) ^ ((C >> 22) | (C << 10))) + ((C & D) ^ (C & E) ^ (D & E)));
	W15 += (((W13 >> 17) | (W13 << 15)) ^ ((W13 >> 19) | (W13 << 13)) ^ (W13 >> 10)) + W8 + (((W0 >> 7) | (W0 << 25)) ^ ((W0 >> 18) | (W0 << 14)) ^ (W0 >> 3));
	R = A + (((F >> 6) | (F << 26)) ^ ((F >> 11) | (F << 21)) ^ ((F >> 25) | (F << 7))) + ((F & G) ^ (~F & H)) + W15 + 0xC67178F2UL;
	E += R;
	A = R + ((((B >> 2) | (B << 30)) ^ ((B >> 13) | (B << 19)) ^ ((B >> 22) | (B << 10))) + ((B & C) ^ (B & D) ^ (C & D)));

	State[0] += A;
	State[1] += B;
	State[2] += C;
	State[3] += D;
	State[4] += E;
	State[5] += F;
	State[6] += G;
	State[7] += H;
}

void SHA2::PermuteR64P512V(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State)
{
#if defined(CEX_HAS_AVX)

	__m128i m0;
	__m128i m1;
	__m128i m2;
	__m128i m3;
	__m128i mask;
	__m128i pmsg;
	__m128i ptmp;
	__m128i s0;
	__m128i s1;
	__m128i t0;
	__m128i t1;

	// load initial values
	ptmp = _mm_loadu_si128(reinterpret_cast<__m128i*>(&State));
	s1 = _mm_loadu_si128(reinterpret_cast<__m128i*>(&State[4]));
	mask = _mm_set_epi64x(0x0C0D0E0F08090A0BULL, 0x0405060700010203ULL);
	ptmp = _mm_shuffle_epi32(ptmp, 0xB1);	// CDAB
	s1 = _mm_shuffle_epi32(s1, 0x1B);		// EFGH
	s0 = _mm_alignr_epi8(ptmp, s1, 8);		// ABEF
	s1 = _mm_blend_epi16(s1, ptmp, 0xF0);	// CDGH
	t0 = s0;
	t1 = s1;

	// rounds 0-3
	pmsg = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset]));
	m0 = _mm_shuffle_epi8(pmsg, mask);
	pmsg = _mm_add_epi32(m0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	// rounds 4-7
	m1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 16]));
	m1 = _mm_shuffle_epi8(m1, mask);
	pmsg = _mm_add_epi32(m1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m0 = _mm_sha256msg1_epu32(m0, m1);
	// rounds 8-11
	m2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 32]));
	m2 = _mm_shuffle_epi8(m2, mask);
	pmsg = _mm_add_epi32(m2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m1 = _mm_sha256msg1_epu32(m1, m2);
	// rounds 12-15
	m3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 48]));
	m3 = _mm_shuffle_epi8(m3, mask);
	pmsg = _mm_add_epi32(m3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m3, m2, 4);
	m0 = _mm_add_epi32(m0, ptmp);
	m0 = _mm_sha256msg2_epu32(m0, m3);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m2 = _mm_sha256msg1_epu32(m2, m3);
	// rounds 16-19
	pmsg = _mm_add_epi32(m0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m0, m3, 4);
	m1 = _mm_add_epi32(m1, ptmp);
	m1 = _mm_sha256msg2_epu32(m1, m0);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m3 = _mm_sha256msg1_epu32(m3, m0);
	// rounds 20-23
	pmsg = _mm_add_epi32(m1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m1, m0, 4);
	m2 = _mm_add_epi32(m2, ptmp);
	m2 = _mm_sha256msg2_epu32(m2, m1);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m0 = _mm_sha256msg1_epu32(m0, m1);
	// rounds 24-27
	pmsg = _mm_add_epi32(m2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m2, m1, 4);
	m3 = _mm_add_epi32(m3, ptmp);
	m3 = _mm_sha256msg2_epu32(m3, m2);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m1 = _mm_sha256msg1_epu32(m1, m2);
	// rounds 28-31
	pmsg = _mm_add_epi32(m3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m3, m2, 4);
	m0 = _mm_add_epi32(m0, ptmp);
	m0 = _mm_sha256msg2_epu32(m0, m3);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m2 = _mm_sha256msg1_epu32(m2, m3);
	// rounds 32-35
	pmsg = _mm_add_epi32(m0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m0, m3, 4);
	m1 = _mm_add_epi32(m1, ptmp);
	m1 = _mm_sha256msg2_epu32(m1, m0);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m3 = _mm_sha256msg1_epu32(m3, m0);
	// rounds 36-39
	pmsg = _mm_add_epi32(m1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m1, m0, 4);
	m2 = _mm_add_epi32(m2, ptmp);
	m2 = _mm_sha256msg2_epu32(m2, m1);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m0 = _mm_sha256msg1_epu32(m0, m1);
	// rounds 40-43
	pmsg = _mm_add_epi32(m2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m2, m1, 4);
	m3 = _mm_add_epi32(m3, ptmp);
	m3 = _mm_sha256msg2_epu32(m3, m2);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m1 = _mm_sha256msg1_epu32(m1, m2);
	// rounds 44-47
	pmsg = _mm_add_epi32(m3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m3, m2, 4);
	m0 = _mm_add_epi32(m0, ptmp);
	m0 = _mm_sha256msg2_epu32(m0, m3);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m2 = _mm_sha256msg1_epu32(m2, m3);
	// rounds 48-51
	pmsg = _mm_add_epi32(m0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m0, m3, 4);
	m1 = _mm_add_epi32(m1, ptmp);
	m1 = _mm_sha256msg2_epu32(m1, m0);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m3 = _mm_sha256msg1_epu32(m3, m0);
	// rounds 52-55
	pmsg = _mm_add_epi32(m1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m1, m0, 4);
	m2 = _mm_add_epi32(m2, ptmp);
	m2 = _mm_sha256msg2_epu32(m2, m1);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	// rounds 56-59
	pmsg = _mm_add_epi32(m2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m2, m1, 4);
	m3 = _mm_add_epi32(m3, ptmp);
	m3 = _mm_sha256msg2_epu32(m3, m2);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	// rounds 60-63
	pmsg = _mm_add_epi32(m3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);

	// combine state 
	s0 = _mm_add_epi32(s0, t0);
	s1 = _mm_add_epi32(s1, t1);
	ptmp = _mm_shuffle_epi32(s0, 0x1B);		// FEBA
	s1 = _mm_shuffle_epi32(s1, 0xB1);		// DCHG
	s0 = _mm_blend_epi16(ptmp, s1, 0xF0);	// DCBA
	s1 = _mm_alignr_epi8(s1, ptmp, 8);		// ABEF

	// store
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[0]), s0);
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[4]), s1);
#else
	PermuteR64P512U(Input, InOffset, State);
#endif
}

#if defined(CEX_HAS_AVX2)

void SHA2::PermuteR64P8x512H(const std::vector<byte> &Input, size_t InOffset, std::vector<UInt256> &State)
{
	std::array<UInt256, 8> A;
	std::array<UInt256, 64> W;
	UInt256 K;
	size_t i;
	size_t j;

	MemoryTools::Copy(State, 0, A, 0, State.size() * sizeof(UInt256));

#if defined(CEX_IS_LITTLE_ENDIAN)
	for (i = 0; i < 16; ++i)
	{
		W[i].Load(
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint))),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 64),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 128),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 196),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 256),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 320),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 384),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 448));
	}
#else
	MemoryTools::Copy(Input, InOffset, W, 0, A.size() * sizeof(UInt256));
#endif

	for (i = 16; i < 64; i++)
	{
		W[i] = Theta1(W[i - 2]) + W[i - 7] + Theta0(W[i - 15]) + W[i - 16];
	}

	j = 0;
	for (i = 0; i < 8; ++i)
	{
		K.Load(SHA2256_RC64[j]);
		Round256W(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], K, W[j]);
		++j;
	}

	State[0] += A[0];
	State[1] += A[1];
	State[2] += A[2];
	State[3] += A[3];
	State[4] += A[4];
	State[5] += A[5];
	State[6] += A[6];
	State[7] += A[7];
}

#endif

#if defined(CEX_HAS_AVX512)

void SHA2::PermuteR64P16x512H(const std::vector<byte> &Input, size_t InOffset, std::vector<UInt512> &State)
{
	std::array<UInt512, 8> A;
	std::array<UInt512, 64> W;
	UInt512 K;
	size_t i;
	size_t j;

	MemoryTools::Copy(State, 0, A, 0, State.size() * sizeof(UInt512));

#if defined(CEX_IS_LITTLE_ENDIAN)
	for (i = 0; i < 16; ++i)
	{
		W[i].Load(
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint))),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 64),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 128),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 196),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 256),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 320),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 384),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 448),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 512),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 576),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 640),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 704),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 768),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 832),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 896),
			IntegerTools::BeBytesTo32(Input, InOffset + (i * sizeof(uint)) + 960));
	}
#else
	MemoryTools::Copy(Input, InOffset, W, 0, A.size() * sizeof(UInt512));
#endif

	for (i = 16; i < 64; i++)
	{
		W[i] = Theta1(W[i - 2]) + W[i - 7] + Theta0(W[i - 15]) + W[i - 16];
	}

	j = 0;
	for (i = 0; i < 8; ++i)
	{
		K.Load(SHA2256_RC64[j]);
		Round256W(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], K, W[j]);
		++j;
		K.Load(SHA2256_RC64[j]);
		Round256W(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], K, W[j]);
		++j;
	}

	State[0] += A[0];
	State[1] += A[1];
	State[2] += A[2];
	State[3] += A[3];
	State[4] += A[4];
	State[5] += A[5];
	State[6] += A[6];
	State[7] += A[7];
}

#endif

//~~~SHA2-512~~~//

void SHA2::PermuteR80P1024C(const std::vector<byte> &Input, size_t InOffset, std::array<ulong, 8> &State)
{
	std::array<ulong, 8> A;
	std::array<ulong, 80> W;
	size_t i;
	size_t j;

	MemoryTools::Copy(State, 0, A, 0, State.size() * sizeof(ulong));

#if defined(CEX_IS_LITTLE_ENDIAN)
	for (i = 0; i < 16; ++i)
	{
		W[i] = IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong)));
	}
#else
	MemoryTools::Copy(Input, InOffset, W, 0, A.size() * sizeof(ulong));
#endif

	for (i = 16; i < 80; i++)
	{
		W[i] = Sigma1(W[i - 2]) + W[i - 7] + Sigma0(W[i - 15]) + W[i - 16];
	}

	j = 0;
	for (i = 0; i < 10; ++i)
	{
		Round512(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], SHA2512_RC80[j], W[j]);
		++j;
		Round512(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], SHA2512_RC80[j], W[j]);
		++j;
		Round512(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], SHA2512_RC80[j], W[j]);
		++j;
		Round512(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], SHA2512_RC80[j], W[j]);
		++j;
		Round512(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], SHA2512_RC80[j], W[j]);
		++j;
		Round512(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], SHA2512_RC80[j], W[j]);
		++j;
		Round512(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], SHA2512_RC80[j], W[j]);
		++j;
		Round512(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], SHA2512_RC80[j], W[j]);
		++j;
	}

	State[0] += A[0];
	State[1] += A[1];
	State[2] += A[2];
	State[3] += A[3];
	State[4] += A[4];
	State[5] += A[5];
	State[6] += A[6];
	State[7] += A[7];
}

void SHA2::PermuteR80P1024U(const std::vector<byte> &Input, size_t InOffset, std::array<ulong, 8> &State)
{
	ulong A;
	ulong B;
	ulong C;
	ulong D;
	ulong E;
	ulong F;
	ulong G;
	ulong H;
	ulong R;
	ulong W0;
	ulong W1;
	ulong W2;
	ulong W3;
	ulong W4;
	ulong W5;
	ulong W6;
	ulong W7;
	ulong W8;
	ulong W9;
	ulong W10;
	ulong W11;
	ulong W12;
	ulong W13;
	ulong W14;
	ulong W15;

	A = State[0];
	B = State[1];
	C = State[2];
	D = State[3];
	E = State[4];
	F = State[5];
	G = State[6];
	H = State[7];

	W0 = IntegerTools::BeBytesTo64(Input, InOffset);
	W1 = IntegerTools::BeBytesTo64(Input, InOffset + 8);
	W2 = IntegerTools::BeBytesTo64(Input, InOffset + 16);
	W3 = IntegerTools::BeBytesTo64(Input, InOffset + 24);
	W4 = IntegerTools::BeBytesTo64(Input, InOffset + 32);
	W5 = IntegerTools::BeBytesTo64(Input, InOffset + 40);
	W6 = IntegerTools::BeBytesTo64(Input, InOffset + 48);
	W7 = IntegerTools::BeBytesTo64(Input, InOffset + 56);
	W8 = IntegerTools::BeBytesTo64(Input, InOffset + 64);
	W9 = IntegerTools::BeBytesTo64(Input, InOffset + 72);
	W10 = IntegerTools::BeBytesTo64(Input, InOffset + 80);
	W11 = IntegerTools::BeBytesTo64(Input, InOffset + 88);
	W12 = IntegerTools::BeBytesTo64(Input, InOffset + 96);
	W13 = IntegerTools::BeBytesTo64(Input, InOffset + 104);
	W14 = IntegerTools::BeBytesTo64(Input, InOffset + 112);
	W15 = IntegerTools::BeBytesTo64(Input, InOffset + 120);

	R = H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + W0 + 0x428A2F98D728AE22ULL;
	D += R;
	H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	R = G + (((D << 50) | (D >> 14)) ^ ((D << 46) | (D >> 18)) ^ ((D << 23) | (D >> 41))) + ((D & E) ^ (~D & F)) + W1 + 0x7137449123EF65CDULL;
	C += R;
	G = R + (((H << 36) | (H >> 28)) ^ ((H << 30) | (H >> 34)) ^ ((H << 25) | (H >> 39))) + ((H & A) ^ (H & B) ^ (A & B));
	R = F + (((C << 50) | (C >> 14)) ^ ((C << 46) | (C >> 18)) ^ ((C << 23) | (C >> 41))) + ((C & D) ^ (~C & E)) + W2 + 0xB5C0FBCFEC4D3B2FULL;
	B += R;
	F = R + (((G << 36) | (G >> 28)) ^ ((G << 30) | (G >> 34)) ^ ((G << 25) | (G >> 39))) + ((G & H) ^ (G & A) ^ (H & A));
	R = E + (((B << 50) | (B >> 14)) ^ ((B << 46) | (B >> 18)) ^ ((B << 23) | (B >> 41))) + ((B & C) ^ (~B & D)) + W3 + 0xE9B5DBA58189DBBCULL;
	A += R;
	E = R + (((F << 36) | (F >> 28)) ^ ((F << 30) | (F >> 34)) ^ ((F << 25) | (F >> 39))) + ((F & G) ^ (F & H) ^ (G & H));
	R = D + (((A << 50) | (A >> 14)) ^ ((A << 46) | (A >> 18)) ^ ((A << 23) | (A >> 41))) + ((A & B) ^ (~A & C)) + W4 + 0x3956C25BF348B538ULL;
	H += R;
	D = R + (((E << 36) | (E >> 28)) ^ ((E << 30) | (E >> 34)) ^ ((E << 25) | (E >> 39))) + ((E & F) ^ (E & G) ^ (F & G));
	R = C + (((H << 50) | (H >> 14)) ^ ((H << 46) | (H >> 18)) ^ ((H << 23) | (H >> 41))) + ((H & A) ^ (~H & B)) + W5 + 0x59F111F1B605D019ULL;
	G += R;
	C = R + (((D << 36) | (D >> 28)) ^ ((D << 30) | (D >> 34)) ^ ((D << 25) | (D >> 39))) + ((D & E) ^ (D & F) ^ (E & F));
	R = B + (((G << 50) | (G >> 14)) ^ ((G << 46) | (G >> 18)) ^ ((G << 23) | (G >> 41))) + ((G & H) ^ (~G & A)) + W6 + 0x923F82A4AF194F9BULL;
	F += R;
	B = R + (((C << 36) | (C >> 28)) ^ ((C << 30) | (C >> 34)) ^ ((C << 25) | (C >> 39))) + ((C & D) ^ (C & E) ^ (D & E));
	R = A + (((F << 50) | (F >> 14)) ^ ((F << 46) | (F >> 18)) ^ ((F << 23) | (F >> 41))) + ((F & G) ^ (~F & H)) + W7 + 0xAB1C5ED5DA6D8118ULL;
	E += R;
	A = R + (((B << 36) | (B >> 28)) ^ ((B << 30) | (B >> 34)) ^ ((B << 25) | (B >> 39))) + ((B & C) ^ (B & D) ^ (C & D));
	R = H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + W8 + 0xD807AA98A3030242ULL;
	D += R;
	H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	R = G + (((D << 50) | (D >> 14)) ^ ((D << 46) | (D >> 18)) ^ ((D << 23) | (D >> 41))) + ((D & E) ^ (~D & F)) + W9 + 0x12835B0145706FBEULL;
	C += R;
	G = R + (((H << 36) | (H >> 28)) ^ ((H << 30) | (H >> 34)) ^ ((H << 25) | (H >> 39))) + ((H & A) ^ (H & B) ^ (A & B));
	R = F + (((C << 50) | (C >> 14)) ^ ((C << 46) | (C >> 18)) ^ ((C << 23) | (C >> 41))) + ((C & D) ^ (~C & E)) + W10 + 0x243185BE4EE4B28CULL;
	B += R;
	F = R + (((G << 36) | (G >> 28)) ^ ((G << 30) | (G >> 34)) ^ ((G << 25) | (G >> 39))) + ((G & H) ^ (G & A) ^ (H & A));
	R = E + (((B << 50) | (B >> 14)) ^ ((B << 46) | (B >> 18)) ^ ((B << 23) | (B >> 41))) + ((B & C) ^ (~B & D)) + W11 + 0x550C7DC3D5FFB4E2ULL;
	A += R;
	E = R + (((F << 36) | (F >> 28)) ^ ((F << 30) | (F >> 34)) ^ ((F << 25) | (F >> 39))) + ((F & G) ^ (F & H) ^ (G & H));
	R = D + (((A << 50) | (A >> 14)) ^ ((A << 46) | (A >> 18)) ^ ((A << 23) | (A >> 41))) + ((A & B) ^ (~A & C)) + W12 + 0x72BE5D74F27B896FULL;
	H += R;
	D = R + (((E << 36) | (E >> 28)) ^ ((E << 30) | (E >> 34)) ^ ((E << 25) | (E >> 39))) + ((E & F) ^ (E & G) ^ (F & G));
	R = C + (((H << 50) | (H >> 14)) ^ ((H << 46) | (H >> 18)) ^ ((H << 23) | (H >> 41))) + ((H & A) ^ (~H & B)) + W13 + 0x80DEB1FE3B1696B1ULL;
	G += R;
	C = R + (((D << 36) | (D >> 28)) ^ ((D << 30) | (D >> 34)) ^ ((D << 25) | (D >> 39))) + ((D & E) ^ (D & F) ^ (E & F));
	R = B + (((G << 50) | (G >> 14)) ^ ((G << 46) | (G >> 18)) ^ ((G << 23) | (G >> 41))) + ((G & H) ^ (~G & A)) + W14 + 0x9BDC06A725C71235ULL;
	F += R;
	B = R + (((C << 36) | (C >> 28)) ^ ((C << 30) | (C >> 34)) ^ ((C << 25) | (C >> 39))) + ((C & D) ^ (C & E) ^ (D & E));
	R = A + (((F << 50) | (F >> 14)) ^ ((F << 46) | (F >> 18)) ^ ((F << 23) | (F >> 41))) + ((F & G) ^ (~F & H)) + W15 + 0xC19BF174CF692694ULL;
	E += R;
	A = R + (((B << 36) | (B >> 28)) ^ ((B << 30) | (B >> 34)) ^ ((B << 25) | (B >> 39))) + ((B & C) ^ (B & D) ^ (C & D));

	W0 += (((W14 << 45) | (W14 >> 19)) ^ ((W14 << 3) | (W14 >> 61)) ^ (W14 >> 6)) + W9 + (((W1 << 63) | (W1 >> 1)) ^ ((W1 << 56) | (W1 >> 8)) ^ (W1 >> 7));
	R = H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + W0 + 0xE49B69C19EF14AD2ULL;
	D += R;
	H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	W1 += (((W15 << 45) | (W15 >> 19)) ^ ((W15 << 3) | (W15 >> 61)) ^ (W15 >> 6)) + W10 + (((W2 << 63) | (W2 >> 1)) ^ ((W2 << 56) | (W2 >> 8)) ^ (W2 >> 7));
	R = G + (((D << 50) | (D >> 14)) ^ ((D << 46) | (D >> 18)) ^ ((D << 23) | (D >> 41))) + ((D & E) ^ (~D & F)) + W1 + 0xEFBE4786384F25E3ULL;
	C += R;
	G = R + (((H << 36) | (H >> 28)) ^ ((H << 30) | (H >> 34)) ^ ((H << 25) | (H >> 39))) + ((H & A) ^ (H & B) ^ (A & B));
	W2 += (((W0 << 45) | (W0 >> 19)) ^ ((W0 << 3) | (W0 >> 61)) ^ (W0 >> 6)) + W11 + (((W3 << 63) | (W3 >> 1)) ^ ((W3 << 56) | (W3 >> 8)) ^ (W3 >> 7));
	R = F + (((C << 50) | (C >> 14)) ^ ((C << 46) | (C >> 18)) ^ ((C << 23) | (C >> 41))) + ((C & D) ^ (~C & E)) + W2 + 0x0FC19DC68B8CD5B5ULL;
	B += R;
	F = R + (((G << 36) | (G >> 28)) ^ ((G << 30) | (G >> 34)) ^ ((G << 25) | (G >> 39))) + ((G & H) ^ (G & A) ^ (H & A));
	W3 += (((W1 << 45) | (W1 >> 19)) ^ ((W1 << 3) | (W1 >> 61)) ^ (W1 >> 6)) + W12 + (((W4 << 63) | (W4 >> 1)) ^ ((W4 << 56) | (W4 >> 8)) ^ (W4 >> 7));
	R = E + (((B << 50) | (B >> 14)) ^ ((B << 46) | (B >> 18)) ^ ((B << 23) | (B >> 41))) + ((B & C) ^ (~B & D)) + W3 + 0x240CA1CC77AC9C65ULL;
	A += R;
	E = R + (((F << 36) | (F >> 28)) ^ ((F << 30) | (F >> 34)) ^ ((F << 25) | (F >> 39))) + ((F & G) ^ (F & H) ^ (G & H));
	W4 += (((W2 << 45) | (W2 >> 19)) ^ ((W2 << 3) | (W2 >> 61)) ^ (W2 >> 6)) + W13 + (((W5 << 63) | (W5 >> 1)) ^ ((W5 << 56) | (W5 >> 8)) ^ (W5 >> 7));
	R = D + (((A << 50) | (A >> 14)) ^ ((A << 46) | (A >> 18)) ^ ((A << 23) | (A >> 41))) + ((A & B) ^ (~A & C)) + W4 + 0x2DE92C6F592B0275ULL;
	H += R;
	D = R + (((E << 36) | (E >> 28)) ^ ((E << 30) | (E >> 34)) ^ ((E << 25) | (E >> 39))) + ((E & F) ^ (E & G) ^ (F & G));
	W5 += (((W3 << 45) | (W3 >> 19)) ^ ((W3 << 3) | (W3 >> 61)) ^ (W3 >> 6)) + W14 + (((W6 << 63) | (W6 >> 1)) ^ ((W6 << 56) | (W6 >> 8)) ^ (W6 >> 7));
	R = C + (((H << 50) | (H >> 14)) ^ ((H << 46) | (H >> 18)) ^ ((H << 23) | (H >> 41))) + ((H & A) ^ (~H & B)) + W5 + 0x4A7484AA6EA6E483ULL;
	G += R;
	C = R + (((D << 36) | (D >> 28)) ^ ((D << 30) | (D >> 34)) ^ ((D << 25) | (D >> 39))) + ((D & E) ^ (D & F) ^ (E & F));
	W6 += (((W4 << 45) | (W4 >> 19)) ^ ((W4 << 3) | (W4 >> 61)) ^ (W4 >> 6)) + W15 + (((W7 << 63) | (W7 >> 1)) ^ ((W7 << 56) | (W7 >> 8)) ^ (W7 >> 7));
	R = B + (((G << 50) | (G >> 14)) ^ ((G << 46) | (G >> 18)) ^ ((G << 23) | (G >> 41))) + ((G & H) ^ (~G & A)) + W6 + 0x5CB0A9DCBD41FBD4ULL;
	F += R;
	B = R + (((C << 36) | (C >> 28)) ^ ((C << 30) | (C >> 34)) ^ ((C << 25) | (C >> 39))) + ((C & D) ^ (C & E) ^ (D & E));
	W7 += (((W5 << 45) | (W5 >> 19)) ^ ((W5 << 3) | (W5 >> 61)) ^ (W5 >> 6)) + W0 + (((W8 << 63) | (W8 >> 1)) ^ ((W8 << 56) | (W8 >> 8)) ^ (W8 >> 7));
	R = A + (((F << 50) | (F >> 14)) ^ ((F << 46) | (F >> 18)) ^ ((F << 23) | (F >> 41))) + ((F & G) ^ (~F & H)) + W7 + 0x76F988DA831153B5ULL;
	E += R;
	A = R + (((B << 36) | (B >> 28)) ^ ((B << 30) | (B >> 34)) ^ ((B << 25) | (B >> 39))) + ((B & C) ^ (B & D) ^ (C & D));
	W8 += (((W6 << 45) | (W6 >> 19)) ^ ((W6 << 3) | (W6 >> 61)) ^ (W6 >> 6)) + W1 + (((W9 << 63) | (W9 >> 1)) ^ ((W9 << 56) | (W9 >> 8)) ^ (W9 >> 7));
	R = H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + W8 + 0x983E5152EE66DFABULL;
	D += R;
	H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	W9 += (((W7 << 45) | (W7 >> 19)) ^ ((W7 << 3) | (W7 >> 61)) ^ (W7 >> 6)) + W2 + (((W10 << 63) | (W10 >> 1)) ^ ((W10 << 56) | (W10 >> 8)) ^ (W10 >> 7));
	R = G + (((D << 50) | (D >> 14)) ^ ((D << 46) | (D >> 18)) ^ ((D << 23) | (D >> 41))) + ((D & E) ^ (~D & F)) + W9 + 0xA831C66D2DB43210ULL;
	C += R;
	G = R + (((H << 36) | (H >> 28)) ^ ((H << 30) | (H >> 34)) ^ ((H << 25) | (H >> 39))) + ((H & A) ^ (H & B) ^ (A & B));
	W10 += (((W8 << 45) | (W8 >> 19)) ^ ((W8 << 3) | (W8 >> 61)) ^ (W8 >> 6)) + W3 + (((W11 << 63) | (W11 >> 1)) ^ ((W11 << 56) | (W11 >> 8)) ^ (W11 >> 7));
	R = F + (((C << 50) | (C >> 14)) ^ ((C << 46) | (C >> 18)) ^ ((C << 23) | (C >> 41))) + ((C & D) ^ (~C & E)) + W10 + 0xB00327C898FB213FULL;
	B += R;
	F = R + (((G << 36) | (G >> 28)) ^ ((G << 30) | (G >> 34)) ^ ((G << 25) | (G >> 39))) + ((G & H) ^ (G & A) ^ (H & A));
	W11 += (((W9 << 45) | (W9 >> 19)) ^ ((W9 << 3) | (W9 >> 61)) ^ (W9 >> 6)) + W4 + (((W12 << 63) | (W12 >> 1)) ^ ((W12 << 56) | (W12 >> 8)) ^ (W12 >> 7));
	R = E + (((B << 50) | (B >> 14)) ^ ((B << 46) | (B >> 18)) ^ ((B << 23) | (B >> 41))) + ((B & C) ^ (~B & D)) + W11 + 0xBF597FC7BEEF0EE4ULL;
	A += R;
	E = R + (((F << 36) | (F >> 28)) ^ ((F << 30) | (F >> 34)) ^ ((F << 25) | (F >> 39))) + ((F & G) ^ (F & H) ^ (G & H));
	W12 += (((W10 << 45) | (W10 >> 19)) ^ ((W10 << 3) | (W10 >> 61)) ^ (W10 >> 6)) + W5 + (((W13 << 63) | (W13 >> 1)) ^ ((W13 << 56) | (W13 >> 8)) ^ (W13 >> 7));
	R = D + (((A << 50) | (A >> 14)) ^ ((A << 46) | (A >> 18)) ^ ((A << 23) | (A >> 41))) + ((A & B) ^ (~A & C)) + W12 + 0xC6E00BF33DA88FC2ULL;
	H += R;
	D = R + (((E << 36) | (E >> 28)) ^ ((E << 30) | (E >> 34)) ^ ((E << 25) | (E >> 39))) + ((E & F) ^ (E & G) ^ (F & G));
	W13 += (((W11 << 45) | (W11 >> 19)) ^ ((W11 << 3) | (W11 >> 61)) ^ (W11 >> 6)) + W6 + (((W14 << 63) | (W14 >> 1)) ^ ((W14 << 56) | (W14 >> 8)) ^ (W14 >> 7));
	R = C + (((H << 50) | (H >> 14)) ^ ((H << 46) | (H >> 18)) ^ ((H << 23) | (H >> 41))) + ((H & A) ^ (~H & B)) + W13 + 0xD5A79147930AA725ULL;
	G += R;
	C = R + (((D << 36) | (D >> 28)) ^ ((D << 30) | (D >> 34)) ^ ((D << 25) | (D >> 39))) + ((D & E) ^ (D & F) ^ (E & F));
	W14 += (((W12 << 45) | (W12 >> 19)) ^ ((W12 << 3) | (W12 >> 61)) ^ (W12 >> 6)) + W7 + (((W15 << 63) | (W15 >> 1)) ^ ((W15 << 56) | (W15 >> 8)) ^ (W15 >> 7));
	R = B + (((G << 50) | (G >> 14)) ^ ((G << 46) | (G >> 18)) ^ ((G << 23) | (G >> 41))) + ((G & H) ^ (~G & A)) + W14 + 0x06CA6351E003826FULL;
	F += R;
	B = R + (((C << 36) | (C >> 28)) ^ ((C << 30) | (C >> 34)) ^ ((C << 25) | (C >> 39))) + ((C & D) ^ (C & E) ^ (D & E));
	W15 += (((W13 << 45) | (W13 >> 19)) ^ ((W13 << 3) | (W13 >> 61)) ^ (W13 >> 6)) + W8 + (((W0 << 63) | (W0 >> 1)) ^ ((W0 << 56) | (W0 >> 8)) ^ (W0 >> 7));
	R = A + (((F << 50) | (F >> 14)) ^ ((F << 46) | (F >> 18)) ^ ((F << 23) | (F >> 41))) + ((F & G) ^ (~F & H)) + W15 + 0x142929670A0E6E70ULL;
	E += R;
	A = R + (((B << 36) | (B >> 28)) ^ ((B << 30) | (B >> 34)) ^ ((B << 25) | (B >> 39))) + ((B & C) ^ (B & D) ^ (C & D));

	W0 += (((W14 << 45) | (W14 >> 19)) ^ ((W14 << 3) | (W14 >> 61)) ^ (W14 >> 6)) + W9 + (((W1 << 63) | (W1 >> 1)) ^ ((W1 << 56) | (W1 >> 8)) ^ (W1 >> 7));
	R = H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + W0 + 0x27B70A8546D22FFCULL;
	D += R;
	H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	W1 += (((W15 << 45) | (W15 >> 19)) ^ ((W15 << 3) | (W15 >> 61)) ^ (W15 >> 6)) + W10 + (((W2 << 63) | (W2 >> 1)) ^ ((W2 << 56) | (W2 >> 8)) ^ (W2 >> 7));
	R = G + (((D << 50) | (D >> 14)) ^ ((D << 46) | (D >> 18)) ^ ((D << 23) | (D >> 41))) + ((D & E) ^ (~D & F)) + W1 + 0x2E1B21385C26C926ULL;
	C += R;
	G = R + (((H << 36) | (H >> 28)) ^ ((H << 30) | (H >> 34)) ^ ((H << 25) | (H >> 39))) + ((H & A) ^ (H & B) ^ (A & B));
	W2 += (((W0 << 45) | (W0 >> 19)) ^ ((W0 << 3) | (W0 >> 61)) ^ (W0 >> 6)) + W11 + (((W3 << 63) | (W3 >> 1)) ^ ((W3 << 56) | (W3 >> 8)) ^ (W3 >> 7));
	R = F + (((C << 50) | (C >> 14)) ^ ((C << 46) | (C >> 18)) ^ ((C << 23) | (C >> 41))) + ((C & D) ^ (~C & E)) + W2 + 0x4D2C6DFC5AC42AEDULL;
	B += R;
	F = R + (((G << 36) | (G >> 28)) ^ ((G << 30) | (G >> 34)) ^ ((G << 25) | (G >> 39))) + ((G & H) ^ (G & A) ^ (H & A));
	W3 += (((W1 << 45) | (W1 >> 19)) ^ ((W1 << 3) | (W1 >> 61)) ^ (W1 >> 6)) + W12 + (((W4 << 63) | (W4 >> 1)) ^ ((W4 << 56) | (W4 >> 8)) ^ (W4 >> 7));
	R = E + (((B << 50) | (B >> 14)) ^ ((B << 46) | (B >> 18)) ^ ((B << 23) | (B >> 41))) + ((B & C) ^ (~B & D)) + W3 + 0x53380D139D95B3DFULL;
	A += R;
	E = R + (((F << 36) | (F >> 28)) ^ ((F << 30) | (F >> 34)) ^ ((F << 25) | (F >> 39))) + ((F & G) ^ (F & H) ^ (G & H));
	W4 += (((W2 << 45) | (W2 >> 19)) ^ ((W2 << 3) | (W2 >> 61)) ^ (W2 >> 6)) + W13 + (((W5 << 63) | (W5 >> 1)) ^ ((W5 << 56) | (W5 >> 8)) ^ (W5 >> 7));
	R = D + (((A << 50) | (A >> 14)) ^ ((A << 46) | (A >> 18)) ^ ((A << 23) | (A >> 41))) + ((A & B) ^ (~A & C)) + W4 + 0x650A73548BAF63DEULL;
	H += R;
	D = R + (((E << 36) | (E >> 28)) ^ ((E << 30) | (E >> 34)) ^ ((E << 25) | (E >> 39))) + ((E & F) ^ (E & G) ^ (F & G));
	W5 += (((W3 << 45) | (W3 >> 19)) ^ ((W3 << 3) | (W3 >> 61)) ^ (W3 >> 6)) + W14 + (((W6 << 63) | (W6 >> 1)) ^ ((W6 << 56) | (W6 >> 8)) ^ (W6 >> 7));
	R = C + (((H << 50) | (H >> 14)) ^ ((H << 46) | (H >> 18)) ^ ((H << 23) | (H >> 41))) + ((H & A) ^ (~H & B)) + W5 + 0x766A0ABB3C77B2A8ULL;
	G += R;
	C = R + (((D << 36) | (D >> 28)) ^ ((D << 30) | (D >> 34)) ^ ((D << 25) | (D >> 39))) + ((D & E) ^ (D & F) ^ (E & F));
	W6 += (((W4 << 45) | (W4 >> 19)) ^ ((W4 << 3) | (W4 >> 61)) ^ (W4 >> 6)) + W15 + (((W7 << 63) | (W7 >> 1)) ^ ((W7 << 56) | (W7 >> 8)) ^ (W7 >> 7));
	R = B + (((G << 50) | (G >> 14)) ^ ((G << 46) | (G >> 18)) ^ ((G << 23) | (G >> 41))) + ((G & H) ^ (~G & A)) + W6 + 0x81C2C92E47EDAEE6ULL;
	F += R;
	B = R + (((C << 36) | (C >> 28)) ^ ((C << 30) | (C >> 34)) ^ ((C << 25) | (C >> 39))) + ((C & D) ^ (C & E) ^ (D & E));
	W7 += (((W5 << 45) | (W5 >> 19)) ^ ((W5 << 3) | (W5 >> 61)) ^ (W5 >> 6)) + W0 + (((W8 << 63) | (W8 >> 1)) ^ ((W8 << 56) | (W8 >> 8)) ^ (W8 >> 7));
	R = A + (((F << 50) | (F >> 14)) ^ ((F << 46) | (F >> 18)) ^ ((F << 23) | (F >> 41))) + ((F & G) ^ (~F & H)) + W7 + 0x92722C851482353BULL;
	E += R;
	A = R + (((B << 36) | (B >> 28)) ^ ((B << 30) | (B >> 34)) ^ ((B << 25) | (B >> 39))) + ((B & C) ^ (B & D) ^ (C & D));
	W8 += (((W6 << 45) | (W6 >> 19)) ^ ((W6 << 3) | (W6 >> 61)) ^ (W6 >> 6)) + W1 + (((W9 << 63) | (W9 >> 1)) ^ ((W9 << 56) | (W9 >> 8)) ^ (W9 >> 7));
	R = H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + W8 + 0xA2BFE8A14CF10364ULL;
	D += R;
	H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	W9 += (((W7 << 45) | (W7 >> 19)) ^ ((W7 << 3) | (W7 >> 61)) ^ (W7 >> 6)) + W2 + (((W10 << 63) | (W10 >> 1)) ^ ((W10 << 56) | (W10 >> 8)) ^ (W10 >> 7));
	R = G + (((D << 50) | (D >> 14)) ^ ((D << 46) | (D >> 18)) ^ ((D << 23) | (D >> 41))) + ((D & E) ^ (~D & F)) + W9 + 0xA81A664BBC423001ULL;
	C += R;
	G = R + (((H << 36) | (H >> 28)) ^ ((H << 30) | (H >> 34)) ^ ((H << 25) | (H >> 39))) + ((H & A) ^ (H & B) ^ (A & B));
	W10 += (((W8 << 45) | (W8 >> 19)) ^ ((W8 << 3) | (W8 >> 61)) ^ (W8 >> 6)) + W3 + (((W11 << 63) | (W11 >> 1)) ^ ((W11 << 56) | (W11 >> 8)) ^ (W11 >> 7));
	R = F + (((C << 50) | (C >> 14)) ^ ((C << 46) | (C >> 18)) ^ ((C << 23) | (C >> 41))) + ((C & D) ^ (~C & E)) + W10 + 0xC24B8B70D0F89791ULL;
	B += R;
	F = R + (((G << 36) | (G >> 28)) ^ ((G << 30) | (G >> 34)) ^ ((G << 25) | (G >> 39))) + ((G & H) ^ (G & A) ^ (H & A));
	W11 += (((W9 << 45) | (W9 >> 19)) ^ ((W9 << 3) | (W9 >> 61)) ^ (W9 >> 6)) + W4 + (((W12 << 63) | (W12 >> 1)) ^ ((W12 << 56) | (W12 >> 8)) ^ (W12 >> 7));
	R = E + (((B << 50) | (B >> 14)) ^ ((B << 46) | (B >> 18)) ^ ((B << 23) | (B >> 41))) + ((B & C) ^ (~B & D)) + W11 + 0xC76C51A30654BE30ULL;
	A += R;
	E = R + (((F << 36) | (F >> 28)) ^ ((F << 30) | (F >> 34)) ^ ((F << 25) | (F >> 39))) + ((F & G) ^ (F & H) ^ (G & H));
	W12 += (((W10 << 45) | (W10 >> 19)) ^ ((W10 << 3) | (W10 >> 61)) ^ (W10 >> 6)) + W5 + (((W13 << 63) | (W13 >> 1)) ^ ((W13 << 56) | (W13 >> 8)) ^ (W13 >> 7));
	R = D + (((A << 50) | (A >> 14)) ^ ((A << 46) | (A >> 18)) ^ ((A << 23) | (A >> 41))) + ((A & B) ^ (~A & C)) + W12 + 0xD192E819D6EF5218ULL;
	H += R;
	D = R + (((E << 36) | (E >> 28)) ^ ((E << 30) | (E >> 34)) ^ ((E << 25) | (E >> 39))) + ((E & F) ^ (E & G) ^ (F & G));
	W13 += (((W11 << 45) | (W11 >> 19)) ^ ((W11 << 3) | (W11 >> 61)) ^ (W11 >> 6)) + W6 + (((W14 << 63) | (W14 >> 1)) ^ ((W14 << 56) | (W14 >> 8)) ^ (W14 >> 7));
	R = C + (((H << 50) | (H >> 14)) ^ ((H << 46) | (H >> 18)) ^ ((H << 23) | (H >> 41))) + ((H & A) ^ (~H & B)) + W13 + 0xD69906245565A910ULL;
	G += R;
	C = R + (((D << 36) | (D >> 28)) ^ ((D << 30) | (D >> 34)) ^ ((D << 25) | (D >> 39))) + ((D & E) ^ (D & F) ^ (E & F));
	W14 += (((W12 << 45) | (W12 >> 19)) ^ ((W12 << 3) | (W12 >> 61)) ^ (W12 >> 6)) + W7 + (((W15 << 63) | (W15 >> 1)) ^ ((W15 << 56) | (W15 >> 8)) ^ (W15 >> 7));
	R = B + (((G << 50) | (G >> 14)) ^ ((G << 46) | (G >> 18)) ^ ((G << 23) | (G >> 41))) + ((G & H) ^ (~G & A)) + W14 + 0xF40E35855771202AULL;
	F += R;
	B = R + (((C << 36) | (C >> 28)) ^ ((C << 30) | (C >> 34)) ^ ((C << 25) | (C >> 39))) + ((C & D) ^ (C & E) ^ (D & E));
	W15 += (((W13 << 45) | (W13 >> 19)) ^ ((W13 << 3) | (W13 >> 61)) ^ (W13 >> 6)) + W8 + (((W0 << 63) | (W0 >> 1)) ^ ((W0 << 56) | (W0 >> 8)) ^ (W0 >> 7));
	R = A + (((F << 50) | (F >> 14)) ^ ((F << 46) | (F >> 18)) ^ ((F << 23) | (F >> 41))) + ((F & G) ^ (~F & H)) + W15 + 0x106AA07032BBD1B8ULL;
	E += R;
	A = R + (((B << 36) | (B >> 28)) ^ ((B << 30) | (B >> 34)) ^ ((B << 25) | (B >> 39))) + ((B & C) ^ (B & D) ^ (C & D));

	W0 += (((W14 << 45) | (W14 >> 19)) ^ ((W14 << 3) | (W14 >> 61)) ^ (W14 >> 6)) + W9 + (((W1 << 63) | (W1 >> 1)) ^ ((W1 << 56) | (W1 >> 8)) ^ (W1 >> 7));
	R = H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + W0 + 0x19A4C116B8D2D0C8ULL;
	D += R;
	H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	W1 += (((W15 << 45) | (W15 >> 19)) ^ ((W15 << 3) | (W15 >> 61)) ^ (W15 >> 6)) + W10 + (((W2 << 63) | (W2 >> 1)) ^ ((W2 << 56) | (W2 >> 8)) ^ (W2 >> 7));
	R = G + (((D << 50) | (D >> 14)) ^ ((D << 46) | (D >> 18)) ^ ((D << 23) | (D >> 41))) + ((D & E) ^ (~D & F)) + W1 + 0x1E376C085141AB53ULL;
	C += R;
	G = R + (((H << 36) | (H >> 28)) ^ ((H << 30) | (H >> 34)) ^ ((H << 25) | (H >> 39))) + ((H & A) ^ (H & B) ^ (A & B));
	W2 += (((W0 << 45) | (W0 >> 19)) ^ ((W0 << 3) | (W0 >> 61)) ^ (W0 >> 6)) + W11 + (((W3 << 63) | (W3 >> 1)) ^ ((W3 << 56) | (W3 >> 8)) ^ (W3 >> 7));
	R = F + (((C << 50) | (C >> 14)) ^ ((C << 46) | (C >> 18)) ^ ((C << 23) | (C >> 41))) + ((C & D) ^ (~C & E)) + W2 + 0x2748774CDF8EEB99ULL;
	B += R;
	F = R + (((G << 36) | (G >> 28)) ^ ((G << 30) | (G >> 34)) ^ ((G << 25) | (G >> 39))) + ((G & H) ^ (G & A) ^ (H & A));
	W3 += (((W1 << 45) | (W1 >> 19)) ^ ((W1 << 3) | (W1 >> 61)) ^ (W1 >> 6)) + W12 + (((W4 << 63) | (W4 >> 1)) ^ ((W4 << 56) | (W4 >> 8)) ^ (W4 >> 7));
	R = E + (((B << 50) | (B >> 14)) ^ ((B << 46) | (B >> 18)) ^ ((B << 23) | (B >> 41))) + ((B & C) ^ (~B & D)) + W3 + 0x34B0BCB5E19B48A8ULL;
	A += R;
	E = R + (((F << 36) | (F >> 28)) ^ ((F << 30) | (F >> 34)) ^ ((F << 25) | (F >> 39))) + ((F & G) ^ (F & H) ^ (G & H));
	W4 += (((W2 << 45) | (W2 >> 19)) ^ ((W2 << 3) | (W2 >> 61)) ^ (W2 >> 6)) + W13 + (((W5 << 63) | (W5 >> 1)) ^ ((W5 << 56) | (W5 >> 8)) ^ (W5 >> 7));
	R = D + (((A << 50) | (A >> 14)) ^ ((A << 46) | (A >> 18)) ^ ((A << 23) | (A >> 41))) + ((A & B) ^ (~A & C)) + W4 + 0x391C0CB3C5C95A63ULL;
	H += R;
	D = R + (((E << 36) | (E >> 28)) ^ ((E << 30) | (E >> 34)) ^ ((E << 25) | (E >> 39))) + ((E & F) ^ (E & G) ^ (F & G));
	W5 += (((W3 << 45) | (W3 >> 19)) ^ ((W3 << 3) | (W3 >> 61)) ^ (W3 >> 6)) + W14 + (((W6 << 63) | (W6 >> 1)) ^ ((W6 << 56) | (W6 >> 8)) ^ (W6 >> 7));
	R = C + (((H << 50) | (H >> 14)) ^ ((H << 46) | (H >> 18)) ^ ((H << 23) | (H >> 41))) + ((H & A) ^ (~H & B)) + W5 + 0x4ED8AA4AE3418ACBULL;
	G += R;
	C = R + (((D << 36) | (D >> 28)) ^ ((D << 30) | (D >> 34)) ^ ((D << 25) | (D >> 39))) + ((D & E) ^ (D & F) ^ (E & F));
	W6 += (((W4 << 45) | (W4 >> 19)) ^ ((W4 << 3) | (W4 >> 61)) ^ (W4 >> 6)) + W15 + (((W7 << 63) | (W7 >> 1)) ^ ((W7 << 56) | (W7 >> 8)) ^ (W7 >> 7));
	R = B + (((G << 50) | (G >> 14)) ^ ((G << 46) | (G >> 18)) ^ ((G << 23) | (G >> 41))) + ((G & H) ^ (~G & A)) + W6 + 0x5B9CCA4F7763E373ULL;
	F += R;
	B = R + (((C << 36) | (C >> 28)) ^ ((C << 30) | (C >> 34)) ^ ((C << 25) | (C >> 39))) + ((C & D) ^ (C & E) ^ (D & E));
	W7 += (((W5 << 45) | (W5 >> 19)) ^ ((W5 << 3) | (W5 >> 61)) ^ (W5 >> 6)) + W0 + (((W8 << 63) | (W8 >> 1)) ^ ((W8 << 56) | (W8 >> 8)) ^ (W8 >> 7));
	R = A + (((F << 50) | (F >> 14)) ^ ((F << 46) | (F >> 18)) ^ ((F << 23) | (F >> 41))) + ((F & G) ^ (~F & H)) + W7 + 0x682E6FF3D6B2B8A3ULL;
	E += R;
	A = R + (((B << 36) | (B >> 28)) ^ ((B << 30) | (B >> 34)) ^ ((B << 25) | (B >> 39))) + ((B & C) ^ (B & D) ^ (C & D));
	W8 += (((W6 << 45) | (W6 >> 19)) ^ ((W6 << 3) | (W6 >> 61)) ^ (W6 >> 6)) + W1 + (((W9 << 63) | (W9 >> 1)) ^ ((W9 << 56) | (W9 >> 8)) ^ (W9 >> 7));
	R = H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + W8 + 0x748F82EE5DEFB2FCULL;
	D += R;
	H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	W9 += (((W7 << 45) | (W7 >> 19)) ^ ((W7 << 3) | (W7 >> 61)) ^ (W7 >> 6)) + W2 + (((W10 << 63) | (W10 >> 1)) ^ ((W10 << 56) | (W10 >> 8)) ^ (W10 >> 7));
	R = G + (((D << 50) | (D >> 14)) ^ ((D << 46) | (D >> 18)) ^ ((D << 23) | (D >> 41))) + ((D & E) ^ (~D & F)) + W9 + 0x78A5636F43172F60ULL;
	C += R;
	G = R + (((H << 36) | (H >> 28)) ^ ((H << 30) | (H >> 34)) ^ ((H << 25) | (H >> 39))) + ((H & A) ^ (H & B) ^ (A & B));
	W10 += (((W8 << 45) | (W8 >> 19)) ^ ((W8 << 3) | (W8 >> 61)) ^ (W8 >> 6)) + W3 + (((W11 << 63) | (W11 >> 1)) ^ ((W11 << 56) | (W11 >> 8)) ^ (W11 >> 7));
	R = F + (((C << 50) | (C >> 14)) ^ ((C << 46) | (C >> 18)) ^ ((C << 23) | (C >> 41))) + ((C & D) ^ (~C & E)) + W10 + 0x84C87814A1F0AB72ULL;
	B += R;
	F = R + (((G << 36) | (G >> 28)) ^ ((G << 30) | (G >> 34)) ^ ((G << 25) | (G >> 39))) + ((G & H) ^ (G & A) ^ (H & A));
	W11 += (((W9 << 45) | (W9 >> 19)) ^ ((W9 << 3) | (W9 >> 61)) ^ (W9 >> 6)) + W4 + (((W12 << 63) | (W12 >> 1)) ^ ((W12 << 56) | (W12 >> 8)) ^ (W12 >> 7));
	R = E + (((B << 50) | (B >> 14)) ^ ((B << 46) | (B >> 18)) ^ ((B << 23) | (B >> 41))) + ((B & C) ^ (~B & D)) + W11 + 0x8CC702081A6439ECULL;
	A += R;
	E = R + (((F << 36) | (F >> 28)) ^ ((F << 30) | (F >> 34)) ^ ((F << 25) | (F >> 39))) + ((F & G) ^ (F & H) ^ (G & H));
	W12 += (((W10 << 45) | (W10 >> 19)) ^ ((W10 << 3) | (W10 >> 61)) ^ (W10 >> 6)) + W5 + (((W13 << 63) | (W13 >> 1)) ^ ((W13 << 56) | (W13 >> 8)) ^ (W13 >> 7));
	R = D + (((A << 50) | (A >> 14)) ^ ((A << 46) | (A >> 18)) ^ ((A << 23) | (A >> 41))) + ((A & B) ^ (~A & C)) + W12 + 0x90BEFFFA23631E28ULL;
	H += R;
	D = R + (((E << 36) | (E >> 28)) ^ ((E << 30) | (E >> 34)) ^ ((E << 25) | (E >> 39))) + ((E & F) ^ (E & G) ^ (F & G));
	W13 += (((W11 << 45) | (W11 >> 19)) ^ ((W11 << 3) | (W11 >> 61)) ^ (W11 >> 6)) + W6 + (((W14 << 63) | (W14 >> 1)) ^ ((W14 << 56) | (W14 >> 8)) ^ (W14 >> 7));
	R = C + (((H << 50) | (H >> 14)) ^ ((H << 46) | (H >> 18)) ^ ((H << 23) | (H >> 41))) + ((H & A) ^ (~H & B)) + W13 + 0xA4506CEBDE82BDE9ULL;
	G += R;
	C = R + (((D << 36) | (D >> 28)) ^ ((D << 30) | (D >> 34)) ^ ((D << 25) | (D >> 39))) + ((D & E) ^ (D & F) ^ (E & F));
	W14 += (((W12 << 45) | (W12 >> 19)) ^ ((W12 << 3) | (W12 >> 61)) ^ (W12 >> 6)) + W7 + (((W15 << 63) | (W15 >> 1)) ^ ((W15 << 56) | (W15 >> 8)) ^ (W15 >> 7));
	R = B + (((G << 50) | (G >> 14)) ^ ((G << 46) | (G >> 18)) ^ ((G << 23) | (G >> 41))) + ((G & H) ^ (~G & A)) + W14 + 0xBEF9A3F7B2C67915ULL;
	F += R;
	B = R + (((C << 36) | (C >> 28)) ^ ((C << 30) | (C >> 34)) ^ ((C << 25) | (C >> 39))) + ((C & D) ^ (C & E) ^ (D & E));
	W15 += (((W13 << 45) | (W13 >> 19)) ^ ((W13 << 3) | (W13 >> 61)) ^ (W13 >> 6)) + W8 + (((W0 << 63) | (W0 >> 1)) ^ ((W0 << 56) | (W0 >> 8)) ^ (W0 >> 7));
	R = A + (((F << 50) | (F >> 14)) ^ ((F << 46) | (F >> 18)) ^ ((F << 23) | (F >> 41))) + ((F & G) ^ (~F & H)) + W15 + 0xC67178F2E372532BULL;
	E += R;
	A = R + (((B << 36) | (B >> 28)) ^ ((B << 30) | (B >> 34)) ^ ((B << 25) | (B >> 39))) + ((B & C) ^ (B & D) ^ (C & D));

	W0 += (((W14 << 45) | (W14 >> 19)) ^ ((W14 << 3) | (W14 >> 61)) ^ (W14 >> 6)) + W9 + (((W1 << 63) | (W1 >> 1)) ^ ((W1 << 56) | (W1 >> 8)) ^ (W1 >> 7));
	R = H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + W0 + 0xCA273ECEEA26619CULL;
	D += R;
	H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	W1 += (((W15 << 45) | (W15 >> 19)) ^ ((W15 << 3) | (W15 >> 61)) ^ (W15 >> 6)) + W10 + (((W2 << 63) | (W2 >> 1)) ^ ((W2 << 56) | (W2 >> 8)) ^ (W2 >> 7));
	R = G + (((D << 50) | (D >> 14)) ^ ((D << 46) | (D >> 18)) ^ ((D << 23) | (D >> 41))) + ((D & E) ^ (~D & F)) + W1 + 0xD186B8C721C0C207ULL;
	C += R;
	G = R + (((H << 36) | (H >> 28)) ^ ((H << 30) | (H >> 34)) ^ ((H << 25) | (H >> 39))) + ((H & A) ^ (H & B) ^ (A & B));
	W2 += (((W0 << 45) | (W0 >> 19)) ^ ((W0 << 3) | (W0 >> 61)) ^ (W0 >> 6)) + W11 + (((W3 << 63) | (W3 >> 1)) ^ ((W3 << 56) | (W3 >> 8)) ^ (W3 >> 7));
	R = F + (((C << 50) | (C >> 14)) ^ ((C << 46) | (C >> 18)) ^ ((C << 23) | (C >> 41))) + ((C & D) ^ (~C & E)) + W2 + 0xEADA7DD6CDE0EB1EULL;
	B += R;
	F = R + (((G << 36) | (G >> 28)) ^ ((G << 30) | (G >> 34)) ^ ((G << 25) | (G >> 39))) + ((G & H) ^ (G & A) ^ (H & A));
	W3 += (((W1 << 45) | (W1 >> 19)) ^ ((W1 << 3) | (W1 >> 61)) ^ (W1 >> 6)) + W12 + (((W4 << 63) | (W4 >> 1)) ^ ((W4 << 56) | (W4 >> 8)) ^ (W4 >> 7));
	R = E + (((B << 50) | (B >> 14)) ^ ((B << 46) | (B >> 18)) ^ ((B << 23) | (B >> 41))) + ((B & C) ^ (~B & D)) + W3 + 0xF57D4F7FEE6ED178ULL;
	A += R;
	E = R + (((F << 36) | (F >> 28)) ^ ((F << 30) | (F >> 34)) ^ ((F << 25) | (F >> 39))) + ((F & G) ^ (F & H) ^ (G & H));
	W4 += (((W2 << 45) | (W2 >> 19)) ^ ((W2 << 3) | (W2 >> 61)) ^ (W2 >> 6)) + W13 + (((W5 << 63) | (W5 >> 1)) ^ ((W5 << 56) | (W5 >> 8)) ^ (W5 >> 7));
	R = D + (((A << 50) | (A >> 14)) ^ ((A << 46) | (A >> 18)) ^ ((A << 23) | (A >> 41))) + ((A & B) ^ (~A & C)) + W4 + 0x06F067AA72176FBAULL;
	H += R;
	D = R + (((E << 36) | (E >> 28)) ^ ((E << 30) | (E >> 34)) ^ ((E << 25) | (E >> 39))) + ((E & F) ^ (E & G) ^ (F & G));
	W5 += (((W3 << 45) | (W3 >> 19)) ^ ((W3 << 3) | (W3 >> 61)) ^ (W3 >> 6)) + W14 + (((W6 << 63) | (W6 >> 1)) ^ ((W6 << 56) | (W6 >> 8)) ^ (W6 >> 7));
	R = C + (((H << 50) | (H >> 14)) ^ ((H << 46) | (H >> 18)) ^ ((H << 23) | (H >> 41))) + ((H & A) ^ (~H & B)) + W5 + 0x0A637DC5A2C898A6ULL;
	G += R;
	C = R + (((D << 36) | (D >> 28)) ^ ((D << 30) | (D >> 34)) ^ ((D << 25) | (D >> 39))) + ((D & E) ^ (D & F) ^ (E & F));
	W6 += (((W4 << 45) | (W4 >> 19)) ^ ((W4 << 3) | (W4 >> 61)) ^ (W4 >> 6)) + W15 + (((W7 << 63) | (W7 >> 1)) ^ ((W7 << 56) | (W7 >> 8)) ^ (W7 >> 7));
	R = B + (((G << 50) | (G >> 14)) ^ ((G << 46) | (G >> 18)) ^ ((G << 23) | (G >> 41))) + ((G & H) ^ (~G & A)) + W6 + 0x113F9804BEF90DAEULL;
	F += R;
	B = R + (((C << 36) | (C >> 28)) ^ ((C << 30) | (C >> 34)) ^ ((C << 25) | (C >> 39))) + ((C & D) ^ (C & E) ^ (D & E));
	W7 += (((W5 << 45) | (W5 >> 19)) ^ ((W5 << 3) | (W5 >> 61)) ^ (W5 >> 6)) + W0 + (((W8 << 63) | (W8 >> 1)) ^ ((W8 << 56) | (W8 >> 8)) ^ (W8 >> 7));
	R = A + (((F << 50) | (F >> 14)) ^ ((F << 46) | (F >> 18)) ^ ((F << 23) | (F >> 41))) + ((F & G) ^ (~F & H)) + W7 + 0x1B710B35131C471BULL;
	E += R;
	A = R + (((B << 36) | (B >> 28)) ^ ((B << 30) | (B >> 34)) ^ ((B << 25) | (B >> 39))) + ((B & C) ^ (B & D) ^ (C & D));
	W8 += (((W6 << 45) | (W6 >> 19)) ^ ((W6 << 3) | (W6 >> 61)) ^ (W6 >> 6)) + W1 + (((W9 << 63) | (W9 >> 1)) ^ ((W9 << 56) | (W9 >> 8)) ^ (W9 >> 7));
	R = H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + W8 + 0x28DB77F523047D84ULL;
	D += R;
	H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	W9 += (((W7 << 45) | (W7 >> 19)) ^ ((W7 << 3) | (W7 >> 61)) ^ (W7 >> 6)) + W2 + (((W10 << 63) | (W10 >> 1)) ^ ((W10 << 56) | (W10 >> 8)) ^ (W10 >> 7));
	R = G + (((D << 50) | (D >> 14)) ^ ((D << 46) | (D >> 18)) ^ ((D << 23) | (D >> 41))) + ((D & E) ^ (~D & F)) + W9 + 0x32CAAB7B40C72493ULL;
	C += R;
	G = R + (((H << 36) | (H >> 28)) ^ ((H << 30) | (H >> 34)) ^ ((H << 25) | (H >> 39))) + ((H & A) ^ (H & B) ^ (A & B));
	W10 += (((W8 << 45) | (W8 >> 19)) ^ ((W8 << 3) | (W8 >> 61)) ^ (W8 >> 6)) + W3 + (((W11 << 63) | (W11 >> 1)) ^ ((W11 << 56) | (W11 >> 8)) ^ (W11 >> 7));
	R = F + (((C << 50) | (C >> 14)) ^ ((C << 46) | (C >> 18)) ^ ((C << 23) | (C >> 41))) + ((C & D) ^ (~C & E)) + W10 + 0x3C9EBE0A15C9BEBCULL;
	B += R;
	F = R + (((G << 36) | (G >> 28)) ^ ((G << 30) | (G >> 34)) ^ ((G << 25) | (G >> 39))) + ((G & H) ^ (G & A) ^ (H & A));
	W11 += (((W9 << 45) | (W9 >> 19)) ^ ((W9 << 3) | (W9 >> 61)) ^ (W9 >> 6)) + W4 + (((W12 << 63) | (W12 >> 1)) ^ ((W12 << 56) | (W12 >> 8)) ^ (W12 >> 7));
	R = E + (((B << 50) | (B >> 14)) ^ ((B << 46) | (B >> 18)) ^ ((B << 23) | (B >> 41))) + ((B & C) ^ (~B & D)) + W11 + 0x431D67C49C100D4CULL;
	A += R;
	E = R + (((F << 36) | (F >> 28)) ^ ((F << 30) | (F >> 34)) ^ ((F << 25) | (F >> 39))) + ((F & G) ^ (F & H) ^ (G & H));
	W12 += (((W10 << 45) | (W10 >> 19)) ^ ((W10 << 3) | (W10 >> 61)) ^ (W10 >> 6)) + W5 + (((W13 << 63) | (W13 >> 1)) ^ ((W13 << 56) | (W13 >> 8)) ^ (W13 >> 7));
	R = D + (((A << 50) | (A >> 14)) ^ ((A << 46) | (A >> 18)) ^ ((A << 23) | (A >> 41))) + ((A & B) ^ (~A & C)) + W12 + 0x4CC5D4BECB3E42B6ULL;
	H += R;
	D = R + (((E << 36) | (E >> 28)) ^ ((E << 30) | (E >> 34)) ^ ((E << 25) | (E >> 39))) + ((E & F) ^ (E & G) ^ (F & G));
	W13 += (((W11 << 45) | (W11 >> 19)) ^ ((W11 << 3) | (W11 >> 61)) ^ (W11 >> 6)) + W6 + (((W14 << 63) | (W14 >> 1)) ^ ((W14 << 56) | (W14 >> 8)) ^ (W14 >> 7));
	R = C + (((H << 50) | (H >> 14)) ^ ((H << 46) | (H >> 18)) ^ ((H << 23) | (H >> 41))) + ((H & A) ^ (~H & B)) + W13 + 0x597F299CFC657E2AULL;
	G += R;
	C = R + (((D << 36) | (D >> 28)) ^ ((D << 30) | (D >> 34)) ^ ((D << 25) | (D >> 39))) + ((D & E) ^ (D & F) ^ (E & F));
	W14 += (((W12 << 45) | (W12 >> 19)) ^ ((W12 << 3) | (W12 >> 61)) ^ (W12 >> 6)) + W7 + (((W15 << 63) | (W15 >> 1)) ^ ((W15 << 56) | (W15 >> 8)) ^ (W15 >> 7));
	R = B + (((G << 50) | (G >> 14)) ^ ((G << 46) | (G >> 18)) ^ ((G << 23) | (G >> 41))) + ((G & H) ^ (~G & A)) + W14 + 0x5FCB6FAB3AD6FAECULL;
	F += R;
	B = R + (((C << 36) | (C >> 28)) ^ ((C << 30) | (C >> 34)) ^ ((C << 25) | (C >> 39))) + ((C & D) ^ (C & E) ^ (D & E));
	W15 += (((W13 << 45) | (W13 >> 19)) ^ ((W13 << 3) | (W13 >> 61)) ^ (W13 >> 6)) + W8 + (((W0 << 63) | (W0 >> 1)) ^ ((W0 << 56) | (W0 >> 8)) ^ (W0 >> 7));
	R = A + (((F << 50) | (F >> 14)) ^ ((F << 46) | (F >> 18)) ^ ((F << 23) | (F >> 41))) + ((F & G) ^ (~F & H)) + W15 + 0x6C44198C4A475817ULL;
	E += R;
	A = R + (((B << 36) | (B >> 28)) ^ ((B << 30) | (B >> 34)) ^ ((B << 25) | (B >> 39))) + ((B & C) ^ (B & D) ^ (C & D));

	State[0] += A;
	State[1] += B;
	State[2] += C;
	State[3] += D;
	State[4] += E;
	State[5] += F;
	State[6] += G;
	State[7] += H;
}

#if defined(CEX_HAS_AVX2)

void SHA2::PermuteR80P4x1024H(const std::vector<byte> &Input, size_t InOffset, std::vector<ULong256> &State)
{
	std::array<ULong256, 8> A;
	std::array<ULong256, 80> W;
	ULong256 K;
	size_t i;
	size_t j;

	MemoryTools::Copy(State, 0, A, 0, State.size() * sizeof(ULong256));

#if defined(CEX_IS_LITTLE_ENDIAN)
	for (i = 0; i < 16; ++i)
	{
		W[i].Load(
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong))),
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong)) + 128),
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong)) + 256),
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong)) + 384));
	}
#else
	MemoryTools::Copy(Input, InOffset, W, 0, A.size() * sizeof(ULong256));
#endif

	for (i = 16; i < 80; i++)
	{
		W[i] = Sigma1(W[i - 2]) + W[i - 7] + Sigma0(W[i - 15]) + W[i - 16];
	}

	j = 0;
	for (i = 0; i < 10; ++i)
	{
		K.Load(SHA2512_RC80[j]);
		Round512W(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j]);
		Round512W(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j]);
		Round512W(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j]);
		Round512W(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j]);
		Round512W(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j]);
		Round512W(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j]);
		Round512W(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j]);
		Round512W(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], K, W[j]);
		++j;
	}

	State[0] += A[0];
	State[1] += A[1];
	State[2] += A[2];
	State[3] += A[3];
	State[4] += A[4];
	State[5] += A[5];
	State[6] += A[6];
	State[7] += A[7];
}

#endif

#if defined(CEX_HAS_AVX512)

void SHA2::PermuteR80P8x1024H(const std::vector<byte> &Input, size_t InOffset, std::vector<ULong512> &State)
{
	std::array<ULong512, 8> A;
	std::array<ULong512, 80> W;
	ULong512 K;
	size_t i;
	size_t j;

	MemoryTools::Copy(State, 0, A, 0, State.size() * sizeof(ULong512));

#if defined(CEX_IS_LITTLE_ENDIAN)
	for (i = 0; i < 16; ++i)
	{
		W[i].Load(
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong))),
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong)) + 128),
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong)) + 256),
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong)) + 384),
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong)) + 512),
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong)) + 640),
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong)) + 768),
			IntegerTools::BeBytesTo64(Input, InOffset + (i * sizeof(ulong)) + 896));
	}
#else
	MemoryTools::Copy(Input, InOffset, W, 0, A.size() * sizeof(ULong512));
#endif

	for (i = 16; i < 80; i++)
	{
		W[i] = Sigma1(W[i - 2]) + W[i - 7] + Sigma0(W[i - 15]) + W[i - 16];
	}

	j = 0;
	for (i = 0; i < 10; ++i)
	{
		K.Load(SHA2512_RC80[j]);
		Round512W(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j];
		Round512W(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j];
		Round512W(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j];
		Round512W(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j];
		Round512W(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j];
		Round512W(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j];
		Round512W(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], K, W[j]);
		++j;
		K.Load(SHA2512_RC80[j];
		Round512W(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], K, W[j]);
		++j;
	}

	State[0] += A[0];
	State[1] += A[1];
	State[2] += A[2];
	State[3] += A[3];
	State[4] += A[4];
	State[5] += A[5];
	State[6] += A[6];
	State[7] += A[7];
}

#endif

//~~~Private Functions~~~//

void SHA2::Round256(uint A, uint B, uint C, uint &D, uint E, uint F, uint G, uint &H, uint M, uint P)
{
	uint R(H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + M + P);
	D += R;
	H = R + ((((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
}

void SHA2::Round512(ulong A, ulong B, ulong C, ulong &D, ulong E, ulong F, ulong G, ulong &H, ulong M, ulong P)
{
	ulong R(H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + M + P);
	D += R;
	H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
}

NAMESPACE_DIGESTEND