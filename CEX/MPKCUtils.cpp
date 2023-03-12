#include "MPKCUtils.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_MCELIECE

using Tools::IntegerTools;
using Tools::MemoryTools;

static const int32_t MCELIECE_GFBITS = 13;
static const int32_t MCELIECE_GFMASK = ((1 << MCELIECE_GFBITS) - 1);

void MPKCUtils::ApplyBenes(uint8_t* R, const uint8_t* Bits, bool Reverse)
{
	// input: r, sequence of bits to be permuted
	// bits, condition bits of the Benes network
	// rev, 0 for normal application; !0 for inverse
	// output: r, permuted bits

	uint64_t riv[2][64];
	uint64_t rih[2][64];
	uint64_t biv[64];
	uint64_t bih[64];
	size_t i;
	int32_t inc;
	uint32_t iter;
	const uint8_t* bptr;
	uint8_t* rptr;

	rptr = R;

	if (Reverse)
	{
		bptr = Bits + 12288;
		inc = -1024;
	}
	else
	{
		bptr = Bits;
		inc = 0;
	}

	for (i = 0; i < 64; ++i)
	{
		riv[0][i] = IntegerTools::LeBytesTo64Raw(rptr + i * 16);
		riv[1][i] = IntegerTools::LeBytesTo64Raw(rptr + i * 16 + 8);
	}

	Transpose64x64(rih[0], riv[0]);
	Transpose64x64(rih[1], riv[1]);

	for (iter = 0; iter <= 6; iter++)
	{
		for (i = 0; i < 64; ++i)
		{
			biv[i] = IntegerTools::LeBytesTo64Raw(bptr);
			bptr += 8;
		}

		bptr += inc;
		Transpose64x64(bih, biv);
		LayerEx(rih[0], bih, iter);
	}

	Transpose64x64(riv[0], rih[0]);
	Transpose64x64(riv[1], rih[1]);

	for (iter = 0; iter <= 5; iter++)
	{
		for (i = 0; i < 64; ++i)
		{
			biv[i] = IntegerTools::LeBytesTo64Raw(bptr);
			bptr += 8;
		}

		bptr += inc;
		LayerIn(riv, biv, iter);
	}

	iter = 5;

	do
	{
		--iter;
		for (i = 0; i < 64; ++i)
		{
			biv[i] = IntegerTools::LeBytesTo64Raw(bptr);
			bptr += 8;
		}

		bptr += inc;
		LayerIn(riv, biv, iter);
	} while (iter != 0);

	Transpose64x64(rih[0], riv[0]);
	Transpose64x64(rih[1], riv[1]);

	iter = 7;

	do
	{
		--iter;
		for (i = 0; i < 64; ++i)
		{
			biv[i] = IntegerTools::LeBytesTo64Raw(bptr);
			bptr += 8;
		}

		bptr += inc;
		Transpose64x64(bih, biv);
		LayerEx(rih[0], bih, iter);
	} while (iter != 0);

	Transpose64x64(riv[0], rih[0]);
	Transpose64x64(riv[1], rih[1]);

	for (i = 0; i < 64; ++i)
	{
		IntegerTools::Le64ToBytesRaw(riv[0][i], rptr + i * 16);
		IntegerTools::Le64ToBytesRaw(riv[1][i], rptr + i * 16 + 8);
	}
}

uint16_t MPKCUtils::BitReverse(uint16_t A)
{
	A = ((A & 0x00FFU) << 8) | ((A & 0xFF00U) >> 8);
	A = ((A & 0x0F0FU) << 4) | ((A & 0xF0F0U) >> 4);
	A = ((A & 0x3333U) << 2) | ((A & 0xCCCCU) >> 2);
	A = ((A & 0x5555U) << 1) | ((A & 0xAAAAU) >> 1);

	return A >> 3;
}

void MPKCUtils::Bm(uint16_t* Output, const uint16_t* S, uint32_t SysT)
{
	// the Berlekamp-Massey algorithm.
	// input: s, sequence of field elements
	// output: out, minimal polynomial of s

	std::vector<uint16_t> T(SysT + 1);
	std::vector<uint16_t> C(SysT + 1);
	std::vector<uint16_t> B(SysT + 1);
	size_t i;
	uint16_t b;
	uint16_t d;
	uint16_t f;
	uint16_t N;
	uint16_t L;
	uint16_t mle;
	uint16_t mne;

	b = 1;
	L = 0;
	B[1] = 1;
	C[0] = 1;

	for (N = 0; N < 2 * SysT; ++N)
	{
		d = 0;

		for (i = 0; i <= IntegerTools::Min((uint32_t)N, (uint32_t)SysT); ++i)
		{
			d ^= MPKCUtils::GfMultiply(C[i], S[N - i]);
		}

		mne = d;
		mne -= 1;
		mne >>= 15;
		mne -= 1;
		mle = N;
		mle -= 2 * L;
		mle >>= 15;
		mle -= 1;
		mle &= mne;

		MemoryTools::Copy(C, 0, T, 0, SysT * sizeof(uint16_t));

		f = MPKCUtils::GfFrac(b, d);

		for (i = 0; i <= SysT; ++i)
		{
			C[i] ^= MPKCUtils::GfMultiply(f, B[i]) & mne;
		}

		L = (L & ~mle) | ((N + 1 - L) & mle);

		for (i = 0; i <= SysT; ++i)
		{
			B[i] = (B[i] & ~mle) | (T[i] & mle);
		}

		b = (b & ~mle) | (d & mle);

		for (i = SysT; i >= 1; --i)
		{
			B[i] = B[i - 1];
		}

		B[0] = 0;
	}

	for (i = 0; i <= SysT; ++i)
	{
		Output[i] = C[SysT - i];
	}
}

void MPKCUtils::CbRecursion(uint8_t* Output, int64_t Position, int64_t Step, const int16_t* Pi, int64_t W, int64_t N, int32_t* Temp)
{
	// parameters: 1 <= w <= 14; n = 2^w.
	// input: permutation pi of {0,1,...,n-1}
	// output: (2m-1)n/2 control bits at positions pos,pos+step,...
	// output position pos is by definition 1&(out[pos/8]>>(pos&7))
	// caller must 0-initialize positions first, temp must have space for int32_t[2*n]

	int32_t* A = Temp;
	int32_t* B = (Temp + N);
	// q can start anywhere between temp+n and temp+n/2
	int16_t* q = ((int16_t*)(Temp + N + N / 4));
	int64_t i;
	int64_t j;
	int64_t x;

	if (W != 1)
	{
		for (x = 0; x < N; ++x)
		{
			A[x] = ((Pi[x] ^ 1) << 16) | Pi[x ^ 1];
		}

		MPKCUtils::Sort32(A, N); // A = (id<<16)+pibar

		for (x = 0; x < N; ++x)
		{
			int32_t Ax = A[x];
			int32_t px = Ax & 0x0000FFFFL;
			int32_t cx = px;

			if ((int32_t)x < cx)
			{
				cx = (int32_t)x;
			}

			B[x] = (px << 16) | cx;
		}

		// B = (p<<16)+c

		for (x = 0; x < N; ++x)
		{
			A[x] = (A[x] << 16) | (int32_t)x; // A = (pibar<<16)+id
		}

		MPKCUtils::Sort32(A, N); // A = (id<<16)+pibar^-1

		for (x = 0; x < N; ++x)
		{
			A[x] = (A[x] << 16) + (B[x] >> 16); // A = (pibar^(-1)<<16)+pibar
		}

		MPKCUtils::Sort32(A, N); // A = (id<<16)+pibar^2

		if (W <= 10)
		{
			for (x = 0; x < N; ++x)
			{
				B[x] = ((A[x] & 0x0000FFFFL) << 10) | (B[x] & 0x000003FFL);
			}

			for (i = 1; i < W - 1; ++i)
			{
				// B = (p<<10)+c

				for (x = 0; x < N; ++x)
				{
					A[x] = ((B[x] & ~0x000003FFL) << 6) | (int32_t)x; // A = (p<<16)+id
				}

				MPKCUtils::Sort32(A, N); // A = (id<<16)+p^{-1}

				for (x = 0; x < N; ++x)
				{
					A[x] = (A[x] << 20) | B[x]; // A = (p^{-1}<<20)+(p<<10)+c
				}

				MPKCUtils::Sort32(A, N); // A = (id<<20)+(pp<<10)+cp

				for (x = 0; x < N; ++x)
				{
					int32_t ppcpx = A[x] & 0x000FFFFFL;
					int32_t ppcx = (A[x] & 0x000FFC00L) | (B[x] & 0x000003FFL);

					if (ppcpx < ppcx)
					{
						ppcx = ppcpx;
					}

					B[x] = ppcx;
				}
			}

			for (x = 0; x < N; ++x)
			{
				B[x] &= 0x000003FFL;
			}
		}
		else
		{
			for (x = 0; x < N; ++x)
			{
				B[x] = (A[x] << 16) | (B[x] & 0x0000FFFFL);
			}

			for (i = 1; i < W - 1; ++i)
			{
				// B = (p<<16)+c

				for (x = 0; x < N; ++x)
				{
					A[x] = (B[x] & ~0x0000FFFFL) | (int32_t)x;
				}

				MPKCUtils::Sort32(A, N); // A = (id<<16)+p^(-1)

				for (x = 0; x < N; ++x)
				{
					A[x] = (A[x] << 16) | (B[x] & 0x0000FFFFL);
				}

				// A = p^(-1)<<16+c

				if (i < W - 2)
				{
					for (x = 0; x < N; ++x)
					{
						B[x] = (A[x] & ~0x0000FFFFL) | (B[x] >> 16);
					}

					// B = (p^(-1)<<16)+p

					MPKCUtils::Sort32(B, N); // B = (id<<16)+p^(-2)

					for (x = 0; x < N; ++x)
					{
						B[x] = (B[x] << 16) | (A[x] & 0x0000FFFFL);
					}
					// B = (p^(-2)<<16)+c
				}

				MPKCUtils::Sort32(A, N);

				// A = id<<16+cp
				for (x = 0; x < N; ++x)
				{
					int32_t cpx = (B[x] & ~0x0000FFFF) | (A[x] & 0x0000FFFF);

					if (cpx < B[x])
					{
						B[x] = cpx;
					}
				}
			}

			for (x = 0; x < N; ++x)
			{
				B[x] &= 0x0000FFFF;
			}
		}

		for (x = 0; x < N; ++x)
		{
			A[x] = (((int32_t)Pi[x]) << 16) + (int32_t)x;
		}

		MPKCUtils::Sort32(A, N); // A = (id<<16)+pi^(-1)

		for (j = 0; j < N / 2; ++j)
		{
			x = 2 * j;
			int32_t fj = B[x] & 1;		// f[j]
			int32_t Fx = (int32_t)x + fj;	// F[x]
			int32_t Fx1 = Fx ^ 1;		// F[x+1]

			Output[Position >> 3] ^= fj << (Position & 7);
			Position += Step;

			B[x] = (A[x] << 16) | Fx;
			B[x + 1] = (A[x + 1] << 16) | Fx1;
		}

		// B = (pi^(-1)<<16)+F 
		MPKCUtils::Sort32(B, N);
		// B = (id<<16)+F(pi) 
		Position += (2 * W - 3) * Step * (N / 2);

		for (int64_t k = 0; k < N / 2; ++k)
		{
			int64_t y = 2 * k;
			int32_t lk = B[y] & 1;		// l[k] 
			int32_t Ly = (int32_t)y + lk;	// L[y] 
			int32_t Ly1 = Ly ^ 1;		// L[y+1] 

			Output[Position >> 3] ^= lk << (Position & 7);
			Position += Step;
			A[y] = (Ly << 16) | (B[y] & 0x0000FFFFL);
			A[y + 1] = (Ly1 << 16) | (B[y + 1] & 0x0000FFFFL);
		}

		// A = (L<<16)+F(pi) 
		MPKCUtils::Sort32(A, N); // A = (id<<16)+F(pi(L)) = (id<<16)+M 
		Position -= (2 * W - 2) * Step * (N / 2);

		for (j = 0; j < N / 2; ++j)
		{
			q[j] = (A[2 * j] & 0x0000FFFFL) >> 1;
			q[j + N / 2] = (A[2 * j + 1] & 0x0000FFFFL) >> 1;
		}

		CbRecursion(Output, Position, Step * 2, q, W - 1, N / 2, Temp);
		CbRecursion(Output, Position + Step, Step * 2, q + N / 2, W - 1, N / 2, Temp);
	}
	else
	{
		Output[Position >> 3] ^= Pi[0] << (Position & 7);
	}
}

void MPKCUtils::ControlBitsFromPermutation(uint8_t* Output, const int16_t* Pi, int64_t W, int64_t N)
{
	// parameters: 1 <= w <= 14; n = 2^w
	// input: permutation pi of {0,1,...,n-1}
	// output: (2m-1)n/2 control bits at positions 0,1,...
	// output position pos is by definition 1&(out[pos/8]>>(pos&7)) 

	int32_t* temp;
	int16_t* pi_test;
	int32_t i;
	int16_t diff;
	const uint8_t* ptr;

	temp = (int32_t*)MemoryTools::Malloc((size_t)N * 2 * sizeof(int32_t));
	pi_test = (int16_t*)MemoryTools::Malloc((size_t)N * sizeof(int16_t));

	if (temp != NULL && pi_test != NULL)
	{
		while (true)
		{
			MemoryTools::ClearRaw(Output, (size_t)(((2 * W - 1) * N / 2) + 7) / 8);
			MPKCUtils::CbRecursion(Output, 0, 1, Pi, W, N, temp);

			// check for correctness

			for (i = 0; i < N; ++i)
			{
				pi_test[i] = (int16_t)i;
			}

			ptr = Output;

			for (i = 0; i < W; ++i)
			{
				MPKCUtils::Layer(pi_test, ptr, i, (int32_t)N);
				ptr += N >> 4;
			}

			for (i = (int32_t)W - 2; i >= 0; --i)
			{
				MPKCUtils::Layer(pi_test, ptr, i, (int32_t)N);
				ptr += N >> 4;
			}

			diff = 0;

			for (i = 0; i < N; ++i)
			{
				diff |= Pi[i] ^ pi_test[i];
			}

			if (diff == 0)
			{
				break;
			}
		}

		MemoryTools::MallocFree(pi_test);
		MemoryTools::MallocFree(temp);
	}
}

uint16_t MPKCUtils::Eval(const uint16_t* F, uint16_t A, uint32_t SysT)
{
	// input: polynomial f and field element a
	// return: f(a)

	size_t i;
	uint16_t r;

	r = F[SysT];
	i = SysT;

	do
	{
		--i;
		r = MPKCUtils::GfMultiply(r, A);
		r = MPKCUtils::GfAdd(r, F[i]);
	} 
	while (i > 0);

	return r;
}

uint16_t MPKCUtils::GfAdd(uint16_t Input0, uint16_t Input1)
{
	return (Input0 ^ Input1);
}

uint16_t MPKCUtils::GfIsZero(uint16_t A)
{
	uint32_t t;

	t = A;
	t -= 1;
	t >>= 19;

	return (uint16_t)t;
}

uint16_t MPKCUtils::GfMultiply(uint16_t Input0, uint16_t Input1)
{
	uint64_t t;
	uint64_t t0;
	uint64_t t1;
	uint64_t tmp;
	size_t i;

	t0 = Input0;
	t1 = Input1;
	tmp = t0 * (t1 & 1);

	for (i = 1; i < MCELIECE_GFBITS; ++i)
	{
		tmp ^= (t0 * (t1 & (1ULL << i)));
	}

	t = tmp & 0x0000000001FF0000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	t = tmp & 0x000000000000E000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

	return (tmp & MCELIECE_GFMASK);
}

uint16_t MPKCUtils::GfSq2(uint16_t Input)
{

	// input: field element in
	// return: (in^2)^2 

	const uint64_t Bf[] = { 0x1111111111111111ULL, 0x0303030303030303ULL, 0x000F000F000F000FULL, 0x000000FF000000FFULL };
	const uint64_t MA[] = { 0x0001FF0000000000ULL, 0x000000FF80000000ULL, 0x000000007FC00000ULL, 0x00000000003FE000ULL };
	uint64_t t;
	uint64_t x;
	size_t i;

	x = Input;
	x = (x | (x << 24)) & Bf[3];
	x = (x | (x << 12)) & Bf[2];
	x = (x | (x << 6)) & Bf[1];
	x = (x | (x << 3)) & Bf[0];

	for (i = 0; i < 4; ++i)
	{
		t = x & MA[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (x & MCELIECE_GFMASK);
}

uint16_t MPKCUtils::GfSqMul(uint16_t Input, uint16_t M)
{
	// input: field element in, m
	// return: (in^2)*m 

	const uint64_t MA[] = { 0x0000001FF0000000ULL, 0x000000000FF80000ULL, 0x000000000007E000ULL };
	uint64_t t;
	uint64_t t0;
	uint64_t t1;
	uint64_t x;
	size_t i;

	t0 = Input;
	t1 = M;
	x = (t1 << 6) * (t0 & (1 << 6));
	t0 ^= (t0 << 7);

	x ^= (t1 * (t0 & 0x0000000000004001ULL));
	x ^= (t1 * (t0 & 0x0000000000008002ULL)) << 1;
	x ^= (t1 * (t0 & 0x0000000000010004ULL)) << 2;
	x ^= (t1 * (t0 & 0x0000000000020008ULL)) << 3;
	x ^= (t1 * (t0 & 0x0000000000040010ULL)) << 4;
	x ^= (t1 * (t0 & 0x0000000000080020ULL)) << 5;

	for (i = 0; i < 3; ++i)
	{
		t = x & MA[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (x & MCELIECE_GFMASK);
}

uint16_t MPKCUtils::GfSq2Mul(uint16_t Input, uint16_t M)
{
	// input: field element in, m
	// return: ((in^2)^2)*m
	const uint64_t MA[] = { 0x1FF0000000000000ULL, 0x000FF80000000000ULL, 0x000007FC00000000ULL,
		0x00000003FE000000ULL, 0x0000000001FE0000ULL, 0x000000000001E000ULL };
	uint64_t x;
	uint64_t t0;
	uint64_t t1;
	uint64_t t;
	size_t i;

	t0 = Input;
	t1 = M;
	x = (t1 << 18) * (t0 & (1 << 6));
	t0 ^= (t0 << 21);

	x ^= (t1 * (t0 & 0x0000000010000001ULL));
	x ^= (t1 * (t0 & 0x0000000020000002ULL)) << 3;
	x ^= (t1 * (t0 & 0x0000000040000004ULL)) << 6;
	x ^= (t1 * (t0 & 0x0000000080000008ULL)) << 9;
	x ^= (t1 * (t0 & 0x0000000100000010ULL)) << 12;
	x ^= (t1 * (t0 & 0x0000000200000020ULL)) << 15;

	for (i = 0; i < 6; ++i)
	{
		t = x & MA[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (x & MCELIECE_GFMASK);
}

uint16_t MPKCUtils::GfFrac(uint16_t Den, uint16_t Num)
{
	// input: field element den, num 
	// return: (num/den) 

	uint16_t tmp_11;
	uint16_t tmp_1111;
	uint16_t out;

	tmp_11 = GfSqMul(Den, Den);				// ^ 11 
	tmp_1111 = GfSq2Mul(tmp_11, tmp_11);	// ^ 1111 
	out = GfSq2(tmp_1111);
	out = GfSq2Mul(out, tmp_1111);			// ^ 11111111 
	out = GfSq2(out);
	out = GfSq2Mul(out, tmp_1111);			// ^ 111111111111 

	return GfSqMul(out, Num);				// ^ 1111111111110 = ^ -1 
}

uint16_t MPKCUtils::GfInv(uint16_t Den)
{
	return GfFrac(Den, ((uint16_t)1));
}

void MPKCUtils::Layer(int16_t* P, const uint8_t* Cb, int32_t S, int32_t N)
{
	// input: p, an array of int16_t
	// input: n, length of p
	// input: s, meaning that stride-2^s cswaps are performed
	// input: cb, the control bits
	// output: the result of apply the control bits to p 

	size_t i;
	size_t j;
	const int32_t stride = 1 << S;
	int32_t index;
	int16_t d;
	int16_t m;

	index = 0;

	for (i = 0; i < (size_t)N; i += stride * 2)
	{
		for (j = 0; j < (size_t)stride; ++j)
		{
			d = P[i + j] ^ P[i + j + stride];
			m = (Cb[index >> 3] >> (index & 7)) & 1;
			m = -m;
			d &= m;
			P[i + j] ^= d;
			P[i + j + stride] ^= d;
			++index;
		}
	}
}

void MPKCUtils::LayerIn(uint64_t Data[2][64], const uint64_t* Bits, uint32_t Lgs)
{
	// middle layers of the benes network

	uint64_t d;
	size_t i;
	size_t j;
	size_t k;
	size_t s;

	k = 0;
	s = static_cast<size_t>(1ULL << Lgs);

	for (i = 0; i < 64; i += s * 2)
	{
		for (j = i; j < i + s; j++)
		{
			d = (Data[0][j] ^ Data[0][j + s]);
			d &= Bits[k];
			++k;
			Data[0][j] ^= d;
			Data[0][j + s] ^= d;

			d = (Data[1][j] ^ Data[1][j + s]);
			d &= Bits[k];
			++k;
			Data[1][j] ^= d;
			Data[1][j + s] ^= d;
		}
	}
}

void MPKCUtils::LayerEx(uint64_t* Data, const uint64_t* Bits, uint32_t Lgs)
{
	// first and last layers of the benes network

	uint64_t d;
	size_t i;
	size_t j;
	size_t k;
	uint32_t s;

	k = 0;
	s = 1UL << Lgs;

	for (i = 0; i < 128; i += s * 2)
	{
		for (j = i; j < i + s; j++)
		{
			d = (Data[j] ^ Data[j + s]);
			d &= Bits[k];
			++k;
			Data[j] ^= d;
			Data[j + s] ^= d;
		}
	}
}

uint16_t MPKCUtils::LoadGf(const uint8_t* Source)
{
	uint16_t a;

	a = IntegerTools::LeBytesTo16Raw(Source);

	return (a & MCELIECE_GFMASK);
}

void MPKCUtils::MinMax32(int32_t* A, int32_t* B)
{
	int32_t ab;
	int32_t c;

	ab = *B ^ *A;
	c = *B - *A;
	c ^= ab & (c ^ *B);
	c >>= 31;
	c &= ab;
	*A ^= c;
	*B ^= c;
}

void MPKCUtils::MinMax64(uint64_t* A, uint64_t* B)
{
	uint64_t c;

	c = *B - *A;
	c >>= 63;
	c = ~c + 1;
	c &= *A ^ *B;
	*A ^= c;
	*B ^= c;
}

void MPKCUtils::Root(uint16_t* Output, const uint16_t* F, const uint16_t* L, uint32_t N, uint32_t SysT)
{
	// input: polynomial f and list of field elements L
	// output: out = [ f(a) for a in L ]

	for (size_t i = 0; i < N; ++i)
	{
		Output[i] = Eval(F, L[i], SysT);
	}
}

uint8_t MPKCUtils::SameMask(uint16_t X, uint16_t Y)
{
	uint32_t mask;

	mask = (uint32_t)(X ^ Y);
	mask -= 1;
	mask >>= 31;
	mask = ~mask + 1;

	return (mask & 0x000000FFUL);
}

void MPKCUtils::Sort32(int32_t* X, int64_t N)
{
	int64_t i;
	int64_t p;
	int64_t r;
	int64_t q;
	int64_t top;
	int32_t a;

	if (N >= 2)
	{
		top = 1;

		while (top < N - top)
		{
			top += top;
		}

		for (p = top; p > 0; p >>= 1)
		{
			for (i = 0; i < N - p; ++i)
			{
				if ((i & p) == 0)
				{
					MinMax32(&X[i], &X[i + p]);
				}
			}

			i = 0;

			for (q = top; q > p; q >>= 1)
			{
				for (; i < N - q; ++i)
				{
					if ((i & p) == 0)
					{
						a = X[i + p];

						for (r = q; r > p; r >>= 1)
						{
							MinMax32(&a, &X[i + r]);
						}

						X[i + p] = a;
					}
				}
			}
		}
	}
}

void MPKCUtils::Sort64(uint64_t* X, int64_t N)
{
	uint64_t a;
	int64_t i;
	int64_t p;
	int64_t q;
	int64_t r;
	int64_t top;

	if (N >= 2)
	{
		top = 1;

		while (top < N - top)
		{
			top += top;
		}

		for (p = top; p > 0; p >>= 1)
		{
			for (i = 0; i < N - p; ++i)
			{
				if ((i & p) == 0)
				{
					MinMax64(&X[i], &X[i + p]);
				}
			}

			i = 0;

			for (q = top; q > p; q >>= 1)
			{
				for (; i < N - q; ++i)
				{
					if ((i & p) == 0)
					{
						a = X[i + p];

						for (r = q; r > p; r >>= 1)
						{
							MinMax64(&a, &X[i + r]);
						}

						X[i + p] = a;
					}
				}
			}
		}
	}
}

void MPKCUtils::Synd(uint16_t* Output, const uint16_t* F, const uint16_t* L, const uint8_t* R, uint32_t N, uint32_t SysT)
{
	// input: Goppa polynomial f, support L, received word r
	// output: out, the Syndrome of length 2t

	size_t i;
	size_t j;
	uint16_t c;
	uint16_t e;
	uint16_t einv;

	MemoryTools::ClearRaw((uint8_t*)Output, 2 * SysT * sizeof(uint16_t));

	for (i = 0; i < N; ++i)
	{
		c = (R[i / 8] >> (i % 8)) & 1;
		e = Eval(F, L[i], SysT);
		einv = MPKCUtils::GfInv(MPKCUtils::GfMultiply(e, e));

		for (j = 0; j < 2 * SysT; ++j)
		{
			Output[j] = MPKCUtils::GfAdd(Output[j], MPKCUtils::GfMultiply(einv, c));
			einv = MPKCUtils::GfMultiply(einv, L[i]);
		}
	}
}

void MPKCUtils::Transpose64x64(uint64_t* Output, const uint64_t* Input)
{
	// input: in, a 64x64 matrix over GF(2)
	// output: out, transpose of in

	uint64_t x;
	uint64_t y;
	size_t i;
	size_t j;
	size_t d;
	size_t s;

	const uint64_t masks[6][2] =
	{
		{0x5555555555555555ULL, 0xAAAAAAAAAAAAAAAAULL},
		{0x3333333333333333ULL, 0xCCCCCCCCCCCCCCCCULL},
		{0x0F0F0F0F0F0F0F0FULL, 0xF0F0F0F0F0F0F0F0ULL},
		{0x00FF00FF00FF00FFULL, 0xFF00FF00FF00FF00ULL},
		{0x0000FFFF0000FFFFULL, 0xFFFF0000FFFF0000ULL},
		{0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL}
	};

	for (i = 0; i < 64; i++)
	{
		Output[i] = Input[i];
	}

	d = 6;

	do
	{
		--d;
		s = 1ULL << d;

		for (i = 0; i < 64; i += s * 2)
		{
			for (j = i; j < i + s; j++)
			{
				x = (Output[j] & masks[d][0]) | ((Output[j + s] & masks[d][0]) << s);
				y = ((Output[j] & masks[d][1]) >> s) | (Output[j + s] & masks[d][1]);
				Output[j] = x;
				Output[j + s] = y;
			}
		}
	} 
	while (d != 0);
}

NAMESPACE_MCELIECEEND
