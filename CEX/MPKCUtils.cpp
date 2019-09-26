#include "MPKCUtils.h"

NAMESPACE_MCELIECE

//~~~N6090T13 and N8192T13~~~//

// benes.c //

void MPKCUtils::LayerIn(ulong Data[2][64], const ulong* Bits, uint Lgs)
{
	// middle layers of the benes network

	ulong d;
	size_t i;
	size_t j;
	size_t k;
	uint s;

	k = 0;
	s = 1UL << Lgs;

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

void MPKCUtils::LayerEx(ulong* Data, const ulong* Bits, uint Lgs)
{
	// first and last layers of the benes network

	ulong d;
	size_t i;
	size_t j;
	size_t k;
	uint s;

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

void MPKCUtils::ApplyBenes(byte* R, const byte* Bits, bool Reverse)
{
	// input: r, sequence of bits to be permuted
	// bits, condition bits of the Benes network
	// rev, 0 for normal application; !0 for inverse
	// output: r, permuted bits

	ulong riv[2][64];
	ulong rih[2][64];
	ulong biv[64];
	ulong bih[64];
	size_t i;
	int32_t inc;
	uint iter;
	const byte* bptr;
	byte* rptr;

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
		riv[0][i] = Load64(rptr + i * 16);
		riv[1][i] = Load64(rptr + i * 16 + 8);
	}

	Transpose64x64(rih[0], riv[0]);
	Transpose64x64(rih[1], riv[1]);

	for (iter = 0; iter <= 6; iter++)
	{
		for (i = 0; i < 64; ++i)
		{
			biv[i] = Load64(bptr);
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
			biv[i] = Load64(bptr);
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
			biv[i] = Load64(bptr);
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
			biv[i] = Load64(bptr);
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
		Store64(rptr + i * 16 + 0, riv[0][i]);
		Store64(rptr + i * 16 + 8, riv[1][i]);
	}
}

// controlbits.c //

void MPKCUtils::Compose(uint W, uint N, const uint* Pi, uint* P)
{
	uint* I = new uint[2 * N];
	uint* Ip = new uint[N];
	size_t i;
	uint c;
	uint t;

	if (I != nullptr && Ip != nullptr)
	{
		Invert(N, Ip, Pi);

		for (i = 0; i < N; ++i)
		{
			I[i] = Ip[i] | (1UL << W);
			I[N + i] = Pi[i];
		}

		// end Ip
		for (c = 0; c < 2 * N; ++c)
		{
			P[c] = (c >> W) + (c & ((1UL << W) - 2)) + ((c & 1UL) << W);
		}

		uint* PI = new uint[2 * N];
		uint* T = new uint[2 * N];

		if (PI != nullptr && T != nullptr)
		{
			for (t = 0; t < W; ++t)
			{
				ComposeInv(2 * N, PI, P, I);

				for (i = 0; i < 2 * N; ++i)
				{
					Flow(W, P[i], PI[i], t);
				}

				for (i = 0; i < 2 * N; ++i)
				{
					T[i] = I[i ^ 1];
				}

				ComposeInv(2 * N, I, I, T);

				for (i = 0; i < 2 * N; ++i)
				{
					T[i] = P[i ^ 1];
				}

				for (i = 0; i < 2 * N; ++i)
				{
					Flow(W, P[i], T[i], 1);
				}
			}
		}

		if (PI != nullptr)
		{
			delete[] PI;
		}
		if (T != nullptr)
		{
			delete[] T;
		}
	}

	if (I != nullptr)
	{
		delete[] I;
	}
	if (Ip != nullptr)
	{
		delete[] Ip;
	}
}

void MPKCUtils::ComposeInv(uint N, uint* Y, const uint* X, const uint* Pi)
{
	// y[pi[i]] = x[i]
	// requires n = 2^w
	// requires pi to be a permutation

	uint* t = new uint[N];
	size_t i;

	if (t != NULL)
	{
		for (i = 0; i < N; ++i)
		{
			t[i] = X[i] | (Pi[i] << 16);
		}

		Sort(N, t);

		for (i = 0; i < N; ++i)
		{
			Y[i] = t[i] & 0x0000FFFFUL;
		}

		delete[] t;
	}
}

void MPKCUtils::CSwap(uint &X, uint &Y, byte Swap)
{
	uint m;
	uint d;

	m = static_cast<uint>(Swap);
	m = 0 - m;
	d = (X ^ Y);
	d &= m;
	X ^= d;
	Y ^= d;
}

void MPKCUtils::CSwap63b(ulong &X, ulong &Y, byte Swap)
{
	ulong m;
	ulong d;

	m = static_cast<uint>(Swap);
	m = 0 - m;
	d = (X ^ Y);
	d &= m;
	X ^= d;
	Y ^= d;
}

void MPKCUtils::Flow(uint W, uint &X, const uint &Y, const uint T)
{
	uint b;
	uint ycopy;
	byte m0;
	byte m1;

	ycopy = Y;
	m0 = IsSmaller(Y & ((1UL << W) - 1), X & ((1UL << W) - 1));
	m1 = IsSmaller(0UL, T);

	CSwap(X, ycopy, m0);
	b = m0 & m1;
	X ^= (b << W);
}

void MPKCUtils::Invert(uint N, uint* Ip, const uint* Pi)
{
	// ip[i] = j iff pi[i] = j
	// requires n = 2^w
	// requires pi to be a permutation

	uint i;

	for (i = 0; i < N; ++i)
	{
		Ip[i] = i;
	}

	ComposeInv(N, Ip, Ip, Pi);
}

byte MPKCUtils::IsSmaller(uint A, uint B)
{
	uint ret;

	ret = A - B;
	ret >>= 31;

	return static_cast<byte>(ret);
}

byte MPKCUtils::IsSmaller63b(ulong A, ulong B)
{
	ulong ret;

	ret = A - B;
	ret >>= 63;

	return static_cast<byte>(ret);
}

void MPKCUtils::Merge(uint N, uint* X, uint Step)
{
	// Merge first half of x[0],x[step],...,x[(2*n-1)*step] with second half
	// requires n to be a power of 2

	size_t i;

	if (N == 1)
	{
		MinMax(X[0], X[Step]);
	}
	else
	{
		Merge(N / 2, X, Step * 2);
		Merge(N / 2, X + Step, Step * 2);

		for (i = 1; i < (2 * N) - 1; i += 2)
		{
			MinMax(X[i * Step], X[(i + 1) * Step]);
		}
	}
}

void MPKCUtils::Merge63b(uint N, ulong* X, uint Step)
{
	size_t i;

	if (N == 1)
	{
		MinMax63b(X[0], X[Step]);
	}
	else
	{
		Merge63b(N / 2, X, Step * 2);
		Merge63b(N / 2, X + Step, Step * 2);

		for (i = 1; i < 2 * N - 1; i += 2)
		{
			MinMax63b(X[i * Step], X[(i + 1) * Step]);
		}
	}
}

void MPKCUtils::MinMax(uint &X, uint &Y)
{
	byte m;

	m = IsSmaller(Y, X);
	CSwap(X, Y, m);
}

void MPKCUtils::MinMax63b(ulong &X, ulong &Y)
{
	byte m;

	m = IsSmaller63b(Y, X);
	CSwap63b(X, Y, m);
}

void MPKCUtils::Permute(uint W, uint N, uint Offset, uint Step, const uint* P, const uint* Pi, byte* C, uint* PiFlip)
{
	size_t i;
	size_t j;

	for (i = 0; i < N; ++i)
	{
		for (j = 0; j < W; ++j)
		{
			PiFlip[i] = Pi[i];
		}
	}

	for (i = 0; i < N / 2; ++i)
	{
		C[(Offset + i * Step) / 8] |= ((P[i * 2] >> W) & 1) << ((Offset + i * Step) % 8);
	}

	for (i = 0; i < N / 2; ++i)
	{
		C[(Offset + ((W - 1)*N + i) * Step) / 8] |= ((P[N + i * 2] >> W) & 1) << ((Offset + ((W - 1) * N + i) * Step) % 8);
	}

	for (i = 0; i < N / 2; ++i)
	{
		CSwap(PiFlip[i * 2], PiFlip[i * 2 + 1], (P[N + i * 2] >> W) & 1);
	}
}

void MPKCUtils::PermuteBits(uint W, uint N, uint Step, uint Offset, byte* C, const uint* Pi)
{
	// input: permutation pi
	// output: (2w-1)n/2 (or 0 if n==1) control bits c[0],c[step],c[2*step],...
	// requires n = 2^w

	size_t i;

	if (W == 1)
	{
		C[Offset / 8] |= (Pi[0] & 1) << (Offset % 8);
	}

	if (W > 1)
	{
		uint* piflip = new uint[N];

		if (piflip != nullptr)
		{
			uint* P = new uint[2 * N];

			if (P != nullptr)
			{
				Compose(W, N, Pi, P);
				Permute(W, N, Offset, Step, P, Pi, C, piflip);
				delete[] P;
			}

			uint* subpi = new uint[N];

			if (subpi != NULL)
			{
				for (i = 0; i < N / 2; ++i)
				{
					subpi[i] = piflip[i * 2] >> 1;
				}

				for (i = 0; i < N / 2; ++i)
				{
					subpi[i + N / 2] = piflip[(i * 2) + 1] >> 1;
				}

				delete[] piflip;

				PermuteBits(W - 1, N / 2, Step * 2, Offset + Step * (N / 2), C, subpi);
				PermuteBits(W - 1, N / 2, Step * 2, Offset + Step * ((N / 2) + 1), C, &subpi[N / 2]);

				delete[] subpi;
			}
		}
	}
}

void MPKCUtils::Sort(uint N, uint* X)
{
	// Sort x[0],x[1],...,x[n-1] in place
	// requires n to be a power of 2

	if (N > 1)
	{
		Sort(N / 2, X);
		Sort(N / 2, X + (N / 2));
		Merge(N / 2, X, 1UL);
	}
}

void MPKCUtils::Sort63b(uint N, ulong* X)
{
	if (N > 1)
	{
		Sort63b(N / 2, X);
		Sort63b(N / 2, X + (N / 2));
		Merge63b(N / 2, X, 1UL);
	}
}

// transpose.c //

void MPKCUtils::Transpose64x64(ulong* Output, const ulong* Input)
{
	// input: in, a 64x64 matrix over GF(2)
	// output: out, transpose of in

	ulong x;
	ulong y;
	size_t i;
	size_t j;
	size_t d;
	size_t s;

	const ulong masks[6][2] =
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
	} while (d != 0);
}

// util.c //

ushort MPKCUtils::BitReverse(ushort A)
{
	A = ((A & 0x00FFU) << 8) | ((A & 0xFF00U) >> 8);
	A = ((A & 0x0F0FU) << 4) | ((A & 0xF0F0U) >> 4);
	A = ((A & 0x3333U) << 2) | ((A & 0xCCCCU) >> 2);
	A = ((A & 0x5555U) << 1) | ((A & 0xAAAAU) >> 1);

	return A >> 3;
}

void MPKCUtils::Clear8(byte* A, size_t Count)
{
	size_t i;

	for (i = 0; i < Count; ++i)
	{
		A[i] = 0;
	}
}

void MPKCUtils::Clear32(uint* A, size_t Count)
{
	size_t i;

	for (i = 0; i < Count; ++i)
	{
		A[i] = 0;
	}
}

void MPKCUtils::Clear64(ulong* A, size_t Count)
{
	size_t i;

	for (i = 0; i < Count; ++i)
	{
		A[i] = 0;
	}
}

uint MPKCUtils::Le8To32(const byte* Input)
{
	return ((ulong)Input[0]) |
		((ulong)Input[1] << 8) |
		((ulong)Input[2] << 16) |
		((ulong)Input[3] << 24);
}

ulong MPKCUtils::Le8To64(const byte* Input)
{
	return ((ulong)Input[0]) |
		((ulong)Input[1] << 8) |
		((ulong)Input[2] << 16) |
		((ulong)Input[3] << 24) |
		((ulong)Input[4] << 32) |
		((ulong)Input[5] << 40) |
		((ulong)Input[6] << 48) |
		((ulong)Input[7] << 56);
}

void MPKCUtils::Le32To8(byte* Output, uint Value)
{
	Output[0] = Value & 0xFF;
	Output[1] = (Value >> 8) & 0xFF;
	Output[2] = (Value >> 16) & 0xFF;
	Output[3] = (Value >> 24) & 0xFF;
}

void MPKCUtils::Le64To8(byte* Output, ulong Value)
{
	Output[0] = Value & 0xFF;
	Output[1] = (Value >> 8) & 0xFF;
	Output[2] = (Value >> 16) & 0xFF;
	Output[3] = (Value >> 24) & 0xFF;
	Output[4] = (Value >> 32) & 0xFF;
	Output[5] = (Value >> 40) & 0xFF;
	Output[6] = (Value >> 48) & 0xFF;
	Output[7] = (Value >> 56) & 0xFF;
}

ushort MPKCUtils::Load16(const byte* Input)
{
	ushort a;

	a = Input[1];
	a <<= 8;
	a |= Input[0];

	return a;
}

ulong MPKCUtils::Load64(const byte* Input)
{
	int32_t i;
	ulong ret;

	ret = Input[7];

	for (i = 6; i >= 0; i--)
	{
		ret <<= 8;
		ret |= Input[i];
	}

	return ret;
}

uint MPKCUtils::Rotl32(uint Value, uint Shift)
{
	return (Value << Shift) | (Value >> ((sizeof(uint) * 8) - Shift));
}

ulong MPKCUtils::Rotl64(ulong Value, uint Shift)
{
	return (Value << Shift) | (Value >> ((sizeof(ulong) * 8) - Shift));
}

uint MPKCUtils::Rotr32(uint Value, uint Shift)
{
	return (Value >> Shift) | (Value << ((sizeof(uint) * 8) - Shift));
}

ulong MPKCUtils::Rotr64(ulong Value, uint Shift)
{
	return (Value >> Shift) | (Value << ((sizeof(ulong) * 8) - Shift));
}

void MPKCUtils::Store16(byte* Output, ushort A)
{
	Output[0] = A & 0xFF;
	Output[1] = A >> 8;
}

void MPKCUtils::Store64(byte* Output, ulong Input)
{
	Output[0] = Input & 0xFF;
	Output[1] = (Input >> 0x08) & 0xFF;
	Output[2] = (Input >> 0x10) & 0xFF;
	Output[3] = (Input >> 0x18) & 0xFF;
	Output[4] = (Input >> 0x20) & 0xFF;
	Output[5] = (Input >> 0x28) & 0xFF;
	Output[6] = (Input >> 0x30) & 0xFF;
	Output[7] = (Input >> 0x38) & 0xFF;
}

int32_t MPKCUtils::Verify(const byte* A, const byte* B, size_t Length)
{
	size_t i;
	ushort d;

	d = 0;

	for (i = 0; i < Length; i++)
	{
		d |= A[i] ^ B[i];
	}

	return (int32_t)(1 & ((d - 1) >> 8)) - 1;
}

//~~~N4096T12~~~//

ushort MPKCUtils::Diff(ushort X, ushort Y)
{
	uint t;
	
	t = static_cast<uint>(X ^ Y);
	t = ((t - 1) >> 20) ^ 0xFFFUL;

	return static_cast<ushort>(t);
}

ushort MPKCUtils::Invert(ushort X, size_t Degree)
{
	ushort out;
	ushort tmpa;
	ushort tmpb;

	out = X;
	out = Square(out, Degree);
	tmpa = Multiply(out, X, Degree);
	out = Square(tmpa, Degree);
	out = Square(out, Degree);
	tmpb = Multiply(out, tmpa, Degree);
	out = Square(tmpb, Degree);
	out = Square(out, Degree);
	out = Square(out, Degree);
	out = Square(out, Degree);
	out = Multiply(out, tmpb, Degree);
	out = Square(out, Degree);
	out = Square(out, Degree);
	out = Multiply(out, tmpa, Degree);
	out = Square(out, Degree);
	out = Multiply(out, X, Degree);

	return Square(out, Degree);
}

ulong MPKCUtils::MaskNonZero64(ushort X)
{
	ulong ret;

	ret = X;
	ret -= 1;
	ret >>= 63;
	ret -= 1;

	return ret;
}

ulong MPKCUtils::MaskLeq64(ushort X, ushort Y)
{
	ulong ret;
	ulong tmpa;
	ulong tmpb;

	tmpa = X;
	tmpb = Y;
	ret = tmpb - tmpa;
	ret >>= 63;
	ret -= 1;

	return ret;
}

ushort MPKCUtils::Multiply(ushort X, ushort Y, size_t Degree)
{
	size_t i;
	uint t;
	uint t0;
	uint t1;
	uint tmp;

	t0 = X;
	t1 = Y;
	tmp = t0 * (t1 & 1);

	for (i = 1; i < Degree; ++i)
	{
		tmp ^= (t0 * (t1 & (1UL << i)));
	}

	t = tmp & 0x7FC000UL;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	t = tmp & 0x3000UL;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	return static_cast<ushort>(tmp & ((1UL << Degree) - 1));
}

ushort MPKCUtils::Square(ushort X, size_t Degree)
{
	static const std::array<uint, 4> B =
	{
		0x55555555UL, 
		0x33333333UL, 
		0x0F0F0F0FUL, 
		0x00FF00FFUL
	};

	uint t;
	uint y;

	y = X;
	y = (y | (y << 8)) & B[3];
	y = (y | (y << 4)) & B[2];
	y = (y | (y << 2)) & B[1];
	y = (y | (y << 1)) & B[0];

	t = y & 0x7FC000UL;
	y ^= t >> 9;
	y ^= t >> 12;

	t = y & 0x3000UL;
	y ^= t >> 9;
	y ^= t >> 12;

	return static_cast<ushort>(y & ((1 << Degree) - 1));
}

NAMESPACE_MCELIECEEND
