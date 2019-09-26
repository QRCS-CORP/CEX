#include "RNBWGfMath.h"
#include "IntegerTools.h"

NAMESPACE_RAINBOW

using Utility::IntegerTools;

byte RNBWGfMath::Gf256vGetEle(const std::vector<byte> &A, size_t Offset, uint Index)
{
	// get an element from GF(256) vector

	return A[Offset + Index];
}

byte RNBWGfMath::Gf256vSetEle(std::vector<byte> &A, size_t Offset, uint Index, byte V)
{
	// set an element for A GF(256) vector

	A[Offset + Index] = V;

	return V;
}

#ifdef CEX_ARCH_64

void RNBWGfMath::Gf256vAddU32(std::vector<byte> &AccuB, size_t BOffset, const std::vector<byte> &A, size_t AOffset, size_t Length)
{
	uint au32;
	uint bu32;
	size_t i;
	size_t nu32;
	size_t rem;

	au32 = 0;
	bu32 = 0;
	nu32 = Length >> 2;

	for (i = 0; i < nu32; ++i)
	{
		au32 = IntegerTools::LeBytesTo32(A, AOffset + (i * sizeof(uint)));
		bu32 = IntegerTools::LeBytesTo32(AccuB, BOffset + i * sizeof(uint));
		bu32 ^= au32;
		IntegerTools::Le32ToBytes(bu32, AccuB, BOffset + i * sizeof(uint));
	}

	AOffset += (nu32 << 2);
	BOffset += (nu32 << 2);
	rem = Length & 3;

	for (i = 0; i < rem; ++i)
	{
		AccuB[BOffset + i] ^= A[AOffset + i];
	}
}

void RNBWGfMath::Gf256vMaddU32(std::vector<byte> &AccuC, size_t COffset, const std::vector<byte> &A, size_t AOffset, byte Gf256B, size_t Length)
{
	uint au32;
	uint cu32;
	uint rem;
	uint tmp32;
	size_t i;
	size_t nu32;

	tmp32 = 0;
	nu32 = Length >> 2;

	for (i = 0; i < nu32; ++i)
	{
		au32 = IntegerTools::LeBytesTo32(A, AOffset + (i * sizeof(uint)));
		cu32 = IntegerTools::LeBytesTo32(AccuC, COffset + i * sizeof(uint));
		cu32 ^= Gf256vMulU32(au32, Gf256B);
		IntegerTools::Le32ToBytes(cu32, AccuC, COffset + (i * sizeof(uint)));
	}

	AOffset += (nu32 << 2);
	COffset += (nu32 << 2);
	rem = Length & 3;

	for (i = 0; i < rem; ++i)
	{
		tmp32 |= ((uint)A[AOffset + i] << (i * 8));
	}

	tmp32 = Gf256vMulU32(tmp32, Gf256B);

	for (i = 0; i < rem; ++i)
	{
		AccuC[COffset + i] ^= (tmp32 >> (i * 8)) & 0xFF;
	}
}

void RNBWGfMath::Gf256vMulScalarU32(std::vector<byte> &A, size_t Offset, byte B, size_t Length)
{
	uint au32;
	uint rem;
	uint tmp32;
	size_t i;
	size_t nu32;

	tmp32 = 0;
	nu32 = Length >> 2;

	for (i = 0; i < nu32; ++i)
	{
		au32 = IntegerTools::LeBytesTo32(A, Offset + (i * sizeof(uint)));
		au32 = Gf256vMulU32(au32, B);
		IntegerTools::Le32ToBytes(au32, A, Offset + (i * sizeof(uint)));
	}

	Offset += (nu32 << 2);
	rem = Length & 3;

	for (i = 0; i < rem; ++i)
	{
		tmp32 |= ((uint)A[Offset + i] << (i * 8));
	}

	tmp32 = Gf256vMulU32(tmp32, B);

	for (i = 0; i < rem; ++i)
	{
		A[Offset + i] = (tmp32 >> (i * 8)) & 0xFF;
	}
}

void RNBWGfMath::Gf256vPredicatedAddU32(std::vector<byte> &AccuB, size_t BOffset, byte Predicate, const std::vector<byte> &A, size_t AOffset, size_t Length)
{
	byte pru8;
	uint au32;
	uint bu32;
	uint pru32;
	uint rem;
	size_t i;
	size_t nu32;

	pru32 = 0UL - ((uint)Predicate);
	pru8 = pru32 & 0xff;
	nu32 = Length >> 2;

	for (i = 0; i < nu32; ++i)
	{
		au32 = IntegerTools::LeBytesTo32(A, AOffset + (i * sizeof(uint)));
		bu32 = IntegerTools::LeBytesTo32(AccuB, BOffset + (i * sizeof(uint)));
		bu32 ^= (au32 & pru32);
		IntegerTools::Le32ToBytes(bu32, AccuB, BOffset + (i * sizeof(uint)));
	}

	AOffset += (nu32 << 2);
	BOffset += (nu32 << 2);
	rem = Length & 3;

	for (i = 0; i < rem; ++i)
	{
		AccuB[BOffset + i] ^= (A[AOffset + i] & pru8);
	}
}

void RNBWGfMath::Gf256vAdd(std::vector<byte> &AccuB, size_t BOffset, const std::vector<byte> &A, size_t AOffset, size_t Length)
{
	ulong au64;
	ulong bu64;
	size_t i;
	size_t nu64;
	size_t rem;

	au64 = 0;
	bu64 = 0;
	nu64 = Length >> 3;

	for (i = 0; i < nu64; ++i)
	{
		au64 = IntegerTools::LeBytesTo64(A, AOffset + (i * sizeof(ulong)));
		bu64 = IntegerTools::LeBytesTo64(AccuB, BOffset + (i * sizeof(ulong)));
		bu64 ^= au64;
		IntegerTools::Le64ToBytes(bu64, AccuB, BOffset + (i * sizeof(ulong)));
	}

	AOffset += (nu64 << 3);
	BOffset += (nu64 << 3);
	rem = Length & 7;

	if (rem)
	{
		Gf256vAddU32(AccuB, BOffset, A, AOffset, rem);
	}
}

void RNBWGfMath::Gf256vMadd(std::vector<byte> &AccuC, size_t COffset, const std::vector<byte> &A, size_t AOffset, byte B, size_t Length)
{
	ulong au64;
	ulong cu64;
	size_t i;
	size_t num;
	size_t numb;

	au64 = 0;
	cu64 = 0;
	num = Length >> 3;

	for (i = 0; i < num; ++i)
	{
		au64 = IntegerTools::LeBytesTo64(A, AOffset + (i * sizeof(ulong)));
		cu64 = IntegerTools::LeBytesTo64(AccuC, COffset + (i * sizeof(ulong)));
		cu64 ^= Gf256vMulU64(au64, B);
		IntegerTools::Le64ToBytes(cu64, AccuC, COffset + i * sizeof(ulong));
	}

	numb = Length & 0x7;
	AOffset += num << 3;
	COffset += num << 3;

	if (numb)
	{
		Gf256vMaddU32(AccuC, COffset, A, AOffset, B, numb);
	}
}

void RNBWGfMath::Gf256vMulScalar(std::vector<byte> &A, size_t Offset, byte B, size_t Length)
{
	ulong au64;
	size_t i;
	size_t num;
	size_t numb;

	au64 = 0;
	num = Length >> 3;

	for (i = 0; i < num; ++i)
	{
		au64 = IntegerTools::LeBytesTo64(A, Offset + (i * sizeof(ulong)));
		au64 = Gf256vMulU64(au64, B);
		IntegerTools::Le64ToBytes(au64, A, Offset + (i * sizeof(ulong)));
	}

	numb = Length & 0x7;
	Offset += num << 3;

	if (numb)
	{
		Gf256vMulScalarU32(A, Offset, B, numb);
	}
}

void RNBWGfMath::Gf256vPredicatedAdd(std::vector<byte> &AccuB, size_t BOffset, byte Predicate, const std::vector<byte> &A, size_t AOffset, size_t Length)
{
	ulong au64;
	ulong bu64;
	ulong pr64;
	size_t i;
	size_t nu64;
	size_t rem;

	au64 = 0;
	bu64 = 0;
	nu64 = Length >> 3;
	pr64 = (0ULL - static_cast<ulong>(Predicate));

	for (i = 0; i < nu64; ++i)
	{
		au64 = IntegerTools::LeBytesTo64(A, AOffset + (i * sizeof(ulong)));
		bu64 = IntegerTools::LeBytesTo64(AccuB, BOffset + (i * sizeof(ulong)));
		bu64 ^= (au64 & pr64);
		IntegerTools::Le64ToBytes(bu64, AccuB, BOffset + (i * sizeof(ulong)));
	}

	AOffset += (nu64 << 3);
	BOffset += (nu64 << 3);
	rem = Length & 7;

	if (rem)
	{
		Gf256vPredicatedAddU32(AccuB, BOffset, Predicate, A, AOffset, rem);
	}
}

#else

void RNBWGfMath::Gf256vAdd(std::vector<byte> &AccuB, size_t BOffset, const std::vector<byte> &A, size_t AOffset, size_t Length)
{
	uint au32;
	uint bu32;
	size_t i;
	size_t nu32;
	size_t rem;

	au32 = 0;
	bu32 = 0;
	nu32 = Length >> 2;

	for (i = 0; i < nu32; ++i)
	{
		au32 = IntegerTools::LeBytesTo32(A, AOffset + (i * sizeof(uint)));
		bu32 = IntegerTools::LeBytesTo32(AccuB, BOffset + (i * sizeof(uint)));
		bu32 ^= au32;
		IntegerTools::Le32ToBytes(bu32, AccuB, BOffset + (i * sizeof(uint)));
	}

	AOffset += (nu32 << 2);
	BOffset += (nu32 << 2);
	rem = Length & 3;

	for (i = 0; i < rem; ++i)
	{
		AccuB[BOffset + i] ^= A[AOffset + i];
	}
}

void RNBWGfMath::Gf256vMadd(std::vector<byte> &AccuC, size_t COffset, const std::vector<byte> &A, size_t AOffset, byte Gf256B, size_t Length)
{
	uint au32;
	uint cu32;
	uint rem;
	uint tmp32;
	size_t i;
	size_t nu32;

	tmp32 = 0;
	nu32 = Length >> 2;

	for (i = 0; i < nu32; ++i)
	{
		au32 = IntegerTools::LeBytesTo32(A, AOffset + (i * sizeof(uint)));
		cu32 = IntegerTools::LeBytesTo32(AccuC, COffset + (i * sizeof(uint)));
		cu32 ^= Gf256vMulU32(au32, Gf256B);
		IntegerTools::Le32ToBytes(cu32, AccuC, COffset + (i * sizeof(uint)));
	}

	COffset += (nu32 << 2);
	AOffset += (nu32 << 2);
	rem = Length & 3;

	for (i = 0; i < rem; ++i)
	{
		tmp32 |= ((uint)A[AOffset + i] << (i * 8));
	}

	tmp32 = Gf256vMulU32(tmp32, Gf256B);

	for (i = 0; i < rem; ++i)
	{
		AccuC[COffset + i] ^= (tmp32 >> (i * 8)) & 0xFF;
	}
}

void RNBWGfMath::Gf256vMulScalar(std::vector<byte> &A, size_t Offset, byte B, size_t Length)
{
	uint au32;
	uint rem;
	uint tmp32;
	size_t i;
	size_t nu32;

	tmp32 = 0;
	nu32 = Length >> 2;

	for (i = 0; i < nu32; ++i)
	{
		au32 = IntegerTools::LeBytesTo32(A, Offset + (i * sizeof(uint)));
		au32 = Gf256vMulU32(au32, B);
		IntegerTools::Le32ToBytes(au32, A, Offset + (i * sizeof(uint)));
	}

	Offset += (nu32 << 2);
	rem = Length & 3;

	for (i = 0; i < rem; ++i)
	{
		tmp32 |= (static_cast<uint>(A[Offset + i]) << (i * 8));
	}

	tmp32 = Gf256vMulU32(tmp32, B);

	for (i = 0; i < rem; ++i)
	{
		A[Offset + i] = (tmp32 >> (i * 8)) & 0xFF;
	}
}

void RNBWGfMath::Gf256vPredicatedAdd(std::vector<byte> &AccuB, size_t BOffset, byte Predicate, const std::vector<byte> &A, size_t AOffset, size_t Length)
{
	byte pru8;
	uint au32;
	uint bu32;
	uint pru32;
	uint rem;
	size_t i;
	size_t nu32;

	pru32 = 0UL - static_cast<uint>(Predicate);
	pru8 = pru32 & 0xff;
	nu32 = Length >> 2;

	for (i = 0; i < nu32; ++i)
	{
		au32 = IntegerTools::LeBytesTo32(A, AOffset + (i * sizeof(uint)));
		bu32 = IntegerTools::LeBytesTo32(AccuB, BOffset + (i * sizeof(uint)));
		bu32 ^= (au32 & pru32);
		IntegerTools::Le32ToBytes(bu32, AccuB, BOffset + (i * sizeof(uint)));
	}

	AOffset += (nu32 << 2);
	BOffset += (nu32 << 2);
	rem = Length & 3;

	for (i = 0; i < rem; ++i)
	{
		AccuB[BOffset + i] ^= (A[AOffset + i] & pru8);
	}
}

#endif

void RNBWGfMath::Gf256vSetZero(std::vector<byte> &B, size_t BOffset, uint Count)
{
	Gf256vAdd(B, BOffset, B, BOffset, Count);
}

void RNBWGfMath::Gf256MatProdRef(std::vector<byte> &C, const std::vector<byte> &MatA, uint Na, uint NaWidth, const std::vector<byte> &B, size_t BOffset)
{
	size_t aoff;
	size_t i;

	aoff = 0;
	Gf256vSetZero(C, 0, Na);

	for (i = 0; i < NaWidth; ++i)
	{
		Gf256vMadd(C, 0, MatA, aoff, B[BOffset + i], Na);
		aoff += Na;
	}
}

uint RNBWGfMath::Gf256MatGaussElimRef(std::vector<byte> &Mat, uint H, uint W)
{
	byte pivot;
	uint align4;
	uint r8;
	size_t aoff;
	size_t i;
	size_t j;
	size_t joff;

	r8 = 1;

	for (i = 0; i < H; ++i)
	{
		aoff = i * W;
		align4 = i & (~0x3);

		for (j = i + 1; j < H; ++j)
		{
			joff = j * W;
			Gf256vPredicatedAdd(Mat, aoff + align4, !Gf256IsNonZero(Mat[aoff + i]), Mat, joff + align4, W - align4);
		}

		r8 &= Gf256IsNonZero(Mat[aoff + i]);
		pivot = Mat[aoff + i];
		pivot = Gf256Inv(pivot);
		Gf256vMulScalar(Mat, aoff + align4, pivot, W - align4);

		for (j = 0; j < H; ++j)
		{
			if (i == j)
			{
				continue;
			}

			joff = j * W;
			Gf256vMadd(Mat, joff + align4, Mat, aoff + align4, Mat[joff + i], W - align4);
		}
	}

	return r8;
}

void RNBWGfMath::Gf256MatSubMat(std::vector<byte> &Mat2, uint W2, uint St, const std::vector<byte> &Mat, uint W, uint H)
{
	size_t i;
	size_t j;

	for (i = 0; i < H; ++i)
	{
		for (j = 0; j < W2; ++j)
		{
			Mat2[(i * W2) + j] = Mat[(i * W) + St + j];
		}
	}
}

void RNBWGfMath::Gf256MatProd(std::vector<byte> &C, const std::vector<byte> &MatA, uint Na, uint NaWidth, const std::vector<byte> &B, size_t BOffset)
{
	Gf256MatProdRef(C, MatA, Na, NaWidth, B, BOffset);
}

unsigned RNBWGfMath::Gf256MatGaussElim(std::vector<byte> &Mat, uint H, uint W)
{
	return Gf256MatGaussElimRef(Mat, H, W);
}

uint RNBWGfMath::Gf256MatInv(std::vector<byte> &InvA, const std::vector<byte> &A, uint H, std::vector<byte> &Buffer)
{
	std::vector<byte> aa;
	std::vector<byte> ai;
	size_t i;
	byte r8;
	size_t aoff;

	aa = Buffer;

	for (i = 0; i < H; ++i)
	{
		aoff = i * 2 * H;
		Gf256vSetZero(aa, aoff, 2 * H);
		Gf256vAdd(aa, aoff, A, i * H, H);
		aa[aoff + H + i] = 1;
	}

	r8 = Gf256MatGaussElim(aa, H, 2 * H);
	Gf256MatSubMat(InvA, H, H, aa, 2 * H, H);

	return r8;
}

byte RNBWGfMath::Gf4Mul2(byte A)
{
	// gf4 := gf2[x]/x^2+x+1

	byte r;

	r = A << 1;
	r ^= (A >> 1) * 7;

	return r;
}

byte RNBWGfMath::Gf4Mul3(byte A)
{
	byte mask;

	mask = (A - 2) >> 1;

	return (mask & (A * 3)) | ((~mask) & (A - 1));
}

byte RNBWGfMath::Gf4Mul(byte A, byte B)
{
	byte r;

	r = A * (B & 1);

	return r ^ (Gf4Mul2(A) * (B >> 1));
}

byte RNBWGfMath::Gf4Squ(byte A)
{
	return A ^ (A >> 1);
}

uint RNBWGfMath::Gf4vMul2U32(uint A)
{
	uint bit0;
	uint bit1;

	bit0 = A & 0x55555555UL;
	bit1 = A & 0xAAAAAAAAUL;

	return (bit0 << 1) ^ bit1 ^ (bit1 >> 1);
}

uint RNBWGfMath::Gf4vMul3U32(uint A)
{
	uint bit0;
	uint bit1;

	bit0 = A & 0x55555555UL;
	bit1 = A & 0xAAAAAAAAUL;

	return (bit0 << 1) ^ bit0 ^ (bit1 >> 1);
}

uint RNBWGfMath::Gf4vMulU32(uint A, byte B)
{
	uint bitb0;
	uint bitb1;

	bitb0 = 0UL - (static_cast<uint>(B & 1));
	bitb1 = 0UL - (static_cast<uint>((B >> 1) & 1));

	return (A & bitb0) ^ (bitb1 & Gf4vMul2U32(A));
}

uint RNBWGfMath::Gf4vMulhU32U32(uint A0, uint A1, uint B0, uint B1)
{
	uint c0;
	uint c1;
	uint c2;

	c0 = A0 & B0;
	c2 = A1 & B1;
	c1 = (A0 ^ A1) & (B0 ^ B1);

	return ((c1 ^ c0) << 1) ^ c0 ^ c2;
}

uint RNBWGfMath::Gf4vSquU32(uint A)
{
	uint bit1;

	bit1 = A & 0xAAAAAAAAUL;

	return A ^ (bit1 >> 1);
}

byte RNBWGfMath::Gf16Mul(byte A, byte B)
{
	// gf16 := gf4[y]/y^2+y+x

	byte a0;
	byte a1;
	byte b0;
	byte b1;
	byte a0b0;
	byte a1b1;
	byte a0b1a1b0;
	byte a1b1x2;

	a0 = A & 3;
	a1 = (A >> 2);
	b0 = B & 3;
	b1 = (B >> 2);
	a0b0 = Gf4Mul(a0, b0);
	a1b1 = Gf4Mul(a1, b1);
	a0b1a1b0 = Gf4Mul(a0 ^ a1, b0 ^ b1) ^ a0b0 ^ a1b1;
	a1b1x2 = Gf4Mul2(a1b1);

	return ((a0b1a1b0 ^ a1b1) << 2) ^ a0b0 ^ a1b1x2;
}

byte RNBWGfMath::Gf16Squ(byte A)
{
	byte a0;
	byte a1;
	byte a1squx2;

	a0 = A & 3;
	a1 = (A >> 2);
	a1 = Gf4Squ(a1);
	a1squx2 = Gf4Mul2(a1);

	return (a1 << 2) ^ a1squx2 ^ Gf4Squ(a0);
}

byte RNBWGfMath::Gf16Mul8(byte A)
{
	byte a0;
	byte a1;

	a0 = A & 3;
	a1 = A >> 2;

	return (Gf4Mul2(a0 ^ a1) << 2) | Gf4Mul3(a1);
}

uint RNBWGfMath::Gf16vMulU32(uint A, byte B)
{
	// gf16 := gf4[y]/y^2+y+x

	uint axb0;
	uint axb1;
	uint a0b1;
	uint a1b1;
	uint a1b12;

	axb0 = Gf4vMulU32(A, B);
	axb1 = Gf4vMulU32(A, B >> 2);
	a0b1 = (axb1 << 2) & 0xCCCCCCCCUL;
	a1b1 = axb1 & 0xCCCCCCCCUL;
	a1b12 = a1b1 >> 2;

	return axb0 ^ a0b1 ^ a1b1 ^ Gf4vMul2U32(a1b12);
}

uint RNBWGfMath::Gf16vMulhU32U32(uint A0, uint A1, uint A2, uint A3, uint B0, uint B1, uint B2, uint B3)
{
	// GF(4) x2: (bit0<<1)^bit1^(bit1>>1)

	uint c0;
	uint c1;
	uint c2x0;
	uint c2x2;
	uint c2x1;
	uint c2r0;
	uint c2r1;

	c0 = Gf4vMulhU32U32(A0, A1, B0, B1);
	c1 = Gf4vMulhU32U32(A0 ^ A2, A1 ^ A3, B0 ^ B2, B1 ^ B3);
	c2x0 = A2 & B2;
	c2x2 = A3 & B3;
	c2x1 = (A2 ^ A3) & (B2 ^ B3);
	c2r0 = c2x0 ^ c2x2;
	c2r1 = c2x0 ^ c2x1;

	return ((c1 ^ c0) << 2) ^ c0 ^ (c2r0 << 1) ^ c2r1 ^ (c2r1 << 1);
}

byte RNBWGfMath::Gf256vReduceU32(uint A)
{
	std::array<ushort, 2> aa = { 0 };
	std::array<byte, 2> rr = { 0 };
	ushort r;

	aa[0] = A & 0xFFFFU;
	aa[1] = (A >> 16) & 0xFFFFU;
	r = aa[0] ^ aa[1];
	IntegerTools::Le16ToBytes(r, rr, 0);

	return rr[0] ^ rr[1];
}

uint RNBWGfMath::Gf16vSquU32(uint A)
{
	uint a2;

	a2 = Gf4vSquU32(A);

	return a2 ^ Gf4vMul2U32((a2 >> 2) & 0x33333333UL);
}

uint RNBWGfMath::Gf16vMul8U32(uint A)
{
	uint a0;
	uint a1;

	a1 = A & 0xCCCCCCCCUL;
	a0 = (A << 2) & 0xCCCCCCCCUL;

	return Gf4vMul2U32(a0 ^ a1) | Gf4vMul3U32(a1 >> 2);
}

byte RNBWGfMath::Gf256IsNonZero(byte A)
{
	uint a8;
	uint r;

	a8 = A;
	r = 0UL - a8;
	r >>= 8;

	return r & 1;
}

byte RNBWGfMath::Gf256Mul(byte A, byte B)
{
	// gf256 := gf16[X]/X^2+X+xy

	byte a0;
	byte a1;
	byte b0;
	byte b1;
	byte a0b0;
	byte a1b1;
	byte a0b1a1b0;
	byte a1b1x8;

	a0 = A & 15;
	a1 = (A >> 4);
	b0 = B & 15;
	b1 = (B >> 4);
	a0b0 = Gf16Mul(a0, b0);
	a1b1 = Gf16Mul(a1, b1);
	a0b1a1b0 = Gf16Mul(a0 ^ a1, b0 ^ b1) ^ a0b0 ^ a1b1;
	a1b1x8 = Gf16Mul8(a1b1);

	return ((a0b1a1b0 ^ a1b1) << 4) ^ a0b0 ^ a1b1x8;
}

byte RNBWGfMath::Gf256MulGf16(byte A, byte Gf16B)
{
	byte a0;
	byte a1;
	byte b0;
	byte a0b0;
	byte a1b0;

	a0 = A & 15;
	a1 = (A >> 4);
	b0 = Gf16B & 15;
	a0b0 = Gf16Mul(a0, b0);
	a1b0 = Gf16Mul(a1, b0);

	return a0b0 ^ (a1b0 << 4);
}

byte RNBWGfMath::Gf256Squ(byte A)
{
	byte a0;
	byte a1;
	byte a1squx8;

	a0 = A & 15;
	a1 = (A >> 4);
	a1 = Gf16Squ(a1);
	a1squx8 = Gf16Mul8(a1);

	return (a1 << 4) ^ a1squx8 ^ Gf16Squ(a0);
}

byte RNBWGfMath::Gf256Inv(byte A)
{
	// 128+64+32+16+8+4+2 = 254

	byte a2;
	byte a4;
	byte a8;
	byte a4x2;
	byte a8x4x2;
	byte a64;
	byte a64x2;
	byte a128;

	a2 = Gf256Squ(A);
	a4 = Gf256Squ(a2);
	a8 = Gf256Squ(a4);
	a4x2 = Gf256Mul(a4, a2);
	a8x4x2 = Gf256Mul(a4x2, a8);
	a64 = Gf256Squ(a8x4x2);
	a64 = Gf256Squ(a64);
	a64 = Gf256Squ(a64);
	a64x2 = Gf256Mul(a64, a8x4x2);
	a128 = Gf256Squ(a64x2);

	return Gf256Mul(a2, a128);
}

uint RNBWGfMath::Gf256vMulU32(uint A, byte B)
{
	uint axb0;
	uint axb1;
	uint a0b1;
	uint a1b1;
	uint a1b1x4;

	axb0 = Gf16vMulU32(A, B);
	axb1 = Gf16vMulU32(A, B >> 4);
	a0b1 = (axb1 << 4) & 0xF0F0F0F0UL;
	a1b1 = axb1 & 0xF0F0F0F0UL;
	a1b1x4 = a1b1 >> 4;

	return axb0 ^ a0b1 ^ a1b1 ^ Gf16vMul8U32(a1b1x4);
}

uint RNBWGfMath::Gf256vSquU32(uint A)
{
	uint a2;
	uint ar;

	a2 = Gf16vSquU32(A);
	ar = (a2 >> 4) & 0x0F0F0F0FUL;

	return a2 ^ Gf16vMul8U32(ar);
}

uint RNBWGfMath::Gf256vMulGf16U32(uint A, byte Gf16B)
{
	return Gf16vMulU32(A, Gf16B);
}

ulong RNBWGfMath::Gf4vMul2U64(ulong A)
{
	ulong bit0;
	ulong bit1;

	bit0 = A & 0x5555555555555555ULL;
	bit1 = A & 0xAAAAAAAAAAAAAAAAULL;

	return (bit0 << 1) ^ bit1 ^ (bit1 >> 1);
}

ulong RNBWGfMath::Gf4vMul3U64(ulong A)
{
	ulong bit0;
	ulong bit1;

	bit0 = A & 0x5555555555555555ULL;
	bit1 = A & 0xAAAAAAAAAAAAAAAAULL;

	return (bit0 << 1) ^ bit0 ^ (bit1 >> 1);
}

ulong RNBWGfMath::Gf4vMulU64(ulong A, byte B)
{
	ulong bitb0;
	ulong bitb1;

	bitb0 = 0ULL - static_cast<ulong>(B & 1);
	bitb1 = 0ULL - (static_cast<ulong>((B >> 1) & 1));

	return (A & bitb0) ^ (bitb1 & Gf4vMul2U64(A));
}

ulong RNBWGfMath::Gf4vMulhU64U64(ulong A0, ulong A1, ulong B0, ulong B1)
{
	ulong c0;
	ulong c1;
	ulong c2;

	c0 = A0 & B0;
	c2 = A1 & B1;
	c1 = (A0 ^ A1) & (B0 ^ B1);

	return ((c1 ^ c0) << 1) ^ c0 ^ c2;
}

ulong RNBWGfMath::Gf4vMulU64U64(ulong A, ulong B)
{
	ulong a0;
	ulong a1;
	ulong b0;
	ulong b1;

	a0 = A & 0xAAAAAAAAAAAAAAAAULL;
	a1 = (A >> 1) & 0xAAAAAAAAAAAAAAAAULL;
	b0 = B & 0xAAAAAAAAAAAAAAAAULL;
	b1 = (B >> 1) & 0xAAAAAAAAAAAAAAAAULL;

	return Gf4vMulhU64U64(a0, a1, b0, b1);
}

ulong RNBWGfMath::Gf4vSquU64(ulong A)
{
	ulong bit1;

	bit1 = A & 0xAAAAAAAAAAAAAAAAULL;

	return A ^ (bit1 >> 1);
}

ulong RNBWGfMath::Gf16vMulU64(ulong A, byte B)
{
	ulong axb0;
	ulong axb1;
	ulong a0b1;
	ulong a1b1;
	ulong a1b1x2;

	axb0 = Gf4vMulU64(A, B);
	axb1 = Gf4vMulU64(A, B >> 2);
	a0b1 = (axb1 << 2) & 0xCCCCCCCCCCCCCCCCULL;
	a1b1 = axb1 & 0xCCCCCCCCCCCCCCCCULL;
	a1b1x2 = a1b1 >> 2;

	return axb0 ^ a0b1 ^ a1b1 ^ Gf4vMul2U64(a1b1x2);
}

ulong RNBWGfMath::Gf16vMulhU64U64(ulong A0, ulong A1, ulong A2, ulong A3, ulong B0, ulong B1, ulong B2, ulong B3)
{
	ulong c0;
	ulong c1;
	ulong c2x0;
	ulong c2x2;
	ulong c2x1;
	ulong c2r0;
	ulong c2r1;

	c0 = Gf4vMulhU64U64(A0, A1, B0, B1);
	c1 = Gf4vMulhU64U64(A0 ^ A2, A1 ^ A3, B0 ^ B2, B1 ^ B3);
	c2x0 = A2 & B2;
	c2x2 = A3 & B3;
	c2x1 = (A2 ^ A3) & (B2 ^ B3);
	c2r0 = c2x0 ^ c2x2;
	c2r1 = c2x0 ^ c2x1;

	return ((c1 ^ c0) << 2) ^ c0 ^ (c2r0 << 1) ^ c2r1 ^ (c2r1 << 1);
}

ulong RNBWGfMath::Gf16vMulU64U64(ulong A, ulong B)
{
	ulong a0;
	ulong a1;
	ulong a2;
	ulong a3;
	ulong b0;
	ulong b1;
	ulong b2;
	ulong b3;

	a0 = A & 0x1111111111111111ULL;
	a1 = (A >> 1) & 0x1111111111111111ULL;
	a2 = (A >> 2) & 0x1111111111111111ULL;
	a3 = (A >> 3) & 0x1111111111111111ULL;
	b0 = B & 0x1111111111111111ULL;
	b1 = (B >> 1) & 0x1111111111111111ULL;
	b2 = (B >> 2) & 0x1111111111111111ULL;
	b3 = (B >> 3) & 0x1111111111111111ULL;

	return Gf16vMulhU64U64(a0, a1, a2, a3, b0, b1, b2, b3);
}

byte RNBWGfMath::Gf256vReduceU64(ulong A)
{
	uint aa[2] = { 0 };
	uint r;

	aa[0] = A & 0xFFFFFFFFUL;
	aa[1] = (A >> 32) & 0xFFFFFFFFUL;
	r = aa[0] ^ aa[1];

	return Gf256vReduceU32(r);
}

ulong RNBWGfMath::Gf16vSquU64(ulong A)
{
	ulong a2;

	a2 = Gf4vSquU64(A);

	return a2 ^ Gf4vMul2U64((a2 >> 2) & 0x3333333333333333ULL);
}

ulong RNBWGfMath::Gf16vMul8U64(ulong A)
{
	ulong a0;
	ulong a1;

	a1 = A & 0xCCCCCCCCCCCCCCCCULL;
	a0 = (A << 2) & 0xCCCCCCCCCCCCCCCCULL;

	return Gf4vMul2U64(a0 ^ a1) | Gf4vMul3U64(a1 >> 2);
}

ulong RNBWGfMath::Gf256vMulU64(ulong A, byte B)
{
	ulong axb0;
	ulong axb1;
	ulong a0b1;
	ulong a1b1;
	ulong a1b1x4;

	axb0 = Gf16vMulU64(A, B);
	axb1 = Gf16vMulU64(A, B >> 4);
	a0b1 = (axb1 << 4) & 0xF0F0F0F0F0F0F0F0ULL;
	a1b1 = axb1 & 0xF0F0F0F0F0F0F0F0ULL;
	a1b1x4 = a1b1 >> 4;

	return axb0 ^ a0b1 ^ a1b1 ^ Gf16vMul8U64(a1b1x4);
}

ulong RNBWGfMath::Gf256vSquU64(ulong A)
{
	ulong a2;
	ulong ar;

	a2 = Gf16vSquU64(A);
	ar = (a2 >> 4) & 0x0F0F0F0F0F0F0F0FULL;

	return a2 ^ Gf16vMul8U64(ar);
}

ulong RNBWGfMath::Gf256vMulGf16U64(ulong A, byte Gf16B)
{
	return Gf16vMulU64(A, Gf16B);
}

NAMESPACE_RAINBOWEND
