// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_NTRUSQ4591N761_H
#define CEX_NTRUSQ4591N761_H

#include "CexDomain.h"
#include "BCG.h"
#include "CSP.h"
#include "CSR.h"
#include "IPrng.h"
#include "Keccak512.h"

NAMESPACE_NTRU

#define NTRU_SPRIME_SIMPLE

/// 
/// internal
/// 

/// <summary>
/// The NTRU S-Prime functions
/// </summary>
class NTRUSQ4591N761
{
public:

	//~~~Public Constants~~~//

	/// <summary>
	/// The parameter sets formal name
	/// </summary>
	static const std::string Name;

	/// <summary>
	/// The byte size of B's reply message to host A
	/// </summary>
	static const size_t NTRU_CIPHERTEXT_SIZE = 1047;

	/// <summary>
	/// The P dimension
	/// </summary>
	static const int NTRU_P = 761;

	/// <summary>
	/// The modulus factor
	/// </summary>
	static const int NTRU_Q = 4591;

	/// <summary>
	/// The byte size of the private key polynomial
	/// </summary>
	static const size_t NTRU_PRIVATEKEY_SIZE = 1600;

	/// <summary>
	/// The byte size of the public key polynomial
	/// </summary>
	static const size_t NTRU_PUBLICKEY_SIZE = 1218;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	static const size_t NTRU_SEED_SIZE = 32;

	/// <summary>
	/// The W dimension
	/// </summary>
	static const int NTRU_W = 286;

private:

	static const int NTRU_QSHIFT = 2295;
	static const size_t NTRU_RQENCODE_SIZE = 1218;
	static const size_t NTRU_SMALLENCODE_SIZE = 191;

	/* Common Functions */

	static void MinMax(int32_t &X, int32_t &Y)
	{
		uint c;
		uint xi;
		uint xy;
		uint yi;

		xi = X;
		yi = Y;
		xy = xi ^ yi;
		c = yi - xi;
		c ^= xy & (c ^ yi);
		c >>= 31;
		c = ~c + 1;
		c &= xy;
		X = xi ^ c;
		Y = yi ^ c;
	}

	static int16_t ModqFreeze(int32_t A)
	{
		/* input between -9000000 and 9000000 output between -2295 and 2295 */
		A -= 4591 * ((228 * A) >> 20);
		A -= 4591 * ((58470 * A + 134217728) >> 28);

		return A;
	}

	static int16_t ModqPlusProduct(int16_t A, int16_t B, int16_t C)
	{
		int32_t a = A;
		int32_t b = B;
		int32_t c = C;

		return ModqFreeze(a + b * c);
	}

	static int16_t ModqSum(int16_t A, int16_t B)
	{
		int32_t s = A + B;

		return ModqFreeze(s);
	}

	static void RqDecodeRounded(std::array<int16_t, NTRU_P> &F, const std::vector<byte> &C, size_t COffset)
	{
		uint c0;
		uint c1;
		uint c2;
		uint c3;
		uint f0;
		uint f1;
		uint f2;
		size_t i;

		for (i = 0; i < NTRU_P / 3; ++i)
		{
			c0 = C[COffset + (i * 4)];
			c1 = C[COffset + (i * 4) + 1];
			c2 = C[COffset + (i * 4) + 2];
			c3 = C[COffset + (i * 4) + 3];

			/* f0 + f1*1536 + f2*1536^2 */
			/* = c0 + c1*256 + c2*256^2 + c3*256^3 */
			/* with each F between 0 and 1530 */
			/* f2 = (64/9)c3 + (1/36)c2 + (1/9216)c1 + (1/2359296)c0 - [0,0.99675] */
			/* claim: 2^21 f2 < x < 2^21(f2+1) */
			/* where x = 14913081*c3 + 58254*c2 + 228*(c1+2) */
			/* proof: x - 2^21 f2 = 456 - (8/9)c0 + (4/9)c1 - (2/9)c2 + (1/9)c3 + 2^21 [0,0.99675] */
			/* at least 456 - (8/9)255 - (2/9)255 > 0 */
			/* at most 456 + (4/9)255 + (1/9)255 + 2^21 0.99675 < 2^21 */
			f2 = ((14913081 * c3) + (58254 * c2) + (228 * (c1 + 2))) >> 21;
			c2 += c3 << 8;
			c2 -= (f2 * 9) << 2;

			/* f0 + f1*1536 */
			/* = c0 + c1*256 + c2*256^2 */
			/* c2 <= 35 = floor((1530+1530*1536)/256^2) */
			/* f1 = (128/3)c2 + (1/6)c1 + (1/1536)c0 - (1/1536)f0 */
			/* claim: 2^21 f1 < x < 2^21(f1+1) */
			/* where x = 89478485*c2 + 349525*c1 + 1365*(c0+1) */
			/* proof: x - 2^21 f1 = 1365 - (1/3)c2 - (1/3)c1 - (1/3)c0 + (4096/3)f0 */
			/* at least 1365 - (1/3)35 - (1/3)255 - (1/3)255 > 0 */
			/* at most 1365 + (4096/3)1530 < 2^21 */
			f1 = ((89478485 * c2) + (349525 * c1) + (1365 * (c0 + 1))) >> 21;
			c1 += c2 << 8;
			c1 -= (f1 * 3) << 1;
			c0 += c1 << 8;
			f0 = c0;

			F[(i * 3)] = ModqFreeze(f0 * 3 + NTRU_Q - NTRU_QSHIFT);
			F[(i * 3) + 1] = ModqFreeze(f1 * 3 + NTRU_Q - NTRU_QSHIFT);
			F[(i * 3) + 2] = ModqFreeze(f2 * 3 + NTRU_Q - NTRU_QSHIFT);
		}

		c0 = C[COffset + (i * 4)];
		c1 = C[COffset + (i * 4) + 1];
		c2 = C[COffset + (i * 4) + 2];
		f1 = ((89478485 * c2) + (349525 * c1) + (1365 * (c0 + 1))) >> 21;

		c1 += c2 << 8;
		c1 -= (f1 * 3) << 1;
		c0 += c1 << 8;
		f0 = c0;

		F[(i * 3)] = ModqFreeze(f0 * 3 + NTRU_Q - NTRU_QSHIFT);
		F[(i * 3) + 1] = ModqFreeze(f1 * 3 + NTRU_Q - NTRU_QSHIFT);
	}

	static void RqEncodeRounded(std::vector<byte> &C, size_t COffset, const std::array<int16_t, NTRU_P> &F)
	{
		int32_t f0;
		int32_t f1;
		int32_t f2;
		size_t i;

		for (i = 0; i < NTRU_P / 3; ++i)
		{
			f0 = F[(i * 3)] + NTRU_QSHIFT;
			f1 = F[(i * 3) + 1] + NTRU_QSHIFT;
			f2 = F[(i * 3) + 2] + NTRU_QSHIFT;
			f0 = (21846 * f0) >> 16;
			f1 = (21846 * f1) >> 16;
			f2 = (21846 * f2) >> 16;
			/* now want f0 + f1*1536 + f2*1536^2 as a 32-bit integer */
			f2 *= 3;
			f1 += f2 << 9;
			f1 *= 3;
			f0 += f1 << 9;
			C[COffset + (i * 4)] = f0;
			f0 >>= 8;
			C[COffset + (i * 4) + 1] = f0;
			f0 >>= 8;
			C[COffset + (i * 4) + 2] = f0;
			f0 >>= 8;
			C[COffset + (i * 4) + 3] = f0;
		}

		/* XXX: using p mod 3 = 2 */
		f0 = F[(i * 3)] + NTRU_QSHIFT;
		f1 = F[(i * 3) + 1] + NTRU_QSHIFT;
		f0 = (21846 * f0) >> 16;
		f1 = (21846 * f1) >> 16;
		f1 *= 3;
		f0 += f1 << 9;
		C[COffset + (i * 4)] = f0;
		f0 >>= 8;
		C[COffset + (i * 4) + 1] = f0;
		f0 >>= 8;
		C[COffset + (i * 4) + 2] = f0;
	}

	static void RqMult(std::array<int16_t, NTRU_P> &H, const std::array<int16_t, NTRU_P> &F, const std::array<int8_t, NTRU_P> &G)
	{
		std::array<int16_t, NTRU_P + NTRU_P - 1> fg;
		size_t i;
		size_t j;
		int16_t result;

		for (i = 0; i < NTRU_P; ++i)
		{
			result = 0;

			for (j = 0; j <= i; ++j)
			{
				result = ModqPlusProduct(result, F[j], G[i - j]);
			}

			fg[i] = result;
		}

		for (i = NTRU_P; i < NTRU_P + NTRU_P - 1; ++i)
		{
			result = 0;

			for (j = i - NTRU_P + 1; j < NTRU_P; ++j)
			{
				result = ModqPlusProduct(result, F[j], G[i - j]);
			}

			fg[i] = result;
		}

		for (i = NTRU_P + NTRU_P - 2; i >= NTRU_P; --i)
		{
			fg[i - NTRU_P] = ModqSum(fg[i - NTRU_P], fg[i]);
			fg[i - NTRU_P + 1] = ModqSum(fg[i - NTRU_P + 1], fg[i]);
		}

		for (i = 0; i < NTRU_P; ++i)
		{
			H[i] = fg[i];
		}
	}

	static void RqRound3(std::array<int16_t, NTRU_P> &H, const std::array<int16_t, NTRU_P> &F)
	{
		size_t i;

		for (i = 0; i < NTRU_P; ++i)
		{
			H[i] = ((21846 * (F[i] + 2295) + 32768) >> 16) * 3 - 2295;
		}
	}

	static void SmallDecode(std::array<int8_t, NTRU_P> &F, const std::vector<byte> &C, size_t COffset)
	{
		size_t i;
		uint8_t c0;

		for (i = 0; i < NTRU_P / 4; ++i)
		{
			c0 = C[COffset + i];
			F[(i * 4)] = ((int8_t)(c0 & 3)) - 1;
			c0 >>= 2;
			F[(i * 4) + 1] = ((int8_t)(c0 & 3)) - 1;
			c0 >>= 2;
			F[(i * 4) + 2] = ((int8_t)(c0 & 3)) - 1;
			c0 >>= 2;
			F[(i * 4) + 3] = ((int8_t)(c0 & 3)) - 1;
		}

		c0 = C[COffset + i];
		F[(i * 4)] = ((int8_t)(c0 & 3)) - 1;
	}

	static void SmallEncode(std::vector<byte> &C, size_t COffset, const std::array<int8_t, NTRU_P> &F)
	{
		// all coefficients in -1, 0, 1
		size_t i;
		uint8_t c0;

		for (i = 0; i < NTRU_P / 4; ++i)
		{
			c0 = F[(i * 4)] + 1;
			c0 += (F[(i * 4) +1 ] + 1) << 2;
			c0 += (F[(i * 4) + 2] + 1) << 4;
			c0 += (F[(i * 4) + 3] + 1) << 6;
			C[COffset + i] = c0;
		}

		c0 = F[i * 4] + 1;
		C[COffset + i] = c0;
	}

	template<typename Array>
	static void Swap(Array &X, size_t XOffset, Array &Y, size_t YOffset, size_t Length, int32_t Mask)
	{
		Array::value_type c;
		Array::value_type t;
		Array::value_type xi;
		Array::value_type yi;
		size_t i;

		c = Mask;

		for (i = 0; i < Length; ++i)
		{
			xi = X[XOffset + i];
			yi = Y[YOffset + i];
			t = c & (xi ^ yi);
			xi ^= t;
			yi ^= t;
			X[XOffset + i] = xi;
			Y[YOffset + i] = yi;
		}
	}

	static void Swap32(int32_t &X, int32_t &Y, int32_t Mask)
	{
		int32_t t;
		int32_t xi;
		int32_t yi;

		xi = X;
		yi = Y;
		t = Mask & (xi ^ yi);
		xi ^= t;
		yi ^= t;
		X = xi;
		Y = yi;
	}

	static void Sort(std::array<int32_t, NTRU_P> &X)
	{
		const int32_t TOP = 512;

		int32_t i;
		int32_t p;
		int32_t q;
		int32_t n;

		n = NTRU_P;

		for (p = TOP; p > 0; p >>= 1)
		{
			for (i = 0; i < n - p; ++i)
			{
				if (!(i & p))
				{
					MinMax(X[i], X[i + p]);
				}
			}

			for (q = TOP; q > p; q >>= 1)
			{
				for (i = 0; i < n - q; ++i)
				{
					if (!(i & p))
					{
						MinMax(X[i + p], X[i + q]);
					}
				}
			}
		}
	}

	static int32_t Mod3NonZeroMask(int8_t X)
	{
		return -X * X;
	}

	static int8_t Mod3Freeze(int32_t a)
	{
		/* input between -100000 and 100000 */
		/* output between -1 and 1 */
		a -= 3 * ((10923 * a) >> 15);
		a -= 3 * (((89478485 * a) + 134217728) >> 28);

		return a;
	}

	static int8_t Mod3MinusProduct(int8_t A, int8_t B, int8_t C)
	{
		int32_t a = A;
		int32_t b = B;
		int32_t c = C;

		return Mod3Freeze(a - b * c);
	}

	static int8_t Mod3PlusProduct(int8_t A, int8_t B, int8_t C)
	{
		int32_t a = A;
		int32_t b = B;
		int32_t c = C;

		return Mod3Freeze(a + b * c);
	}

	static int8_t Mod3Product(int8_t A, int8_t B)
	{
		return A * B;
	}

	static int8_t Mod3Sum(int8_t A, int8_t B)
	{
		int32_t a = A;
		int32_t b = B;

		return Mod3Freeze(a + b);
	}

	static int8_t Mod3Reciprocal(int8_t A1)
	{
		return A1;
	}

	static int8_t Mod3Quotient(int8_t Num, int8_t Den)
	{
		return Mod3Product(Num, Mod3Reciprocal(Den)); // fix
	}

	static int16_t ModqMinusProduct(int16_t A, int16_t B, int16_t C)
	{
		int32_t a = A;
		int32_t b = B;
		int32_t c = C;

		return ModqFreeze(a - b * c);
	}

	static int ModqNonZeroMask(int16_t X)
	{
		/* -1 if x is nonzero, 0 otherwise */
		int32_t r;

		r = (ushort)X;
		r = -r;
		r >>= 30;

		return r;
	}

	static int16_t ModqProduct(int16_t A, int16_t B)
	{
		int32_t a = A;
		int32_t b = B;

		return ModqFreeze(a * b);
	}

	static int16_t ModqSquare(int16_t A)
	{
		int32_t a = A;

		return ModqFreeze(a * a);
	}

	static int16_t ModqReciprocal(int16_t A1)
	{
		int16_t a2 = ModqSquare(A1);
		int16_t a3 = ModqProduct(a2, A1);
		int16_t a4 = ModqSquare(a2);
		int16_t a8 = ModqSquare(a4);
		int16_t a16 = ModqSquare(a8);
		int16_t a32 = ModqSquare(a16);
		int16_t a35 = ModqProduct(a32, a3);
		int16_t a70 = ModqSquare(a35);
		int16_t a140 = ModqSquare(a70);
		int16_t a143 = ModqProduct(a140, a3);
		int16_t a286 = ModqSquare(a143);
		int16_t a572 = ModqSquare(a286);
		int16_t a1144 = ModqSquare(a572);
		int16_t a1147 = ModqProduct(a1144, a3);
		int16_t a2294 = ModqSquare(a1147);
		int16_t a4588 = ModqSquare(a2294);
		int16_t a4589 = ModqProduct(a4588, A1);

		return a4589;
	}

	static int16_t ModqQuotient(int16_t Num, int16_t Den)
	{
		return ModqProduct(Num, ModqReciprocal(Den));
	}

	static void R3Mult(std::array<int8_t, NTRU_P> &H, const std::array<int8_t, NTRU_P> &F, const std::array<int8_t, NTRU_P> &G)
	{
		std::array<int8_t, NTRU_P + NTRU_P - 1> fg;
		size_t i;
		size_t j;
		int8_t result;

		for (i = 0; i < NTRU_P; ++i)
		{
			result = 0;

			for (j = 0; j <= i; ++j)
			{
				result = Mod3PlusProduct(result, F[j], G[i - j]);
			}

			fg[i] = result;
		}
		for (i = NTRU_P; i < NTRU_P + NTRU_P - 1; ++i)
		{
			result = 0;

			for (j = i - NTRU_P + 1; j < NTRU_P; ++j)
			{
				result = Mod3PlusProduct(result, F[j], G[i - j]);
			}

			fg[i] = result;
		}

		for (i = NTRU_P + NTRU_P - 2; i >= NTRU_P; --i)
		{
			fg[i - NTRU_P] = Mod3Sum(fg[i - NTRU_P], fg[i]);
			fg[i - NTRU_P + 1] = Mod3Sum(fg[i - NTRU_P + 1], fg[i]);
		}

		for (i = 0; i < NTRU_P; ++i)
		{
			H[i] = fg[i];
		}
	}

	static int SmallerMask(int32_t X, int32_t Y)
	{
		return (X - Y) >> 31;
	}

	static void SmallRandomWeightW(std::array<int8_t, NTRU_P> &F, std::unique_ptr<Prng::IPrng> &Rng)
	{
		std::array<int32_t, NTRU_P> r;
		size_t i;

		for (i = 0; i < NTRU_P; ++i)
		{
			r[i] = static_cast<int32_t>(Rng->NextUInt32());
		}

		for (i = 0; i < NTRU_W; ++i)
		{
			r[i] &= -2;
		}

		for (i = NTRU_W; i < NTRU_P; ++i)
		{
			r[i] = (r[i] & -3) | 1;
		}

		Sort(r);

		for (i = 0; i < NTRU_P; ++i)
		{
			F[i] = static_cast<int8_t>(r[i] & 3) - 1;
		}
	}

	static void SmallRandom(std::array<int8_t, NTRU_P> &G, std::unique_ptr<Prng::IPrng> &Rng)
	{
		size_t i;

		for (i = 0; i < NTRU_P; ++i)
		{
			uint r = Rng->NextUInt32();
			G[i] = (int8_t)(((1073741823 & r) * 3) >> 30) - 1;
		}
	}

	static void VectorMod3Product(std::array<int8_t, NTRU_P> &Z, const std::vector<int8_t> &X, size_t XOffset, const int8_t C, size_t Length)
	{
		size_t i;

		for (i = 0; i < Length; ++i)
		{
			Z[i] = Mod3Product(X[XOffset + i], C);
		}
	}

#if !defined(NTRU_SPRIME_SIMPLE)
	static void VectorMod3MinusProduct(std::vector<int8_t> &Z, size_t ZOffset, const std::vector<int8_t> &X, size_t XOffset, const std::vector<int8_t> &Y, size_t YOffset, const int8_t C, size_t Length)
	{
		size_t i;

		for (i = 0; i < Length; ++i)
		{
			Z[ZOffset + i] = Mod3MinusProduct(X[XOffset + i], Y[YOffset + i], C);
		}
	}
#endif

	static void VectorMod3MinusProduct(std::vector<int8_t> &Z, const std::vector<int8_t> &X, const std::vector<int8_t> &Y, const int8_t C, size_t Length)
	{
		size_t i;

		for (i = 0; i < Length; ++i)
		{
			Z[i] = Mod3MinusProduct(X[i], Y[i], C);
		}
	}

	static void VectorMod3Shift(std::vector<int8_t> &Z, size_t ZOffset, size_t Length)
	{
		int32_t i;

		for (i = Length - 1; i > 0; --i)
		{
			Z[ZOffset + i] = Z[ZOffset + i - 1];
		}

		Z[0] = 0;
	}

	static void RqEncode(std::vector<byte> &C, const std::array<int16_t, NTRU_P> &F)
	{
		int32_t f0;
		int32_t f1;
		int32_t f2;
		int32_t f3;
		int32_t f4;
		size_t  i;

		for (i = 0; i < NTRU_P / 5; ++i)
		{
			f0 = F[(i * 5)] + NTRU_QSHIFT;
			f1 = F[(i * 5) + 1] + NTRU_QSHIFT;
			f2 = F[(i * 5) + 2] + NTRU_QSHIFT;
			f3 = F[(i * 5) + 3] + NTRU_QSHIFT;
			f4 = F[(i * 5) + 4] + NTRU_QSHIFT;
			// now want f0 + 6144*f1 + ... as a 64-bit integer
			f1 *= 3;
			f2 *= 9;
			f3 *= 27;
			f4 *= 81;
			// now want f0 + f1<<11 + f2<<22 + f3<<33 + f4<<44
			f0 += f1 << 11;
			C[(i * 8)] = f0;
			f0 >>= 8;
			C[(i * 8) + 1] = f0;
			f0 >>= 8;
			f0 += f2 << 6;
			C[(i * 8) + 2] = f0;
			f0 >>= 8;
			C[(i * 8) + 3] = f0;
			f0 >>= 8;
			f0 += f3 << 1;
			C[(i * 8) + 4] = f0;
			f0 >>= 8;
			f0 += f4 << 4;
			C[(i * 8) + 5] = f0;
			f0 >>= 8;
			C[(i * 8) + 6] = f0;
			f0 >>= 8;
			C[(i * 8) + 7] = f0;
		}

		// using p mod 5 = 1
		f0 = F[(i * 5)] + NTRU_QSHIFT;
		C[(i * 8)] = f0;
		f0 >>= 8;
		C[(i * 8) + 1] = f0;
	}

	static void RqDecode(std::array<int16_t, NTRU_P> &F, const std::vector<byte> &C, size_t COffset)
	{
		uint c0;
		uint c1;
		uint c2;
		uint c3;
		uint c4;
		uint c5;
		uint c6;
		uint c7;
		uint f0;
		uint f1;
		uint f2;
		uint f3;
		uint f4;
		size_t i;

		for (i = 0; i < NTRU_P / 5; ++i)
		{
			c0 = C[COffset + (i * 8)];
			c1 = C[COffset + (i * 8) + 1];
			c2 = C[COffset + (i * 8) + 2];
			c3 = C[COffset + (i * 8) + 3];
			c4 = C[COffset + (i * 8) + 4];
			c5 = C[COffset + (i * 8) + 5];
			c6 = C[COffset + (i * 8) + 6];
			c7 = C[COffset + (i * 8) + 7];

			/* f0 + f1*6144 + f2*6144^2 + f3*6144^3 + f4*6144^4 */
			/* = c0 + c1*256 + ... + c6*256^6 + c7*256^7 */
			/* with each F between 0 and 4590 */
			c6 += c7 << 8;
			/* c6 <= 23241 = floor(4591*6144^4/2^48) */
			/* f4 = (16/81)c6 + (1/1296)(c5+[0,1]) - [0,0.75] */
			/* claim: 2^19 f4 < x < 2^19(f4+1) */
			/* where x = 103564 c6 + 405(c5+1) */
			/* proof: x - 2^19 f4 = (76/81)c6 + (37/81)c5 + 405 - (32768/81)[0,1] + 2^19[0,0.75] */
			/* at least 405 - 32768/81 > 0 */
			/* at most (76/81)23241 + (37/81)255 + 405 + 2^19 0.75 < 2^19 */
			f4 = (103564 * c6 + 405 * (c5 + 1)) >> 19;
			c5 += c6 << 8;
			c5 -= (f4 * 81) << 4;
			c4 += c5 << 8;

			/* f0 + f1*6144 + f2*6144^2 + f3*6144^3 */
			/* = c0 + c1*256 + c2*256^2 + c3*256^3 + c4*256^4 */
			/* c4 <= 247914 = floor(4591*6144^3/2^32) */
			/* f3 = (1/54)(c4+[0,1]) - [0,0.75] */
			/* claim: 2^19 f3 < x < 2^19(f3+1) */
			/* where x = 9709(c4+2) */
			/* proof: x - 2^19 f3 = 19418 - (1/27)c4 - (262144/27)[0,1] + 2^19[0,0.75] */
			/* at least 19418 - 247914/27 - 262144/27 > 0 */
			/* at most 19418 + 2^19 0.75 < 2^19 */
			f3 = (9709 * (c4 + 2)) >> 19;
			c4 -= (f3 * 27) << 1;
			c3 += c4 << 8;

			/* f0 + f1*6144 + f2*6144^2 */
			/* = c0 + c1*256 + c2*256^2 + c3*256^3 */
			/* c3 <= 10329 = floor(4591*6144^2/2^24) */
			/* f2 = (4/9)c3 + (1/576)c2 + (1/147456)c1 + (1/37748736)c0 - [0,0.75] */
			/* claim: 2^19 f2 < x < 2^19(f2+1) */
			/* where x = 233017 c3 + 910(c2+2) */
			/* proof: x - 2^19 f2 = 1820 + (1/9)c3 - (2/9)c2 - (32/9)c1 - (1/72)c0 + 2^19[0,0.75] */
			/* at least 1820 - (2/9)255 - (32/9)255 - (1/72)255 > 0 */
			/* at most 1820 + (1/9)10329 + 2^19 0.75 < 2^19 */
			f2 = ((233017 * c3) + (910 * (c2 + 2))) >> 19;
			c2 += c3 << 8;
			c2 -= (f2 * 9) << 6;
			c1 += c2 << 8;

			/* f0 + f1*6144 */
			/* = c0 + c1*256 */
			/* c1 <= 110184 = floor(4591*6144/2^8) */
			/* f1 = (1/24)c1 + (1/6144)c0 - (1/6144)f0 */
			/* claim: 2^19 f1 < x < 2^19(f1+1) */
			/* where x = 21845(c1+2) + 85 c0 */
			/* proof: x - 2^19 f1 = 43690 - (1/3)c1 - (1/3)c0 + 2^19 [0,0.75] */
			/* at least 43690 - (1/3)110184 - (1/3)255 > 0 */
			/* at most 43690 + 2^19 0.75 < 2^19 */
			f1 = ((21845 * (c1 + 2)) + (85 * c0)) >> 19;
			c1 -= (f1 * 3) << 3;
			c0 += c1 << 8;
			f0 = c0;

			F[(i * 5)] = ModqFreeze(f0 + NTRU_Q - NTRU_QSHIFT);
			F[(i * 5) + 1] = ModqFreeze(f1 + NTRU_Q - NTRU_QSHIFT);
			F[(i * 5) + 2] = ModqFreeze(f2 + NTRU_Q - NTRU_QSHIFT);
			F[(i * 5) + 3] = ModqFreeze(f3 + NTRU_Q - NTRU_QSHIFT);
			F[(i * 5) + 4] = ModqFreeze(f4 + NTRU_Q - NTRU_QSHIFT);
		}

		c0 = C[COffset + (i * 8)];
		c1 = C[COffset + (i * 8) + 1];
		c0 += c1 << 8;
		F[(i * 5)] = ModqFreeze(c0 + NTRU_Q - NTRU_QSHIFT);
	}

	static void RqDecode(std::array<int16_t, NTRU_P> &F, const std::vector<byte> &C)
	{
		uint c0;
		uint c1;
		uint c2;
		uint c3;
		uint c4;
		uint c5;
		uint c6;
		uint c7;
		uint f0;
		uint f1;
		uint f2;
		uint f3;
		uint f4;
		size_t i;

		for (i = 0; i < NTRU_P / 5; ++i)
		{
			c0 = C[(i * 8)];
			c1 = C[(i * 8) + 1];
			c2 = C[(i * 8) + 2];
			c3 = C[(i * 8) + 3];
			c4 = C[(i * 8) + 4];
			c5 = C[(i * 8) + 5];
			c6 = C[(i * 8) + 6];
			c7 = C[(i * 8) + 7];

			/* f0 + f1*6144 + f2*6144^2 + f3*6144^3 + f4*6144^4 */
			/* = c0 + c1*256 + ... + c6*256^6 + c7*256^7 */
			/* with each F between 0 and 4590 */
			c6 += c7 << 8;
			/* c6 <= 23241 = floor(4591*6144^4/2^48) */
			/* f4 = (16/81)c6 + (1/1296)(c5+[0,1]) - [0,0.75] */
			/* claim: 2^19 f4 < x < 2^19(f4+1) */
			/* where x = 103564 c6 + 405(c5+1) */
			/* proof: x - 2^19 f4 = (76/81)c6 + (37/81)c5 + 405 - (32768/81)[0,1] + 2^19[0,0.75] */
			/* at least 405 - 32768/81 > 0 */
			/* at most (76/81)23241 + (37/81)255 + 405 + 2^19 0.75 < 2^19 */
			f4 = ((103564 * c6) + (405 * (c5 + 1))) >> 19;
			c5 += c6 << 8;
			c5 -= (f4 * 81) << 4;
			c4 += c5 << 8;

			/* f0 + f1*6144 + f2*6144^2 + f3*6144^3 */
			/* = c0 + c1*256 + c2*256^2 + c3*256^3 + c4*256^4 */
			/* c4 <= 247914 = floor(4591*6144^3/2^32) */
			/* f3 = (1/54)(c4+[0,1]) - [0,0.75] */
			/* claim: 2^19 f3 < x < 2^19(f3+1) */
			/* where x = 9709(c4+2) */
			/* proof: x - 2^19 f3 = 19418 - (1/27)c4 - (262144/27)[0,1] + 2^19[0,0.75] */
			/* at least 19418 - 247914/27 - 262144/27 > 0 */
			/* at most 19418 + 2^19 0.75 < 2^19 */
			f3 = (9709 * (c4 + 2)) >> 19;
			c4 -= (f3 * 27) << 1;
			c3 += c4 << 8;

			/* f0 + f1*6144 + f2*6144^2 */
			/* = c0 + c1*256 + c2*256^2 + c3*256^3 */
			/* c3 <= 10329 = floor(4591*6144^2/2^24) */
			/* f2 = (4/9)c3 + (1/576)c2 + (1/147456)c1 + (1/37748736)c0 - [0,0.75] */
			/* claim: 2^19 f2 < x < 2^19(f2+1) */
			/* where x = 233017 c3 + 910(c2+2) */
			/* proof: x - 2^19 f2 = 1820 + (1/9)c3 - (2/9)c2 - (32/9)c1 - (1/72)c0 + 2^19[0,0.75] */
			/* at least 1820 - (2/9)255 - (32/9)255 - (1/72)255 > 0 */
			/* at most 1820 + (1/9)10329 + 2^19 0.75 < 2^19 */
			f2 = ((233017 * c3) + (910 * (c2 + 2))) >> 19;
			c2 += c3 << 8;
			c2 -= (f2 * 9) << 6;
			c1 += c2 << 8;

			/* f0 + f1*6144 */
			/* = c0 + c1*256 */
			/* c1 <= 110184 = floor(4591*6144/2^8) */
			/* f1 = (1/24)c1 + (1/6144)c0 - (1/6144)f0 */
			/* claim: 2^19 f1 < x < 2^19(f1+1) */
			/* where x = 21845(c1+2) + 85 c0 */
			/* proof: x - 2^19 f1 = 43690 - (1/3)c1 - (1/3)c0 + 2^19 [0,0.75] */
			/* at least 43690 - (1/3)110184 - (1/3)255 > 0 */
			/* at most 43690 + 2^19 0.75 < 2^19 */
			f1 = ((21845 * (c1 + 2)) + (85 * c0)) >> 19;
			c1 -= (f1 * 3) << 3;
			c0 += c1 << 8;
			f0 = c0;

			F[(i * 5)] = ModqFreeze(f0 + NTRU_Q - NTRU_QSHIFT);
			F[(i * 5) + 1] = ModqFreeze(f1 + NTRU_Q - NTRU_QSHIFT);
			F[(i * 5) + 2] = ModqFreeze(f2 + NTRU_Q - NTRU_QSHIFT);
			F[(i * 5) + 3] = ModqFreeze(f3 + NTRU_Q - NTRU_QSHIFT);
			F[(i * 5) + 4] = ModqFreeze(f4 + NTRU_Q - NTRU_QSHIFT);
		}

		c0 = C[(i * 8)];
		c1 = C[(i * 8) + 1];
		c0 += c1 << 8;
		F[(i * 5)] = ModqFreeze(c0 + NTRU_Q - NTRU_QSHIFT);
	}

	static int R3Recip(std::array<int8_t, NTRU_P> &R, const std::array<int8_t, NTRU_P> &S)
	{
		const size_t ITRCNT = (2 * NTRU_P) + 1;

		std::vector<int8_t> f(NTRU_P + 1);
		std::vector<int8_t> g(NTRU_P + 1);
		std::vector<int8_t> u(2 * NTRU_P + 2);
		std::vector<int8_t> v(2 * NTRU_P + 2);
		size_t i;
		size_t loop;
		int32_t d;
		int32_t e;
		int32_t swapmask;
		int8_t c;

		f[0] = -1;
		f[1] = -1;
		f[NTRU_P] = 1;

		for (i = 0; i < NTRU_P; ++i)
		{
			g[i] = S[i];
		}

		g[NTRU_P] = 0;
		v[0] = 1;
		d = NTRU_P;
		e = NTRU_P;
		loop = 0;

		while (loop < ITRCNT)
		{
			/* e == -1 or d + e + loop <= 2*p */
			/* f has degree p: i.e., f[p]!=0 */
			/* f[i]==0 for i < p-d */
			/* g has degree <=p (so it fits in p+1 coefficients) */
			/* g[i]==0 for i < p-e */
			/* u has degree <=loop (so it fits in loop+1 coefficients) */
			/* u[i]==0 for i < p-d */
			/* if invertible: u[i]==0 for i < loop-p (so can look at just p+1 coefficients) */
			/* v has degree <=loop (so it fits in loop+1 coefficients) */
			/* v[i]==0 for i < p-e */
			/* v[i]==0 for i < loop-p (so can look at just p+1 coefficients) */

			c = Mod3Quotient(g[NTRU_P], f[NTRU_P]);
			VectorMod3MinusProduct(g, g, f, c, NTRU_P + 1);
			VectorMod3Shift(g, 0, NTRU_P + 1);


#if defined(NTRU_SPRIME_SIMPLE)
			VectorMod3MinusProduct(v, v, u, c, ITRCNT + 1);
			VectorMod3Shift(v, 0, ITRCNT + 1);
#else
			if (loop < NTRU_P)
			{
				VectorMod3MinusProduct(v, v, u, c, loop + 1);
				VectorMod3Shift(v, 0, loop + 2);
			}
			else
			{
				VectorMod3MinusProduct(v, loop - NTRU_P, v, loop - NTRU_P, u, loop - NTRU_P, c, NTRU_P + 1);
				VectorMod3Shift(v, loop - NTRU_P, NTRU_P + 2);
			}
#endif

			++loop;
			e -= 1;

			swapmask = SmallerMask(e, d) & Mod3NonZeroMask(g[NTRU_P]);
			Swap32(e, d, swapmask);
			Swap(f, 0, g, 0, NTRU_P + 1, swapmask);


#if defined(NTRU_SPRIME_SIMPLE)
			Swap(u, 0, v, 0, ITRCNT + 1, swapmask);
#else
			if (loop < NTRU_P)
			{
				Swap(u, 0, v, 0, loop + 1, swapmask);
			}
			else
			{
				Swap(u, loop - NTRU_P, v, loop - NTRU_P, NTRU_P + 1, swapmask);
			}
#endif
		}

		c = Mod3Reciprocal(f[NTRU_P]);
		VectorMod3Product(R, u, NTRU_P, c, NTRU_P);

		return SmallerMask(0, d);
	}

	static void VectorModqProduct(std::array<int16_t, NTRU_P> &Z, const std::vector<int16_t> &X, size_t XOffset, size_t Length, const int16_t C)
	{
		size_t i;

		for (i = 0; i < Length; ++i)
		{
			Z[i] = ModqProduct(X[XOffset + i], C);
		}
	}

	static void VectorModqMinusProduct(std::vector<int16_t> &Z, const std::vector<int16_t> &X, const std::vector<int16_t> &Y, size_t Length, const int16_t C)
	{
		size_t i;

		for (i = 0; i < Length; ++i)
		{
			Z[i] = ModqMinusProduct(X[i], Y[i], C);
		}
	}

#if !defined(NTRU_SPRIME_SIMPLE)

	static void VectorModqMinusProduct(std::vector<int16_t> &Z, size_t ZOffset, const std::vector<int16_t> &X, size_t XOffset, const std::vector<int16_t> &Y, size_t YOffset, size_t Length, const int16_t C)
	{
		size_t i;

		for (i = 0; i < Length; ++i)
		{
			Z[ZOffset + i] = ModqMinusProduct(X[XOffset + i], Y[YOffset + i], C);
		}
	}

#endif

	static void VectorModqShift(std::vector<int16_t> &Z, size_t ZOffset, size_t Length)
	{
		int32_t i;

		for (i = Length - 1; i > 0; --i)
		{
			Z[ZOffset + i] = Z[ZOffset + i - 1];
		}

		Z[0] = 0;
	}

	static int RqRecip3(std::array<int16_t, NTRU_P> &R, const std::array<int8_t, NTRU_P> &S)
	{
		/*
		r = (3s)^(-1) mod m, returning 0, if s is invertible mod m
		or returning -1 if s is not invertible mod m
		r,s are polys of degree <p
		m is x^p-x-1
		*/
		const size_t ITRCNT = 2 * NTRU_P + 1;

		std::vector<int16_t> f(NTRU_P + 1);
		std::vector<int16_t> g(NTRU_P + 1);
		std::vector<int16_t> u(2 * NTRU_P + 2);
		std::vector<int16_t> v(2 * NTRU_P + 2);
		size_t i;
		size_t loop;
		int32_t d;
		int32_t e;
		int32_t swapmask;
		int16_t c;

		for (i = 2; i < NTRU_P; ++i)
		{
			f[i] = 0;
		}

		f[0] = -1;
		f[1] = -1;
		f[NTRU_P] = 1;

		/* generalization: can initialize f to any polynomial m */
		/* requirements: m has degree exactly p, nonzero constant coefficient */
		for (i = 0; i < NTRU_P; ++i)
		{
			g[i] = 3 * S[i];
		}

		g[NTRU_P] = 0;

		for (i = 0; i <= ITRCNT; ++i)
		{
			u[i] = 0;
		}

		v[0] = 1;

		for (i = 1; i <= ITRCNT; ++i)
		{
			v[i] = 0;
		}

		d = NTRU_P;
		e = NTRU_P;
		loop = 0;

		while (loop < ITRCNT)
		{
			/* e == -1 or d + e + loop <= 2*p */
			/* f has degree p: i.e., f[p]!=0 */
			/* f[i]==0 for i < p-d */
			/* g has degree <=p (so it fits in p+1 coefficients) */
			/* g[i]==0 for i < p-e */
			/* u has degree <=loop (so it fits in loop+1 coefficients) */
			/* u[i]==0 for i < p-d */
			/* if invertible: u[i]==0 for i < loop-p (so can look at just p+1 coefficients) */
			/* v has degree <=loop (so it fits in loop+1 coefficients) */
			/* v[i]==0 for i < p-e */
			/* v[i]==0 for i < loop-p (so can look at just p+1 coefficients) */

			c = ModqQuotient(g[NTRU_P], f[NTRU_P]);
			VectorModqMinusProduct(g, g, f, NTRU_P + 1, c);
			VectorModqShift(g, 0, NTRU_P + 1);

#ifdef NTRU_SPRIME_SIMPLE
			VectorModqMinusProduct(v, v, u, ITRCNT + 1, c);
			VectorModqShift(v, 0, ITRCNT + 1);
#else
			if (loop < NTRU_P)
			{
				VectorModqMinusProduct(v, v, u, loop + 1, c);
				VectorModqShift(v, 0, loop + 2);
			}
			else
			{
				VectorModqMinusProduct(v, loop - NTRU_P, v, loop - NTRU_P, u, loop - NTRU_P, NTRU_P + 1, c);
				VectorModqShift(v, loop - NTRU_P, NTRU_P + 2);
			}
#endif

			e -= 1;
			++loop;
			swapmask = SmallerMask(e, d) & ModqNonZeroMask(g[NTRU_P]);
			Swap32(e, d, swapmask);
			Swap(f, 0, g, 0, NTRU_P + 1, swapmask);

#ifdef NTRU_SPRIME_SIMPLE
			Swap(u, 0, v, 0, ITRCNT + 1, swapmask);
#else
			if (loop < NTRU_P)
			{
				Swap(u, 0, v, 0, loop + 1, swapmask);
			}
			else
			{
				Swap(u, loop - NTRU_P, v, loop - NTRU_P, NTRU_P + 1, swapmask);
			}
#endif
		}

		c = ModqReciprocal(f[NTRU_P]);
		VectorModqProduct(R, u, NTRU_P, NTRU_P, c);

		return SmallerMask(0, d);
	}

	static int32_t Verify32(const std::vector<byte> &X, const std::vector<byte> &Y)
	{
		uint diff = 0;
		size_t i;

		for (i = 0; i < 32; ++i)
		{
			diff |= X[i] ^ Y[i];
		}

		return (1 & ((diff - 1) >> 8)) - 1;
	}

public:

	static void SelfTest()
	{
		std::vector<byte> msg1(NTRU_SEED_SIZE);
		std::vector<byte> msg2(NTRU_SEED_SIZE);
		std::vector<byte> ct(NTRU_CIPHERTEXT_SIZE);
		std::vector<byte> pk(NTRU_PUBLICKEY_SIZE);
		std::vector<byte> sk(NTRU_PRIVATEKEY_SIZE);

		Prng::IPrng* rng = new Prng::CSR();
		std::unique_ptr<Prng::IPrng> rngP(rng);

		Generate(pk, sk, rngP);

		rng->GetBytes(msg1);
		Encrypt(msg1, ct, pk, rngP);

		Decrypt(msg2, ct, sk);

		if (msg1 != msg2)
		{
			throw;
		}
	}

	static int Decrypt(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey)
	{
		std::array<int16_t, NTRU_P> c;
		std::array<int16_t, NTRU_P> h;
		std::array<int16_t, NTRU_P> hr;
		std::array<int16_t, NTRU_P> t;
		std::array<int8_t, NTRU_P> f;
		std::array<int8_t, NTRU_P> grecip;
		std::array<int8_t, NTRU_P> r;
		std::array<int8_t, NTRU_P> t3;
		std::vector<byte> hash(64);
		std::vector<byte> rstr(NTRU_SMALLENCODE_SIZE);
		size_t i;
		int32_t result;
		int32_t weight;

		SmallDecode(f, PrivateKey, 0);
		SmallDecode(grecip, PrivateKey, NTRU_SMALLENCODE_SIZE);
		RqDecode(h, PrivateKey, 2 * NTRU_SMALLENCODE_SIZE);
		RqDecodeRounded(c, CipherText, 32);
		RqMult(t, c, f);

		for (i = 0; i < NTRU_P; ++i)
		{
			t3[i] = Mod3Freeze(ModqFreeze(3 * t[i]));
		}

		R3Mult(r, t3, grecip);
		R3Mult(r, t3, grecip);

		weight = 0;
		for (i = 0; i < NTRU_P; ++i)
		{
			weight += (1 & r[i]);
		}
		weight -= NTRU_W;

		/* XXX: puts limit on p */
		result = 0;
		result |= ModqNonZeroMask(weight);
		RqMult(hr, h, r);
		RqRound3(hr, hr);

		for (i = 0; i < NTRU_P; ++i)
		{
			result |= ModqNonZeroMask(hr[i] - c[i]);
		}

		SmallEncode(rstr, 0, r);
		Digest::Keccak512 dgt;
		dgt.Compute(rstr, hash);

		result |= Verify32(hash, CipherText);

		for (i = 0; i < 32; ++i)
		{
			Secret[i] = (hash[32 + i] & ~result);
		}

		return result;
	}

	static void Encrypt(std::vector<byte> &Secret, std::vector<byte> &CipherText, const std::vector<byte> &PublicKey, std::unique_ptr<Prng::IPrng> &Rng)
	{
		std::array<int16_t, NTRU_P> h;
		std::array<int16_t, NTRU_P> c;
		std::array<int8_t, NTRU_P> r;
		std::vector<uint8_t> rstr(NTRU_SMALLENCODE_SIZE);
		std::vector<uint8_t> hash(64);

		SmallRandomWeightW(r, Rng);
		SmallEncode(rstr, 0, r);
		Digest::Keccak512 dgt;
		dgt.Compute(rstr, hash);

		RqDecode(h, PublicKey);
		RqMult(c, h, r);
		RqRound3(c, c);

		std::memcpy(Secret.data(), hash.data() + 32, 32);
		std::memcpy(CipherText.data(), hash.data(), 32);

		RqEncodeRounded(CipherText, 32, c);
	}

	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
	{
		std::array<int16_t, NTRU_P> f3recip;
		std::array<int16_t, NTRU_P> h;
		std::array<int8_t, NTRU_P> f;
		std::array<int8_t, NTRU_P> g;
		std::array<int8_t, NTRU_P> grecip;

		do
		{
			SmallRandom(g, Rng);
		} 
		while (R3Recip(grecip, g) != 0);

		SmallRandomWeightW(f, Rng);
		RqRecip3(f3recip, f);
		RqMult(h, f3recip, g);

		RqEncode(PublicKey, h);
		SmallEncode(PrivateKey, 0, f);
		SmallEncode(PrivateKey, NTRU_SMALLENCODE_SIZE, grecip);
		std::memcpy((uint8_t*)PrivateKey.data() + 2 * NTRU_SMALLENCODE_SIZE, (uint8_t*)PublicKey.data(), NTRU_RQENCODE_SIZE);
	}
};

NAMESPACE_NTRUEND
#endif
