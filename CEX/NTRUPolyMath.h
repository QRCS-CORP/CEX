// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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

#ifndef CEX_NTRUPOLYMATH_H
#define CEX_NTRUPOLYMATH_H

#include "CexDomain.h"
#include "MemoryTools.h"

NAMESPACE_NTRUPRIME

using Tools::MemoryTools;

/// 
/// internal
/// 

/// <summary>
/// The NTRU-Prime math functions
/// </summary>
class NTRUPolyMath
{
public:

	//~~~Inline~~~//

	inline static int8_t F3Freeze(int16_t X)
	{
		// F3 is always represented as -1,0,1
		// so ZZ_fromF3 is a no-op
		// x must not be close to top int16

		return static_cast<int8_t>(I32ModU14(X + 1, 3) - 1);
	}

	inline static int16_t FqFreeze(int32_t X, int32_t Q)
	{
		const int32_t Q12 = ((Q - 1) / 2);

		// x must not be close to top int32
		return static_cast<int16_t>(I32ModU14(X + Q12, Q) - Q12);
	}

	inline static int32_t I16NegativeMask(int16_t X)
	{
		// return -1 if x<0; otherwise return 0
		ushort u;

		u = X;
		u >>= 15;

		// alternative with gcc -fwrapv:
		// x>>15 compiles to CPU's arithmetic right shift
		return -static_cast<int32_t>(u);
	}

	inline static int32_t I16NonZeroMask(int16_t X)
	{
		// return -1 if x!=0; else return 0
		ushort u;
		uint v;

		u = X;
		v = u;
		// 0, else 2^32-65535...2^32-1
		v = ~v + 1;
		// 0, else 1
		v >>= 31;

		// 0, else -1
		return -static_cast<int32_t>(v);
	}

	inline static int32_t I32DivU14(int32_t X, ushort M)
	{
		int32_t qt;
		ushort r;

		I32DivModU14(qt, r, X, M);

		return qt;
	}

	inline static void I32DivModU14(int32_t &Q, ushort &R, int32_t X, ushort M)
	{
		uint mask;
		uint uq;
		uint uq2;
		ushort ur;
		ushort ur2;

		U32DivModU14(uq, ur, 0x80000000UL + static_cast<uint>(X), M);
		U32DivModU14(uq2, ur2, 0x80000000UL, M);
		ur -= ur2;
		uq -= uq2;
		mask = ~static_cast<uint>(ur >> 15) + 1;
		ur += mask & M;
		uq += mask;
		R = ur;
		Q = uq;
	}

	inline static ushort I32ModU14(int32_t X, ushort M)
	{
		int32_t qt;
		ushort r;

		I32DivModU14(qt, r, X, M);

		return r;
	}

	//~~~Templates~~~//

	template <typename ArrayU32>
	static void MinMax(ArrayU32 &X, size_t XOffset, ArrayU32 &Y, size_t YOffset)
	{
		uint xi;
		uint yi;
		uint xy;
		uint c;

		xi = X[XOffset];
		yi = Y[YOffset];
		xy = xi ^ yi;
		c = yi - xi;

		c ^= xy & (c ^ yi ^ 0x80000000UL);
		c >>= 31;
		c = ~c + 1;
		c &= xy;
		X[XOffset] = xi ^ c;
		Y[YOffset] = yi ^ c;
	}

	template <typename ArrayU32>
	static void U32Sort(ArrayU32 &X, int32_t N)
	{
		size_t i;
		size_t pt;
		size_t qt;
		size_t top;

		if (N > 1)
		{
			top = 1;

			while (top < N - top)
			{
				top += top;
			}

			for (pt = top; pt > 0; pt >>= 1)
			{
				for (i = 0; i < N - pt; ++i)
				{
					if ((i & pt) == 0)
					{
						MinMax(X, i, X, i + pt);
					}
				}

				for (qt = top; qt > pt; qt >>= 1)
				{
					for (i = 0; i < N - qt; ++i)
					{
						if ((i & pt) == 0)
						{
							MinMax(X, i + pt, X, i + qt);
						}
					}
				}
			}
		}
	}

	//~~~Static Functions~~~//

	static void Decode(std::vector<ushort> &Output, size_t OutOffset, const std::vector<byte> &S, size_t SOffset, const std::vector<ushort> &M, size_t Length);
	static void Decrypt(std::vector<int8_t> &R, const std::vector<int16_t> &C, const std::vector<int8_t> &F, const std::vector<int8_t> &GInv, int32_t Q, int32_t W);
	static void Encode(std::vector<byte> &Output, size_t OutOffset, const std::vector<ushort> &R, const std::vector<ushort> &M, size_t Length);
	static void Encrypt(std::vector<int16_t> &C, const std::vector<int8_t> &R, const std::vector<int16_t> &H, int32_t Q);
	static int16_t FqRecip(int16_t A1, int32_t Q);
	static int R3Recip(std::vector<int8_t> &Output, const std::vector<int8_t> &Input);
	static void R3FromRq(std::vector<int8_t> &Output, const std::vector<int16_t> &R);
	static void R3Mult(std::vector<int8_t> &H, const std::vector<int8_t> &F, const std::vector<int8_t> &G);
	static void RqMult3(std::vector<int16_t> &H, const std::vector<int16_t> &F, int32_t Q);
	static void RqMultSmall(std::vector<int16_t> &H, const std::vector<int16_t> &F, const std::vector<int8_t> &G, int32_t Q);
	static void Round(std::vector<int16_t> &Output, const std::vector<int16_t> &A);
	static void RoundedDecode(std::vector<int16_t> &R, const std::vector<byte> &S, int32_t Q);
	static void RoundedEncode(std::vector<byte> &S, const std::vector<int16_t> &R, int32_t Q);
	static void RqDecode(std::vector<int16_t> &R, const std::vector<byte> &S, int32_t Q);
	static void RqEncode(std::vector<byte> &S, const std::vector<int16_t> &R, int32_t Q);
	static int32_t RqRecip3(std::vector<int16_t> &Output, const std::vector<int8_t> &Input, int32_t Q);
	static void SmallDecode(std::vector<int8_t> &F, const std::vector<byte> &S, size_t SOffset);
	static void SmallEncode(std::vector<byte> &S, size_t SOffset, const std::vector<int8_t> &F);
	static uint U32DivU14(uint X, ushort M);
	static void U32DivModU14(uint& Q, ushort &R, uint X, ushort M);
	static ushort U32ModU14(uint X, ushort M);
	static int32_t WeightWMask(std::vector<int8_t> &R, int32_t W);
};

NAMESPACE_NTRUPRIMEEND
#endif
