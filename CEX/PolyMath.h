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

#ifndef CEX_POLYMATH_H
#define CEX_POLYMATH_H

#include "CexDomain.h"

#if defined(__AVX512__)
#	include "UInt512.h"
#elif defined(__AVX2__)
#	include "UInt256.h"
#elif defined(__AVX__)
#	include "UInt128.h"
#endif

NAMESPACE_UTILITY

/// 
/// internal
/// 

/// <summary>
/// Internal class used by RingLWE
/// </summary>
class PolyMath
{
private:

	static const int Q = 12289;
	static const uint QINV = 12287;
	static const uint RLOG = 18;

public:

	inline static ushort BarrettReduce(ushort X)
	{
		uint u;
		u = (static_cast<uint>(X * 5) >> 16);
		u *= Q;
		X -= u;

		return X;
	}

	inline static ushort MontgomeryReduce(uint X)
	{
		uint u;
		u = (X * QINV);
		u &= ((1 << RLOG) - 1);
		u *= Q;
		X = X + u;

		return static_cast<ushort>(X >> RLOG);
	}

	template <class T>
	inline static T Abs(T &V)
	{
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		return T::Abs(V);
#else
		T mask = V >> ((sizeof(T) * 8) - 1);
		return (V ^ mask) - mask;
#endif
	}

	template <typename Array, class T>
	inline static void Add(Array &R, const Array &A, const Array &B, int Q)
	{
		const T VN(5);

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		const size_t ULVSZE = T::size() / sizeof(uint);
		std::array<uint, ULVSZE> tmpR;
		const T NQ(Q);
		T tmpA, tmpB;
#else
		const size_t ULVSZE = 1;
#endif

		for (size_t i = 0; i < R.size(); i += ULVSZE)
		{
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
#	if defined(__AVX512__)
			tmpA.Load(A[i + 15], A[i + 14], A[i + 13], A[i + 12], A[i + 11], A[i + 10], A[i + 9], A[i + 8], A[i + 7], A[i + 6], A[i + 5], A[i + 4], A[i + 3], A[i + 2], A[i + 1], A[i]);
			tmpB.Load(B[i + 15], B[i + 14], B[i + 13], B[i + 12], B[i + 11], B[i + 10], B[i + 9], B[i + 8], B[i + 7], B[i + 6], B[i + 5], B[i + 4], B[i + 3], B[i + 2], B[i + 1], B[i]);
#	elif defined(__AVX2__)
			tmpA.Load(A[i + 7], A[i + 6], A[i + 5], A[i + 4], A[i + 3], A[i + 2], A[i + 1], A[i]);
			tmpB.Load(B[i + 7], B[i + 6], B[i + 5], B[i + 4], B[i + 3], B[i + 2], B[i + 1], B[i]);
#	elif defined(__AVX__) 
			tmpA.Load(A[i + 3], A[i + 2], A[i + 1], A[i]);
			tmpB.Load(B[i + 3], B[i + 2], B[i + 1], B[i]);
#	endif

			T VF(tmpA + tmpB);
			T VU = (VF * VN) >> 16;
			VU *= NQ;
			VF -= VU;
			VF.Store(tmpR, 0);

			for (size_t j = 0; j < ULVSZE; ++j)
			{
				R[j + i] = static_cast<ushort>(tmpR[j]);
			}
#else
			T F = A[i] + B[i];
			uint U = static_cast<uint>(F * VN) >> 16;
			U *= Q;
			F -= U;
			R[i] = F;
#endif
		}
	}

	template <typename ArrayA, typename ArrayB>
	inline static void BitReverse(ArrayA &P, ArrayB &RevTable)
	{
		uint r;
		ushort tmp;

		for (size_t i = 0; i < P.size(); ++i)
		{
			r = RevTable[i];
			if (i < r)
			{
				tmp = P[i];
				P[i] = P[r];
				P[r] = tmp;
			}
		}
	}

	template <typename Array, class T>
	inline static void Mul(Array &R, const Array &Factors, int Q, uint QInv, uint RLog)
	{
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		const size_t ULVSZE = T::size() / sizeof(uint);
		std::array<uint, ULVSZE> tmpR;
		T tmpP, tmpF;
#else
		const size_t ULVSZE = 1;
#endif

		for (size_t i = 0; i < R.size(); i += ULVSZE)
		{
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
#	if defined(__AVX512__)
			tmpP.Load(R[i + 15], R[i + 14], R[i + 13], R[i + 12], R[i + 11], R[i + 10], R[i + 9], R[i + 8], R[i + 7], R[i + 6], R[i + 5], R[i + 4], R[i + 3], R[i + 2], R[i + 1], R[i]);
			tmpF.Load(Factors[i + 15], Factors[i + 14], Factors[i + 13], Factors[i + 12], Factors[i + 11], Factors[i + 10], Factors[i + 9], Factors[i + 8], Factors[i + 7], Factors[i + 6], Factors[i + 5], Factors[i + 4], Factors[i + 3], Factors[i + 2], Factors[i + 1], Factors[i]);
#	elif defined(__AVX2__)
			tmpP.Load(R[i + 7], R[i + 6], R[i + 5], R[i + 4], R[i + 3], R[i + 2], R[i + 1], R[i]);
			tmpF.Load(Factors[i + 7], Factors[i + 6], Factors[i + 5], Factors[i + 4], Factors[i + 3], Factors[i + 2], Factors[i + 1], Factors[i]);
#	elif defined(__AVX__) 
			tmpP.Load(R[i + 3], R[i + 2], R[i + 1], R[i]);
			tmpF.Load(Factors[i + 3], Factors[i + 2], Factors[i + 1], Factors[i]);
#	endif

			T a = tmpP * tmpF;
			T u = (a * T(QInv));
			u &= ((T::ONE() << RLog) - T::ONE());
			u *= T(Q);
			a += u;
			a >>= 18;
			a.Store(tmpR, 0);

			for (size_t j = 0; j < ULVSZE; ++j)
			{
				R[j + i] = static_cast<ushort>(tmpR[j]);
			}
#else
			T a = R[i] * Factors[i];
			T u = (a * QInv);
			u &= ((1 << RLog) - 1);
			u *= Q;
			a += u;
			R[i] = a >> 18;
#endif
		}
	}
};

NAMESPACE_UTILITYEND
#endif

