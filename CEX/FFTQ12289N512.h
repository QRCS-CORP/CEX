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

#ifndef CEX_FFTQ12289N512_H
#define CEX_FFTQ12289N512_H

#include "CexDomain.h"
#include "IPrng.h"
#include "PolyMath.h"

NAMESPACE_RINGLWE

/// 
/// internal
/// 

/// <summary>
/// The RingLWE FFT using a modulus of 12289 with 1024 coefficients
/// </summary>
class FFTQ12289N512
{
public:

	//~~~Public Constants~~~//

	/// <summary>
	/// The number of coefficients
	/// </summary>
	static const uint N = 512;

	/// <summary>
	/// The modulus factor
	/// </summary>
	static const int Q = 12289;

	/// <summary>
	/// The byte size of A's public key polynomial
	/// </summary>
	static const size_t POLY_BYTES = 896;

	/// <summary>
	/// The byte size of B's encrypted seed array
	/// </summary>
	static const size_t RECD_BYTES = 256;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	static const size_t SEED_BYTES = 32;

	/// <summary>
	/// The byte size of the public key polynomial
	/// </summary>
	static const size_t PUBKEY_SIZE = POLY_BYTES + SEED_BYTES;

	/// <summary>
	/// The byte size of the private key polynomial
	/// </summary>
	static const size_t PRIKEY_SIZE = N;

	/// <summary>
	/// The byte size of B's reply message to host A
	/// </summary>
	static const size_t CPRTXT_SIZE = POLY_BYTES + RECD_BYTES;

	/// <summary>
	/// The parameter sets formal name
	/// </summary>
	static const std::string Name;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a cipher-text
	/// </summary>
	/// 
	/// <param name="Secret">The shared secret</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Received">The received ciphertext</param>
	static void Decrypt(std::vector<byte> &Secret, const std::vector<ushort> &PrivateKey, const std::vector<byte> &Received);

	/// <summary>
	/// Encrypt a message
	/// </summary>
	/// 
	/// <param name="Secret">The secret message</param>
	/// <param name="Send">The ciphertext output</param>
	/// <param name="Received">The public asymmetric key</param>
	/// <param name="Rng">The random provider</param>
	/// <param name="Parallel">Run in parallel or sequential mode</param>
	static void Encrypt(std::vector<byte> &Secret, std::vector<byte> &Send, const std::vector<byte> &Received, std::unique_ptr<Prng::IPrng> &Rng, bool Parallel);

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	///
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Rng">The random provider</param>
	/// <param name="Parallel">Run in parallel or sequential mode</param>
	static void Generate(std::vector<byte> &PublicKey, std::vector<ushort> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, bool Parallel);

private:

	static const std::array<ushort, 512> BitrevTable;
	static const std::array<ushort, 256> OmegasMontgomery;
	static const std::array<ushort, 256> OmegasInvMontgomery;
	static const std::array<ushort, 512> PsisBitrevMontgomery;
	static const std::array<ushort, 512> PsisInvMontgomery;

	//~~~Inlined~~~//

	inline static void NTTEvenDist(ushort &A, ushort &B, const ushort Omega)
	{
		uint tmpW = Omega * ((A + (3 * Q)) - B);
		A += B;
		B = Utility::PolyMath::MontgomeryReduce(tmpW);
	}

	inline static void NTTOddDist(ushort &A, ushort &B, const ushort Omega)
	{
		uint tmpW = Omega * ((A + (3 * Q)) - B);
		ushort tmpB = A + B;
		A = Utility::PolyMath::BarrettReduce(tmpB);
		B = Utility::PolyMath::MontgomeryReduce(tmpW);
	}

	//~~~Templates~~~//

	template <typename Vector>
	inline static Vector CalcK(Vector &V0, Vector &V1, Vector &X, int Q)
	{
		const Vector NQ(Q);
		const Vector N1(1);
		Vector xit;
		Vector tmpT;
		Vector tmpR;
		Vector tmpB;

		tmpB = X * Vector(2730);
		tmpT = tmpB >> 25;
		tmpB = X - tmpT * NQ;
		tmpB = Vector(12288) - tmpB;
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		tmpB = Vector::ShiftRA(tmpB, 31);
#else
		tmpB >>= 31;
#endif
		tmpT -= tmpB;
		tmpR = tmpT & N1;
		xit = (tmpT >> 1);
		V0 = xit + tmpR;
		tmpT -= N1;
		tmpR = tmpT & N1;
		V1 = (tmpT >> 1) + tmpR;
		Vector v = X - (V0 * Vector(2) * NQ);

		return Utility::PolyMath::Abs<Vector>(v);
	}

	template <typename Vector>
	inline static Vector Decode(Vector &X, const int Q)
	{
		Vector tmpT;
		Vector tmpC;
		Vector tmpB;

		tmpB = X * Vector(2730);
		tmpT = tmpB >> 27;
		tmpB = X - tmpT * Vector(49156);
		tmpB = Vector(49155) - tmpB;
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		tmpB = Vector::ShiftRA(tmpB, 31);
#else
		tmpB >>= 31;
#endif
		tmpT -= tmpB;
		tmpC = tmpT & Vector(1);
		tmpT >>= 1;
		tmpT += tmpC;
		tmpT *= (Vector(8) * Vector(Q));
		tmpT -= X;

		return Utility::PolyMath::Abs<Vector>(tmpT);
	}

	template <typename Array>
	inline static void FwdNTT(Array &A)
	{
		size_t dist;
		size_t i; 
		size_t j; 
		size_t jt;
		size_t k;

		for (size_t i = 0; i < A.size(); ++i)
		{
			A[i] = Utility::PolyMath::MontgomeryReduce((A[i] * PsisBitrevMontgomery[i]));
		}

		for (i = 0; i < 9; i += 2)
		{
			dist = (static_cast<ulong>(1) << i);

			for (j = 0; j < dist; j++)
			{
				for (k = j, jt = 0; k < N - 1; k += 2 * dist, jt++)
				{
					NTTEvenDist(A[k], A[k + dist], OmegasMontgomery[jt]);
				}
			}

			if (i + 1 < 9)
			{
				dist <<= 1;

				for (j = 0; j < dist; j++)
				{
					for (k = j, jt = 0; k < N - 1; k += 2 * dist, jt++)
					{
						NTTOddDist(A[k], A[k + dist], OmegasMontgomery[jt]);
					}
				}
			}
		}
	}

	template <typename Array>
	inline static void InvNTT(Array &R)
	{
		size_t dist;
		size_t i;
		size_t j;
		size_t jt;
		size_t k;

		for (i = 0; i < 9; i += 2)
		{
			dist = (static_cast<ulong>(1) << i);

			for (j = 0; j < dist; j++)
			{
				for (k = j, jt = 0; k < N - 1; k += 2 * dist, jt++)
				{
					NTTEvenDist(R[k], R[k + dist], OmegasInvMontgomery[jt]);
				}
			}

			if (i + 1 < 9)
			{
				dist <<= 1;

				for (j = 0; j < dist; j++)
				{
					for (k = j, jt = 0; k < N - 1; k += 2 * dist, jt++)
					{
						NTTOddDist(R[k], R[k + dist], OmegasInvMontgomery[jt]);
					}
				}
			}
		}

		for (size_t i = 0; i < R.size(); ++i)
		{
			R[i] = Utility::PolyMath::MontgomeryReduce((R[i] * PsisInvMontgomery[i]));
		}
	}

	template <typename Vector, typename ArrayA, typename ArrayB>
	inline static void GetNoise(ArrayA &R, ArrayB &Random, int Q)
	{
		Vector tmpA;
		Vector tmpB;
		Vector tmpR;
		const Vector AIBMASK(0x01010101);
		const Vector BITMASK(0xFF);

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		const Vector NQ(Q);
		const size_t ULVSZE = Vector::size() / sizeof(uint);
		std::vector<uint> tmpU(ULVSZE);
#else
		const size_t ULVSZE = 1;
#endif

		for (size_t i = 0; i < R.size(); i += ULVSZE)
		{
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
			tmpR.Load(Random, i);
#else
			tmpR = Random[i];
#endif
			Vector d(0);

			for (int j = 0; j < 8; ++j)
			{
				d += (tmpR >> j) & AIBMASK;
			}

			tmpA = ((d >> 8) & BITMASK) + (d & BITMASK);
			tmpB = (d >> 24) + ((d >> 16) & BITMASK);

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
			Vector vR(tmpA + NQ - tmpB);
			vR.Store(tmpU, 0);

			for (size_t j = 0; j < ULVSZE; ++j)
			{
				R[j + i] = static_cast<ushort>(tmpU[j]);
			}
#else
			R[i] = tmpA + Q - tmpB;
#endif
		}
	}

	template <typename Vector, typename ArrayA, typename ArrayB>
	inline static void HelpRec(ArrayA &C, const ArrayA &V, ArrayB &Random, int Q)
	{
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		const Vector NQ(Q);
		const Vector N1(1);
		const Vector N2(2);
		const Vector N3(3);
		const Vector N4(4);
		const Vector N8(8);
		const size_t ULVSZE = Vector::size() / sizeof(uint);
		Vector tmpK;
		Vector tmpR;
		Vector c0;
		Vector c1;
		Vector c2;
		Vector c3;
		Vector t0;
		Vector t1;
		Vector t2;
		Vector t3;
		std::array<Vector, 4> v0;
		std::array<Vector, 4> v1;
		std::array<Vector, 4> tmpV;
		std::vector<int> tmpC(ULVSZE * 4);

		for (size_t i = 0; i < V.size() / 4; i += ULVSZE)
		{
#	if defined(__AVX512__)
			tmpR.Load(static_cast<byte>((Random[i >> 3] >> (i & 7)) & 1), static_cast<byte>((Random[(i + 1) >> 3] >> ((i + 1) & 7)) & 1), static_cast<byte>((Random[(i + 2) >> 3] >> ((i + 2) & 7)) & 1), static_cast<byte>((Random[(i + 3) >> 3] >> ((i + 3) & 7)) & 1),
				static_cast<byte>((Random[(i + 4) >> 3] >> ((i + 4) & 7)) & 1), static_cast<byte>((Random[(i + 5) >> 3] >> ((i + 5) & 7)) & 1), static_cast<byte>((Random[(i + 6) >> 3] >> ((i + 6) & 7)) & 1), static_cast<byte>((Random[(i + 7) >> 3] >> ((i + 7) & 7)) & 1),
				static_cast<byte>((Random[(i + 8) >> 3] >> ((i + 8) & 7)) & 1), static_cast<byte>((Random[(i + 9) >> 3] >> ((i + 9) & 7)) & 1), static_cast<byte>((Random[(i + 10) >> 3] >> ((i + 10) & 7)) & 1), static_cast<byte>((Random[(i + 11) >> 3] >> ((i + 11) & 7)) & 1),
				static_cast<byte>((Random[(i + 12) >> 3] >> ((i + 12) & 7)) & 1), static_cast<byte>((Random[(i + 13) >> 3] >> ((i + 13) & 7)) & 1), static_cast<byte>((Random[(i + 14) >> 3] >> ((i + 14) & 7)) & 1), static_cast<byte>((Random[(i + 15) >> 3] >> ((i + 15) & 7)) & 1));
#	elif defined(__AVX2__)
			tmpR.Load(static_cast<byte>((Random[i >> 3] >> (i & 7)) & 1), static_cast<byte>((Random[(i + 1) >> 3] >> ((i + 1) & 7)) & 1), static_cast<byte>((Random[(i + 2) >> 3] >> ((i + 2) & 7)) & 1), static_cast<byte>((Random[(i + 3) >> 3] >> ((i + 3) & 7)) & 1),
				static_cast<byte>((Random[(i + 4) >> 3] >> ((i + 4) & 7)) & 1), static_cast<byte>((Random[(i + 5) >> 3] >> ((i + 5) & 7)) & 1), static_cast<byte>((Random[(i + 6) >> 3] >> ((i + 6) & 7)) & 1), static_cast<byte>((Random[(i + 7) >> 3] >> ((i + 7) & 7)) & 1));
#	elif defined(__AVX__)
			tmpR.Load(static_cast<byte>((Random[i >> 3] >> (i & 7)) & 1), static_cast<byte>((Random[(i + 1) >> 3] >> ((i + 1) & 7)) & 1), static_cast<byte>((Random[(i + 2) >> 3] >> ((i + 2) & 7)) & 1), static_cast<byte>((Random[(i + 3) >> 3] >> ((i + 3) & 7)) & 1));
#	endif 

			t0.LoadUL(V, i);
			t1.LoadUL(V, i + 256);
			t2.LoadUL(V, i + 512);
			t3.LoadUL(V, i + 768);

			tmpK = CalcK<Vector>(v0[0], v1[0], N8 * t0 + N4 * tmpR, Q);
			tmpK += CalcK<Vector>(v0[1], v1[1], N8 * t1 + N4 * tmpR, Q);
			tmpK += CalcK<Vector>(v0[2], v1[2], N8 * t2 + N4 * tmpR, Q);
			tmpK += CalcK<Vector>(v0[3], v1[3], N8 * t3 + N4 * tmpR, Q);
			tmpK = Vector::ShiftRA((N2 * NQ - N1 - tmpK), 31);

			tmpV[0] = ((~tmpK) & v0[0]) ^ (tmpK & v1[0]);
			tmpV[1] = ((~tmpK) & v0[1]) ^ (tmpK & v1[1]);
			tmpV[2] = ((~tmpK) & v0[2]) ^ (tmpK & v1[2]);
			tmpV[3] = ((~tmpK) & v0[3]) ^ (tmpK & v1[3]);

			c0 = (tmpV[0] - tmpV[3]) & N3;
			c1 = (tmpV[1] - tmpV[3]) & N3;
			c2 = (tmpV[2] - tmpV[3]) & N3;
			c3 = (Vector::Negate(tmpK) + N2 * tmpV[3]) & N3;

			c0.Store(tmpC, 0);
			c1.Store(tmpC, ULVSZE);
			c2.Store(tmpC, ULVSZE * 2);
			c3.Store(tmpC, ULVSZE * 3);

			for (uint j = static_cast<uint>(tmpC.size() - 1), k = 0; k < ULVSZE; --j, ++k)
			{
				C[i + k + 768] = static_cast<ushort>(tmpC[j]);
				C[i + k + 512] = static_cast<ushort>(tmpC[j - ULVSZE]);
				C[i + k + 256] = static_cast<ushort>(tmpC[j - (ULVSZE * 2)]);
				C[i + k] = static_cast<ushort>(tmpC[j - (ULVSZE * 3)]);
			}
		}

#else
		std::array<int, 4> v0;
		std::array<int, 4> v1;
		std::array<uint, 4> tmpV;
		int k;
		int x;
		byte rbit;

		for (size_t i = 0; i < V.size() / 4; i++)
		{
			rbit = (Random[i >> 3] >> (i & 7)) & 1;

			x = (8 * V[i]) + (4 * rbit);
			k = CalcK<int>(v0[0], v1[0], x, Q);
			x = (8 * V[256 + i]) + (4 * rbit);
			k += CalcK<int>(v0[1], v1[1], x, Q);
			x = (8 * V[512 + i]) + (4 * rbit);
			k += CalcK<int>(v0[2], v1[2], x, Q);
			x = (8 * V[768 + i]) + (4 * rbit);
			k += CalcK<int>(v0[3], v1[3], x, Q);
			k = ((2 * Q) - 1 - k) >> 31;

			tmpV[0] = ((~k) & v0[0]) ^ (k & v1[0]);
			tmpV[1] = ((~k) & v0[1]) ^ (k & v1[1]);
			tmpV[2] = ((~k) & v0[2]) ^ (k & v1[2]);
			tmpV[3] = ((~k) & v0[3]) ^ (k & v1[3]);

			C[0 + i] = (tmpV[0] - tmpV[3]) & 3;
			C[256 + i] = (tmpV[1] - tmpV[3]) & 3;
			C[512 + i] = (tmpV[2] - tmpV[3]) & 3;
			C[768 + i] = (-k + 2 * tmpV[3]) & 3;
		}
#endif
	}

	template <typename Vector>
	inline static Vector LdDecode(Vector &X0, Vector &X1, Vector &X2, Vector &X3, const int Q)
	{
		Vector tmpT;

		tmpT = Decode<Vector>(X0, Q);
		tmpT += Decode<Vector>(X1, Q);
		tmpT += Decode<Vector>(X2, Q);
		tmpT += Decode<Vector>(X3, Q);
		tmpT -= Vector(8) * Vector(Q);
		tmpT >>= 31;
		tmpT &= Vector(1);

		return tmpT;
	}

	template <typename ArrayR, typename ArrayA, typename ArrayB>
	inline static void PolyAdd(ArrayR &R, const ArrayA &A, const ArrayB &B)
	{
		for (size_t i = 0; i < R.size(); ++i)
		{
			R[i] = Utility::PolyMath::BarrettReduce(A[i] + B[i]);
		}
	}

	template <typename ArrayA, typename ArrayB>
	inline static void PolyGetNoise(ArrayA &R, ArrayB &Random)
	{
#if defined(__AVX512__)
		GetNoise<Numeric::UInt512, ArrayA, ArrayB>(R, Random, Q);
#elif defined(__AVX2__)
		GetNoise<Numeric::UInt256, ArrayA, ArrayB>(R, Random, Q);
#elif defined(__AVX__)
		GetNoise<Numeric::UInt128, ArrayA, ArrayB>(R, Random, Q);
#else
		GetNoise<uint, ArrayA, ArrayB>(R, Random, Q);
#endif
	}

	template <typename ArrayA, typename ArrayB>
	inline static void PolyMul(ArrayA &Poly, const ArrayB &Factors)
	{
		for (size_t i = 0; i < Poly.size(); ++i)
		{
			Poly[i] = Utility::PolyMath::MontgomeryReduce((Poly[i] * Factors[i]));
		}
	}

	template <typename ArrayA, typename ArrayB, typename ArrayC>
	inline static void PolyPointwise(ArrayA &R, const ArrayB &A, const ArrayC &B)
	{
		ushort t;

		for (size_t i = 0; i < N; i++)
		{
			// t is now in Montgomery domain
			t = Utility::PolyMath::MontgomeryReduce(3186 * B[i]);
			// R[i] is back in normal domain
			R[i] = Utility::PolyMath::MontgomeryReduce(A[i] * t);
		}
	}

	template <typename Vector, typename ArrayA, typename ArrayB>
	inline static void Rec(ArrayA &Key, const ArrayB &V, const ArrayB &C, const int Q)
	{
		Utility::MemUtils::Clear(Key, 0, Key.size());

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)

		const Vector NQ(Q);
		const Vector N2(2);
		const Vector N8(8);
		const Vector N16(16);
		const size_t ULVSZE = Vector::size() / sizeof(uint);
		Vector c0;
		Vector c1;
		Vector c2;
		Vector c3;
		Vector v0;
		Vector v1;
		Vector v2;
		Vector v3;
		std::array<Vector, 4> tmpV;
		std::vector<uint> tmpK(ULVSZE);

		for (size_t i = 0; i < V.size() / 4; i += ULVSZE)
		{
			c0.LoadUL(C, i);
			c1.LoadUL(C, 256 + i);
			c2.LoadUL(C, 512 + i);
			c3.LoadUL(C, 768 + i);

			v0.LoadUL(V, i);
			v1.LoadUL(V, 256 + i);
			v2.LoadUL(V, 512 + i);
			v3.LoadUL(V, 768 + i);

			tmpV[0] = N16 * NQ + N8 * v0 - NQ * (N2 * c0 + c3);
			tmpV[1] = N16 * NQ + N8 * v1 - NQ * (N2 * c1 + c3);
			tmpV[2] = N16 * NQ + N8 * v2 - NQ * (N2 * c2 + c3);
			tmpV[3] = N16 * NQ + N8 * v3 - NQ * c3;

			Vector K = LdDecode<Vector>(tmpV[0], tmpV[1], tmpV[2], tmpV[3], Q);

			K.Store(tmpK, 0);

			for (size_t j = ULVSZE, k = 0; j > 0; --j, ++k)
			{
				Key[((i + k) >> 3)] |= static_cast<byte>(tmpK[j - 1] << ((i + k) & 7));
			}
		}

#else

		std::array<int, 4> tmp;
		for (uint i = 0; i < 256; i++)
		{
			tmp[0] = (16 * Q) + (8 * static_cast<int>(V[0 + i])) - (Q * ((2 * C[0 + i]) + C[768 + i]));
			tmp[1] = (16 * Q) + (8 * static_cast<int>(V[256 + i])) - (Q * ((2 * C[256 + i]) + C[768 + i]));
			tmp[2] = (16 * Q) + (8 * static_cast<int>(V[512 + i])) - (Q * ((2 * C[512 + i]) + C[768 + i]));
			tmp[3] = (16 * Q) + (8 * static_cast<int>(V[768 + i])) - (Q * C[768 + i]);
			Key[i >> 3] |= LdDecode<int>(tmp[0], tmp[1], tmp[2], tmp[3], Q) << (i & 7);
		}
#endif
	}

	//~~~Static~~~//

	static void DecodeA(std::array<ushort, N> &PubKey, std::vector<byte> &Seed, const std::vector<byte> &R);
	static void DecodeB(std::array<ushort, N> &B, std::array<ushort, N> &C, const std::vector<byte> &R);
	static void EncodeA(std::vector<byte> &R, const std::array<ushort, N> &PubKey, const std::vector<byte> &Seed);
	static void EncodeB(std::vector<byte> &R, const std::array<ushort, N> &B, const std::array<ushort, N> &C);
	static void FromBytes(std::array<ushort, N> &R, const std::vector<byte> &A);
	static void PolyUniform(std::array<ushort, N> &A, const std::vector<byte> &Seed, bool Parallel);
	static void RecHelper(std::array<ushort, N> &C, const std::array<ushort, N> &V, std::vector<byte> &Random);
	static void Reconcile(std::vector<byte> &Key, const std::array<ushort, N> &V, const std::array<ushort, N> &C);
	static void ToBytes(std::vector<byte> &R, const std::array<ushort, N> &Poly);
};

NAMESPACE_RINGLWEEND
#endif
