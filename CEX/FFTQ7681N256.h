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

#ifndef CEX_FFTQ7681N256_H
#define CEX_FFTQ7681N256_H

#include "CexDomain.h"
#include "BCG.h"
#include "IntUtils.h"
#include "IPrng.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

NAMESPACE_MODULELWE

/// <summary>
/// The ModuleLWE FFT using a modulus of 12289 with 1024 coefficients
/// </summary>
class FFTQ7681N256
{
private:


	static const uint QINV = 7679;
	static const uint RLOG = 18;


	static const std::array<ushort, 128> OmegasInvMontgomery;
	static const std::array<ushort, 256> PsisInvMontgomery;
	static const std::array<ushort, 256> Zetas;

public:

	//~~~Public Constants~~~//

	static const size_t PRIPOLY_SIZE = 416;
	static const size_t PUBPOLY_SIZE = 352;
	static const size_t SEED_SIZE = 32;

	/// <summary>
	/// The number of coefficients
	/// </summary>
	static const uint N = 256;

	/// <summary>
	/// The Q modulus
	/// </summary>
	static const uint Q = 7681;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a cipher-text
	/// </summary>
	/// 
	/// <param name="Secret">The shared secret</param>
	/// <param name="CipherText">The received ciphertext</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="K">The coefficient dimension parameter K</param>
	static void Decrypt(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey, uint K);

	/// <summary>
	/// Encrypt a message
	/// </summary>
	/// 
	/// <param name="CipherText">The cipher-text output</param>
	/// <param name="Message">The secret message</param>
	/// <param name="PublicKey">The asymmetric public key</param>
	/// <param name="Rng">The random provider</param>
	/// <param name="K">The coefficient dimension parameter K</param>
	static void Encrypt(std::vector<byte> &CipherText, const std::vector<byte> &Message, const std::vector<byte> &PublicKey, std::unique_ptr<Prng::IPrng> &Rng, uint K);

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	///
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Rng">The random provider</param>
	/// <param name="K">The coefficient dimension parameter K</param>
	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, uint K);

private:

	//~~~Inlined~~~//

	inline static ushort BarrettReduce(ushort X)
	{
		uint u;

		u = (static_cast<uint>(X) >> 13);
		u *= Q;
		X -= u;

		return X;
	}

	inline static ushort Freeze(ushort X)
	{
		ushort m;
		ushort r;
		int16_t c;

		r = BarrettReduce(X);
		m = r - Q;
		c = m;
		c >>= 15;
		r = m ^ ((r ^ m) & c);

		return r;
	}

	inline static uint LeBytesTo32(const std::vector<byte> &A, size_t Offset, size_t Length)
	{
		size_t i;
		uint r;

		r = A[Offset];

		for (i = 1; i < Length; i++)
		{
			r |= static_cast<uint>(A[Offset + i]) << (8 * i);
		}

		return r;
	}

	inline static ulong LeBytesTo64(const std::vector<byte> &A, size_t Offset, size_t Length)
	{
		size_t i;
		ulong r;

		r = A[Offset];

		for (i = 1; i < Length; i++)
		{
			r |= static_cast<ulong>(A[Offset + i]) << (8 * i);
		}

		return r;
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

	//~~~Static~~~//

	static void GenerateMatrix(std::vector<std::vector<std::array<ushort, N>>> &A, const std::vector<byte> &Seed, bool Transposed);

	static void GetNoise(std::array<ushort, N> &R, size_t Eta, std::unique_ptr<Prng::IPrng> &Rng);

	static void InvNTT(std::array<ushort, N> &P);

	static void FwdNTT(std::array<ushort, N> &P);

	static void Cbd(std::array<ushort, N> &R, const std::vector<byte> &Buffer, size_t Eta);

	static void PackCiphertext(std::vector<byte> &R, const std::vector<std::array<ushort, N>> &B, const std::array<ushort, N> &V);

	static void PackPublicKey(std::vector<byte> &R, const std::vector<std::array<ushort, N>> &Pk, const std::vector<byte> &Seed);

	static void PackSecretKey(std::vector<byte> &R, const std::vector<std::array<ushort, N>> &Sk);

	static void PolyAdd(std::array<ushort, N> &R, const std::array<ushort, N> &A, const std::array<ushort, N> &B);

	static void PolyCompress(std::vector<byte> &R, size_t Offset, const std::array<ushort, N> &A);

	static void PolyDecompress(std::array<ushort, N> &R, const std::vector<byte> &A, size_t Offset);

	static void PolyFrombytes(std::array<ushort, N> &R, const std::vector<byte> &A, size_t Offset);

	static void PolySub(std::array<ushort, N> &R, const std::array<ushort, N> &A, const std::array<ushort, N> &B);

	static void PolyToBytes(std::vector<byte> &R, size_t Offset, const std::array<ushort, N> &A);

	static void PolyToMsg(std::vector<byte> &Message, const std::array<ushort, N> &A);

	static void PolyVecAdd(std::vector<std::array<ushort, N>> &R, const std::vector<std::array<ushort, N>> &A, const std::vector<std::array<ushort, N>> &B);

	static void PolyVecCompress(std::vector<byte> &R, size_t Offset, const std::vector<std::array<ushort, N>> &A);

	static void PolyFromMessage(std::array<ushort, N> &R, const std::vector<byte> &Message);

	static void PolyVecCompress(std::vector<byte> &R, const std::vector<std::array<ushort, N>> &A);

	static void PolyVecDecompress(std::vector<std::array<ushort, N>> &R, const std::vector<byte> &A);

	static void PolyVecFrombytes(std::vector<std::array<ushort, N>> &R, const std::vector<byte> &A);

	static void PolyVecInvNTT(std::vector<std::array<ushort, N>> &R);

	static void PolyVecNTT(std::vector<std::array<ushort, N>> &R);

	static void PolyVecPointwiseAcc(std::array<ushort, N> &R, const std::vector<std::array<ushort, N>> &A, const std::vector<std::array<ushort, N>> &B);

	static void PolyVecToBytes(std::vector<byte> &R, const std::vector<std::array<ushort, N>> &A);

	static void UnpackCiphertext(std::vector<std::array<ushort, N>> &B, std::array<ushort, N> &V, const std::vector<byte> &C);

	static void UnpackPublicKey(std::vector<std::array<ushort, N>> &Pk, std::vector<byte> &Seed, const std::vector<byte> &PackedPk);

	static void UnpackSecretKey(std::vector<std::array<ushort, N>> &Sk, const std::vector<byte> &PackedSk);
};

NAMESPACE_MODULELWEEND
#endif
