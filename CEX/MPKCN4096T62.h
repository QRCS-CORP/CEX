// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
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

#ifndef CEX_MPKCN4096T62_H
#define CEX_MPKCN4096T62_H

#include "CexDomain.h"
#include "IPrng.h"

NAMESPACE_MCELIECE

using Prng::IPrng;

///
/// internal
///

/// <summary>
/// The McEliece MPKCS1N4096T62 FFT
/// </summary>
class MPKCN4096T62
{
private:

	static const uint MPKC_GFBITS = 12;
	static const uint MPKC_SYST = 62;
	static const uint MPKC_PKN_ROWS = (MPKC_SYST * MPKC_GFBITS);
	static const uint MPKC_PKN_COLS = (4096 - (MPKC_SYST * MPKC_GFBITS));
	static const uint MPKC_IRR_SIZE = (MPKC_GFBITS * 8);
	static const uint MPKC_CND_SIZE = ((MPKC_PKN_ROWS - 8) * 8);
	static const uint KEYGEN_RETRIES_MAX = 100;
	static const size_t MPKC_COLUMN_SIZE = 64;
	static const size_t MPKC_SYNDBYTES = (MPKC_PKN_ROWS / 8);
	static const size_t MPKC_KEY_SIZE = 32;
	static const size_t MPKC_CPACIPHERTEXT_SIZE = (MPKC_PKN_ROWS / 8);
	static const size_t MPKC_CPAPRIVATEKEY_SIZE = (MPKC_CND_SIZE + MPKC_IRR_SIZE);
	static const size_t MPKC_CPAPUBLICKEY_SIZE = (MPKC_PKN_ROWS * ((MPKC_COLUMN_SIZE - MPKC_GFBITS) * 8)) + (MPKC_PKN_ROWS * (8 - ((MPKC_PKN_ROWS & 63) >> 3)));

	static const std::vector<std::vector<ulong>> ButterflyConsts;
	static const std::vector<std::vector<ulong>> GfPoints;
	static const std::vector<std::vector<std::vector<ulong>>> RadixTrScalar;

public:

	//~~~Public Constants~~~//

	/// <summary>
	/// The MAC tag size in bytes
	/// </summary>
	static const size_t MAC_SIZE = 16;

	/// <summary>
	/// The byte size of the CCA cipher-text
	/// </summary>
	static const size_t CIPHERTEXT_SIZE = ((MPKC_PKN_ROWS / 8) + MPKC_KEY_SIZE + MAC_SIZE);

	/// <summary>
	/// The finite field dimension of GF(2^m): M
	/// </summary>
	static const size_t MPKC_M = 12;

	/// <summary>
	/// The dimension: N
	/// </summary>
	static const size_t MPKC_N = 4096;

	/// <summary>
	/// The error correction capability of the code: T
	/// </summary>
	static const size_t MPKC_T = 62; 

	/// <summary>
	/// The byte size of the CCA private key polynomial
	/// </summary>
	static const size_t PRIVATEKEY_SIZE = 5984;

	/// <summary>
	/// The byte size of the CCA public key polynomial
	/// </summary>
	static const size_t PUBLICKEY_SIZE = 311736;

	/// <summary>
	/// The shared secret size in bytes
	/// </summary>
	static const size_t SECRET_SIZE = 32;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt an encrypted cipher-text and return the shared secret
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private key array</param>
	/// <param name="CipherText">The ciphertext input vector</param>
	/// <param name="SharedSecret">The shared secret output</param>
	/// 
	/// <returns>The message was decrypted succesfully</returns>
	static bool Decrypt(const std::vector<byte> &PrivateKey, const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret);

	/// <summary>
	/// Encrypt a message and return the shared secret and cipher-text
	/// </summary>
	/// 
	/// <param name="PublicKey">The public key array</param>
	/// <param name="CipherText">The ciphertext input vector</param>
	/// <param name="SharedSecret">The shared secret output</param>
	/// <param name="Rng">The random generator instance</param>
	static void Encrypt(const std::vector<byte> &PublicKey, std::vector<byte> &CipherText, std::vector<byte> &SharedSecret, std::unique_ptr<IPrng> &Rng);

	/// <summary>
	/// Generate a public/private key pair
	/// </summary>
	/// 
	/// <param name="PublicKey">The public key array</param>
	/// <param name="PrivateKey">The private key array</param>
	/// <param name="Rng">The random generator instance</param>
	/// 
	/// <returns>The message was decrypted succesfully</returns>
	static bool Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<IPrng> &Rng);

private:

	static void XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate);

	//~~~Decrypt~~~//

	static void BerlekampMassey(std::array<ulong, MPKC_M> &Output, std::array<std::array<ulong, MPKC_M>, 2> &Input);

	static byte DecryptE(std::vector<byte> &E, const std::vector<byte> &PrivateKey, const std::vector<byte> &S);

	static void PreProcess(std::vector<ulong> &Received, const std::vector<byte> &S);

	static void Scaling(std::array<std::array<ulong, MPKC_M>, MPKC_COLUMN_SIZE> &Output, std::array<std::array<ulong, MPKC_M>, MPKC_COLUMN_SIZE> &Inverse, const std::vector<byte> &PrivateKey, std::vector<ulong> &Received);

	static void ScalingInverse(std::array<std::array<ulong, MPKC_M>, MPKC_COLUMN_SIZE> &Output, std::array<std::array<ulong, MPKC_M>, MPKC_COLUMN_SIZE> &Inverse, std::array<ulong, MPKC_COLUMN_SIZE> &Received);

	static void SyndromeAdjust(std::array<std::array<ulong, MPKC_M>, 2> &Output);

	//~~~Encrypt~~~//

	static void EncryptE(std::vector<byte> &S, std::vector<byte> &E, const std::vector<byte> &PublicKey, std::unique_ptr<IPrng> &Rng);

	static void GenE(std::vector<byte> &E, std::unique_ptr<IPrng> &Rng);

	static void Syndrome(std::vector<byte> &S, const std::vector<byte> &PublicKey, const std::vector<byte> &E);

	//~~~KeyGen~~~//

	static bool IrrGen(std::array<ushort, MPKC_T + 1> &Output, std::vector<ushort> &F);

	static void SkGen(std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);

	static bool PkGen(std::vector<byte> &PublicKey, const std::vector<byte> &PrivateKey);

	//~~~Utils~~~//

	static void Invert(std::array<ulong, MPKC_M> &Output, const std::array<ulong, MPKC_M> &Input);

	static void MatrixMultiply(std::array<ushort, MPKC_T> &Output, std::array<ushort, MPKC_T> &A, std::vector<ushort> &B);

	static void Square(std::array<ulong, MPKC_M> &Output, std::array<ulong, MPKC_M> &Input);

	//~~~FFT~~~//

	class AdditiveFFT
	{
	public:

		static void Transform(std::array<std::array<ulong, MPKC_M>, MPKC_COLUMN_SIZE> &Output, std::array<ulong, MPKC_M> &Input);

	private:

		static void Butterflies(std::array<std::array<ulong, MPKC_M>, MPKC_COLUMN_SIZE> &Output, std::array<ulong, MPKC_M> &Input);

		static void RadixConversions(std::array<ulong, MPKC_M> &Output);
	};

	class TransposedFFT
	{
	public:

		static void Transform(std::array<std::array<ulong, MPKC_M>, 2> &Output, std::array<std::array<ulong, MPKC_M>, MPKC_COLUMN_SIZE> &Input);

	private:

		static void Butterflies(std::array<std::array<ulong, MPKC_M>, 2> &Output, std::array<std::array<ulong, MPKC_M>, MPKC_COLUMN_SIZE> &Input);

		static void RadixConversions(std::array<std::array<ulong, MPKC_M>, 2> &Output);
	};
};

NAMESPACE_MCELIECEEND
#endif
