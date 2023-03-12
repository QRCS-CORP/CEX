// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
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

#ifndef CEX_MPKCN6960T119_H
#define CEX_MPKCN6960T119_H

#include "CexDomain.h"
#include "IPrng.h"

NAMESPACE_MCELIECE

using Prng::IPrng;

///
/// internal
///

/// <summary>
/// The McEliece MPKCN6960T119 FFT
/// </summary>
class MPKCN6960T119
{
private:

	static const uint GFBITS = 13;
	static const uint SYS_N = 6960;
	static const uint SYS_T = 119;
	static const uint COND_BYTES = ((1UL << (GFBITS - 4)) * ((2 * GFBITS) - 1));
	static const uint IRR_BYTES = (SYS_T * 2);
	static const uint PK_NROWS = (SYS_T * GFBITS);
	static const uint PK_NCOLS = (SYS_N - PK_NROWS);
	static const uint PK_ROW_BYTES = ((PK_NCOLS + 7) / 8);
	static const uint SK_BYTES = ((SYS_N / 8) + IRR_BYTES + COND_BYTES);
	static const uint SYND_BYTES = ((PK_NROWS + 7) / 8);
	static const uint GFMASK = ((1UL << GFBITS) - 1);
	static const uint GF_MUL_FACTOR1 = 6400;
	static const uint GF_MUL_FACTOR2 = 3134;
	static const uint KEYGEN_RETRIES = 100;

public:

	//~~~Public Constants~~~//

	/// <summary>
	/// The byte size of the CCA cipher-text
	/// </summary>
	static const size_t CIPHERTEXT_SIZE = 226;

	/// <summary>
	/// The mac size in bytes
	/// </summary>
	static const size_t MAC_SIZE = 32;

	/// <summary>
	/// The finite field dimension of GF(2^m): M
	/// </summary>
	static const uint MPKC_M = 13;

	/// <summary>
	/// The dimension: N
	/// </summary>
	static const uint MPKC_N = 6960;

	/// <summary>
	/// The error correction capability of the code: T
	/// </summary>
	static const uint MPKC_T = 119;

	/// <summary>
	/// The byte size of the CCA private key polynomial
	/// </summary>
	static const size_t PRIVATEKEY_SIZE = 13908;

	/// <summary>
	/// The byte size of the CCA public key polynomial
	/// </summary>
	static const size_t PUBLICKEY_SIZE = 1047319;

	/// <summary>
	/// The key size in bytes
	/// </summary>
	static const size_t SECRET_SIZE = 32;

	//~~~Public Functions~~~//  

	/// <summary>
	/// Extracts the shared secret for a given cipher-text and private-key
	/// </summary>
	/// 
	/// <param name="PrivateKey">The private-key vector</param>
	/// <param name="CipherText">The input cipher-text vector</param>
	/// <param name="SharedSecret">The output shared-secret (a vector of MCELIECE_SECRET_SIZE bytes)</param>
	/// 
	/// <returns>The message was decrypted succesfully, fails on authentication failure</returns>
	static bool Decapsulate(const std::vector<byte> &PrivateKey, const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret);

	/// <summary>
	/// Generates the cipher-text and shared-secret for a given public key
	/// </summary>
	/// 
	/// <param name="PublicKey">The public-key vector</param>
	/// <param name="CipherText">The output cipher-text vector</param>
	/// <param name="SharedSecret">The output shared-secret (an array of MCELIECE_SECRET_SIZE bytes)</param>
	/// <param name="Rng">The random generator instance</param>
	static void Encapsulate(const std::vector<byte> &PublicKey, std::vector<byte> &CipherText, std::vector<byte> &SharedSecret, std::unique_ptr<IPrng> &Rng);

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	/// 
	/// <param name="PublicKey">The public-key vector</param>
	/// <param name="PrivateKey">The private-key vector</param>
	/// <param name="Rng">The random generator instance</param>
	/// 
	/// <returns>The key-pair was generated succesfully, or false for generation failure</returns>
	static bool Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<IPrng> &Rng);

private:

	static void XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate);

	// benes.c //

	static void SupportGen(ushort* S, const byte* C);

	// bm.c //

	static void BerlekampMassey(ushort* Output, const ushort* S);

	// controlbits.c //

	static void ControlBits(byte* Output, const uint* Pi);

	// decrypt.c //

	static byte DecryptE(byte* E, const byte* Sk, const byte* C);

	// encrypt.c //

	static void GenE(byte* E, std::unique_ptr<IPrng> &Rng);

	static int32_t MovForward(ushort* Ind);

	static void Syndrome(byte* S, const byte* Pk, const byte* E);

	static void EncryptE(byte* SS, const byte* Pk, byte* E, std::unique_ptr<IPrng> &Rng);

	// pk_gen.c //

	static int32_t PkGen(byte* Pk, const byte* Sk);

	// root.c //

	static ushort Evaluate(const ushort* F, ushort A);

	static void Root(ushort* Output, const ushort* F, const ushort* L);

	// sk_gen.c //

	static int32_t IrrGen(ushort* Output, const ushort* F);

	static int32_t PermConversion(uint* Perm);

	static int32_t SkPartGen(byte* Sk, std::unique_ptr<IPrng> &Rng);

	// syndrome.c //

	static void Syndrome(ushort* Output, const ushort* F, const ushort* L, const byte* R);

	// gf.c //

	class GF
	{
	private:

		static ushort Sq2(ushort Input);
		static ushort SqMul(ushort Input, ushort M);
		static ushort Sq2Mul(ushort Input, ushort M);

	public:

		static ushort Add(ushort A, ushort B);
		static ushort GfFrac(ushort Den, ushort Num);
		static ushort Inverse(ushort Den);
		static ushort IsZero(ushort A);
		static ushort Multiply(ushort A, ushort B);
		static void Multiply(ushort* Output, const ushort* X, const ushort* Y);
	};
};

NAMESPACE_MCELIECEEND
#endif
