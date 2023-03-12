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

#ifndef CEX_MPKCN6688T128_H
#define CEX_MPKCN6688T128_H

#include "CexDomain.h"
#include "IPrng.h"

NAMESPACE_MCELIECE

using Prng::IPrng;

/// 
/// internal
/// 
 
/// <summary>
// An internal McEliece utilities class
/// </summary>
class MPKCN6688T128
{
public:

	//~~~Public Constants~~~//

	/// <summary>
	/// The uint8_t size of the CCA cipher-text
	/// </summary>
	static const size_t CIPHERTEXT_SIZE = 240;

	/// <summary>
	/// The mac size in bytes
	/// </summary>
	static const size_t MAC_SIZE = 32;

	/// <summary>
	/// The finite field dimension of GF(2^m): M
	/// </summary>
	static const uint32_t MPKC_M = 13;

	/// <summary>
	/// The dimension: N
	/// </summary>
	static const uint32_t MPKC_N = 6688;

	/// <summary>
	/// The error correction capability of the code: T
	/// </summary>
	static const uint32_t MPKC_T = 128;

	/// <summary>
	/// The uint8_t size of the CCA private key polynomial
	/// </summary>
	static const size_t PRIVATEKEY_SIZE = 13932;

	/// <summary>
	/// The uint8_t size of the CCA public key polynomial
	/// </summary>
	static const size_t PUBLICKEY_SIZE = 1044992;

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
	static bool Decapsulate(const std::vector<uint8_t> &PrivateKey, const std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret);

	/// <summary>
	/// Generates the cipher-text and shared-secret for a given public key
	/// </summary>
	/// 
	/// <param name="PublicKey">The public-key vector</param>
	/// <param name="CipherText">The output cipher-text vector</param>
	/// <param name="SharedSecret">The output shared-secret (an array of MCELIECE_SECRET_SIZE bytes)</param>
	/// <param name="Rng">The random generator instance</param>
	static void Encapsulate(const std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret, std::unique_ptr<IPrng>& Rng);

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	/// 
	/// <param name="PublicKey">The public-key vector</param>
	/// <param name="PrivateKey">The private-key vector</param>
	/// <param name="Rng">The random generator instance</param>
	/// 
	/// <returns>The key-pair was generated succesfully, or false for generation failure</returns>
	static bool Generate(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::unique_ptr<IPrng> &Rng);

private:

	static int32_t Decrypt(uint8_t* E, const uint8_t* Sk, const uint8_t* C);
	static void Encrypt(uint8_t* S, const uint8_t* Pk, uint8_t* E, std::unique_ptr<IPrng> &Rng);
	static void GenE(uint8_t* E, std::unique_ptr<IPrng> &Rng);
	static int32_t GenPolyGen(uint16_t* Output, const uint16_t* F);
	static void GfMul(uint16_t* Output, const uint16_t* Input0, const uint16_t* Input1);
	static int32_t PkGen(uint8_t* Pk, const uint8_t* Sk, const uint32_t* Perm, int16_t* Pi);
	static void SupportGen(uint16_t* S, const uint8_t* C);
	static void Syndrome(uint8_t* S, const uint8_t* Pk, const uint8_t* E);
};

NAMESPACE_MCELIECEEND
#endif