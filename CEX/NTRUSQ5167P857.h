// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
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

#ifndef CEX_NTRUSQ5167P857_H
#define CEX_NTRUSQ5167P857_H

#include "CexDomain.h"
#include "NTRUPolyMath.h"
#include "IntegerTools.h"
#include "IPrng.h"
#include "MemoryTools.h"
#include "SHA512.h"

NAMESPACE_NTRUPRIME

using Utility::IntegerTools;
using Prng::IPrng;
using Utility::MemoryTools;
using Digest::SHA512;

/// 
/// internal
/// 

/// <summary>
/// The NTRU S-Prime functions
/// </summary>
class NTRUSQ5167P857
{
private:

	static const int32_t NTRUP_P = 857;
	static const int32_t NTRUP_Q = 5167;
	static const int32_t NTRUP_W = 322;
	static const int32_t NTRUP_ROUNDED = 1152;
	static const int32_t NTRUP_RQ = 1322;
	static const int32_t NTRUP_SPOLY = ((NTRUP_P + 3) / 4);
	static const int32_t NTRUP_CPAPRIVATEKEY_SIZE = (2 * NTRUP_SPOLY);
	static const int32_t NTRUP_HASH_SIZE = 32;
	static const int32_t NTRUP_SEED_SIZE = 32;

public:

	/// <summary>
	/// The byte size of the CCA cipher-text
	/// </summary>
	static const int32_t CIPHERTEXT_SIZE = NTRUP_ROUNDED + NTRUP_HASH_SIZE;

	/// <summary>
	/// The byte size of the CCA private key polynomial
	/// </summary>
	static const int32_t PRIVATEKEY_SIZE = NTRUP_RQ + NTRUP_CPAPRIVATEKEY_SIZE + NTRUP_SPOLY + NTRUP_HASH_SIZE;

	/// <summary>
	/// The byte size of the CCA public key polynomial
	/// </summary>
	static const int32_t PUBLICKEY_SIZE = NTRUP_RQ;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	static const int32_t SEED_SIZE = NTRUP_SEED_SIZE;

	/// <summary>
	/// Decapsulate a cipher-text and return the shared-secret
	/// </summary>
	/// 
	/// <param name="Secret">The shared-secret key</param>
	/// <param name="CipherText">The encapsulated keys ciphertext</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	static bool Decapsulate(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey);

	/// <summary>
	/// Encapsulate a secret key and output the cipher-text and the shared-secret
	/// </summary>
	/// 
	/// <param name="Secret">The shared-secret message</param>
	/// <param name="CipherText">The encapsulated keys ciphertext</param>
	/// <param name="PublicKey">The asymmetric public key</param>
	/// <param name="Rng">The random generator instance</param>
	static void Encapsulate(std::vector<byte> &Secret, std::vector<byte> &CipherText, const std::vector<byte> &PublicKey, std::unique_ptr<Prng::IPrng> &Rng);

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	///
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Rng">The random provider</param>
	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);

private:

	static void Hash(std::vector<byte> &Output, size_t OutOffset, int32_t B, const std::vector<byte> &Input);

	static void HashConfirm(std::vector<byte> &H, size_t HOffset, const std::vector<byte> &R, const std::vector<byte> &Pk, const std::vector<byte> &Cache);

	static void HashSession(std::vector<byte> &K, int32_t B, const std::vector<byte> &Y, const std::vector<byte> &Z);

	static void Hide(std::vector<byte> &C, std::vector<byte> &REnc, const std::vector<int8_t> &R, const std::vector<byte> &Pk, const std::vector<byte> &Cache);

	static void KeyGen(std::vector<int16_t> &H, std::vector<int8_t> &F, std::vector<int8_t> &GInv, std::unique_ptr<Prng::IPrng> &Rng);

	static void ShortFromList(std::vector<int8_t> &Output, const std::vector<uint> &Input);

	static void ShortRandom(std::vector<int8_t> &Output, std::unique_ptr<Prng::IPrng> &Rng);

	static void SmallRandom(std::vector<int8_t> &Output, std::unique_ptr<Prng::IPrng> &Rng);

	static uint URandom32(std::unique_ptr<Prng::IPrng> &Rng);

	static void ZKeyGen(std::vector<byte> &Pk, std::vector<byte> &Sk, std::unique_ptr<Prng::IPrng> &Rng);

	static void ZDecrypt(std::vector<int8_t> &R, const std::vector<byte> &C, const std::vector<byte> &Sk);

	static void ZEncrypt(std::vector<byte> &C, const std::vector<int8_t> &R, const std::vector<byte> &Pk);
};

NAMESPACE_NTRUPRIMEEND
#endif
