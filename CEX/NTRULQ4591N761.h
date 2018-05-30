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

#ifndef CEX_NTRULQ4591N761_H
#define CEX_NTRULQ4591N761_H

#include "CexDomain.h"
#include "BCG.h"
#include "CSR.h"
#include "IPrng.h"
#include "Keccak512.h"

NAMESPACE_NTRU

/// 
/// internal
/// 

/// <summary>
/// The NTRU L-Prime functions
/// </summary>
class NTRULQ4591N761
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
	static const size_t NTRU_CIPHERTEXT_SIZE = 1175;

	/// <summary>
	/// The P dimension
	/// </summary>
	static const int NTRU_P = 761;

	/// <summary>
	/// The modulus factor
	/// </summary>
	static const int NTRU_Q = 4591;

	/// <summary>
	/// The W dimension
	/// </summary>
	static const int NTRU_W = 250;

	/// <summary>
	/// The byte size of the private key polynomial
	/// </summary>
	static const size_t NTRU_PRIVATEKEY_SIZE = 1238;

	/// <summary>
	/// The byte size of the public key polynomial
	/// </summary>
	static const size_t NTRU_PUBLICKEY_SIZE = 1047;

	/// <summary>
	/// The modulus shift factor
	/// </summary>
	static const int NTRU_QSHIFT = 2295;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	static const size_t NTRU_SEED_SIZE = 32;

	//~~~Internal Constants~~~//

	static const size_t NTRU_RQENCODEROUNDED_SIZE = 1015;
	static const size_t NTRU_SMALLENCODE_SIZE = 191;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a cipher-text
	/// </summary>
	/// 
	/// <param name="Secret">The shared secret</param>
	/// <param name="CipherText">The private asymmetric key</param>
	/// <param name="PrivateKey">The received ciphertext</param>
	static int Decrypt(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey);

	/// <summary>
	/// Encrypt a message
	/// </summary>
	/// 
	/// <param name="Secret">The shared secret message output</param>
	/// <param name="CipherText">The ciphertext output</param>
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="Coin">The random provider</param>
	static void Encrypt(std::vector<byte> &Secret, std::vector<byte> &CipherText, const std::vector<byte> &PublicKey, std::unique_ptr<Prng::IPrng> &Rng);

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	///
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Rng">The random provider</param>
	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);

	//~~~Internal Functions~~~//

	static void Hide(std::vector<byte> &CipherText, std::vector<byte> &Secret, const std::vector<byte> &Key, size_t KeyOffset, const std::vector<byte> &Rand);

	static void MinMax(int32_t &X, int32_t &Y);

	static int16_t ModqFreeze(int32_t A);

	static int16_t ModqFromUL(uint A);

	static int16_t ModqPlusProduct(int16_t A, int16_t B, int16_t C);

	static int16_t ModqSum(int16_t A, int16_t B);

	static void RqDecodeRounded(std::array<int16_t, NTRU_P> &F, const std::vector<byte> &Key, size_t KeyOffset);

	static void RqEncodeRounded(std::vector<byte> &C, const std::array<int16_t, NTRU_P> &Key);

	static void RqFromSeed(std::array<int16_t, NTRU_P> &H, const std::vector<byte> &Key, size_t KeyOffset);

	static void RqMult(std::array<int16_t, NTRU_P> &H, const std::array<int16_t, NTRU_P> &F, const std::array<int8_t, NTRU_P> &G);

	static void RqRound3(std::array<int16_t, NTRU_P> &H, const std::array<int16_t, NTRU_P> &F);

	static void SeededWeightW(std::array<int8_t, NTRU_P> &F, const std::vector<byte> &K);

	static void SmallDecode(std::array<int8_t, NTRU_P> &F, const std::vector<byte> &C);

	static void SmallEncode(std::vector<byte> &C, const std::array<int8_t, NTRU_P> &F);

	static void Sort(std::array<int32_t, NTRU_P> &X);

	static int32_t Verify(const std::vector<byte> &X, const std::vector<byte> &Y);
};

NAMESPACE_NTRUEND
#endif
