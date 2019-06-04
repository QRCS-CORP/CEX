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

#ifndef CEX_RLWEQ12289N1024_H
#define CEX_RLWEQ12289N1024_H

#include "CexDomain.h"
#include "IPrng.h"

NAMESPACE_RINGLWE

/// 
/// internal
/// 

/// <summary>
/// The RingLWE FFT using a modulus of 12289 with 1024 coefficients
/// </summary>
class RLWEQ12289N1024
{
private:

	static const std::vector<ushort> OmegasMontgomery;
	static const std::vector<ushort> OmegasInvMontgomery;
	static const std::vector<ushort> PsisBitrevMontgomery;
	static const std::vector<ushort> PsisInvMontgomery;
	static const std::vector<ushort> BitRevTable;

	static const uint RLWE_QINV = 0x00002FFFUL;
	static const uint RLWE_RLOG = 0x00000012UL;
	static const uint RLWE_N = 1024;
	static const uint RLWE_Q = 0x00003001UL;
	static const size_t RLWE_SEED_SIZE = 32;
	static const size_t RLWE_POLY_SIZE = ((14 * RLWE_N) / 8);
	static const size_t RLWE_POLYCOMPRESSED_SIZE = ((3 * RLWE_N) / 8);
	static const size_t RLWE_RECEIVED_SIZE = 256;
	static const size_t RLWE_CPACIPHERTEXT_SIZE = (RLWE_POLY_SIZE + RLWE_POLYCOMPRESSED_SIZE);
	static const size_t RLWE_CPAPUBLICKEY_SIZE = (RLWE_POLY_SIZE + RLWE_SEED_SIZE);
	static const size_t RLWE_CPAPRIVATEKEY_SIZE = RLWE_POLY_SIZE;

public:

	//~~~Public Constants~~~//

	/// <summary>
	/// The byte size of the CCA cipher-text
	/// </summary>
	static const size_t CIPHERTEXT_SIZE = (RLWE_CPACIPHERTEXT_SIZE + RLWE_SEED_SIZE);

	/// <summary>
	/// The byte size of the CCA public key polynomial
	/// </summary>
	static const size_t PUBLICKEY_SIZE = RLWE_CPAPUBLICKEY_SIZE;

	/// <summary>
	/// The byte size of the CCA private key polynomial
	/// </summary>
	static const size_t PRIVATEKEY_SIZE = (RLWE_CPAPRIVATEKEY_SIZE + RLWE_CPAPUBLICKEY_SIZE + (2 * RLWE_SEED_SIZE));

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	static const size_t SEED_SIZE = RLWE_SEED_SIZE;

	/// <summary>
	/// The parameter sets formal name
	/// </summary>
	static const std::string Name;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decapsulate and authenticate a cipher-text, generating a shared secret key
	/// </summary>
	/// 
	/// <param name="Secret">The shared secret</param>
	/// <param name="CipherText">The private asymmetric key</param>
	/// <param name="PrivateKey">The received ciphertext</param>
	/// 
	/// <returns>Returns true for success, false for authentication failure</returns>
	static bool Decapsulate(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey);

	/// <summary>
	/// Encapsulate a message, generating a shared secret key
	/// </summary>
	/// 
	/// <param name="CipherText">The ciphertext output</param>
	/// <param name="Secret">The secret message</param>
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="Rng">The random generator instance</param>
	static void Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &Secret, const std::vector<byte> &PublicKey, std::unique_ptr<Prng::IPrng> &Rng);

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	///
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Rng">The random provider</param>
	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);

	/// <summary>
	/// Decrypt a cipher-text
	/// </summary>
	/// 
	/// <param name="Secret">The shared secret</param>
	/// <param name="CipherText">The private asymmetric key</param>
	/// <param name="PrivateKey">The received ciphertext</param>
	static void CpaDecrypt(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey);

	/// <summary>
	/// Encrypt a message
	/// </summary>
	/// 
	/// <param name="CipherText">The ciphertext output</param>
	/// <param name="Secret">The secret message</param>
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="Coin">The random provider</param>
	static void CpaEncrypt(std::vector<byte> &CipherText, std::vector<byte> &Secret, const std::vector<byte> &PublicKey, const std::vector<byte> &Coin);

	/// <summary>
	/// Generate a CPA-Secure public/private key-pair
	/// </summary>
	///
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Rng">The random provider instance</param>
	static void CpaGenerate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);

private:

	//~~~Static~~~//

	static void BitRevVector(std::array<ushort, RLWE_N> &P);

	static void DecodeC(std::array<ushort, RLWE_N> &B, std::array<ushort, RLWE_N> &V, const std::vector<byte> &R);

	static void DecodePk(std::array<ushort, RLWE_N> &PublicKey, std::vector<byte> &Seed, const std::vector<byte> &R);

	static void EncodeC(std::vector<byte> &R, const std::array<ushort, RLWE_N> &B, const std::array<ushort, RLWE_N> &V);

	static void EncodePk(std::vector<byte> &R, const std::array<ushort, RLWE_N> &PublicKey, const std::vector<byte> &Seed);

	static ushort FlipAbs(ushort X);

	static ushort Freeze(ushort X);

	static byte HammimgWeight(byte A);

	static ushort MontgomeryReduce(uint X);

	static void MulCoefficients(std::array<ushort, RLWE_N> &Poly, const std::vector<ushort> &Factors);

	static void Ntt(std::array<ushort, RLWE_N> &A, const std::vector<ushort> &Omega);

	static void PolyAdd(std::array<ushort, RLWE_N> &R, const std::array<ushort, RLWE_N> &A, const std::array<ushort, RLWE_N> &B);

	static void PolyCompress(std::vector<byte> &R, const std::array<ushort, RLWE_N> &P);

	static void PolyDecompress(std::array<ushort, RLWE_N> &R, const std::vector<byte> &A);

	static void PolyFromBytes(std::array<ushort, RLWE_N> &R, const std::vector<byte> &A);

	static void PolyFromMessage(std::array<ushort, RLWE_N> &R, const std::vector<byte> &Message);

	static void PolyInvNtt(std::array<ushort, RLWE_N> &R);

	static void PolyMulPointwise(std::array<ushort, RLWE_N> &R, const std::array<ushort, RLWE_N> &A, const std::array<ushort, RLWE_N> &B);

	static void PolyNtt(std::array<ushort, RLWE_N> &R);

	static void PolySample(std::array<ushort, RLWE_N> &R, const std::vector<byte> &Seed, byte Nonce);

	static void PolySub(std::array<ushort, RLWE_N> &R, const std::array<ushort, RLWE_N> &A, const std::array<ushort, RLWE_N> &B);

	static void PolyToBytes(std::vector<byte> &R, const std::array<ushort, RLWE_N> &P);

	static void PolyToMessage(std::vector<byte> &Message, const std::array<ushort, RLWE_N> &X);

	static void PolyUniform(std::array<ushort, RLWE_N> &A, const std::vector<byte> &Seed);

	static void XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate);
};

NAMESPACE_RINGLWEEND
#endif
