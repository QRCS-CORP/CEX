// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
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

#ifndef CEX_NTRUSQ4591N761_H
#define CEX_NTRUSQ4591N761_H

#include "CexDomain.h"
#include "IPrng.h"

NAMESPACE_NTRU

#define NTRU_SPRIME_SIMPLE

/// 
/// internal
/// 

/// <summary>
/// The NTRU S-Prime functions
/// </summary>
class NTRUSQ4591N761
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
	static const size_t NTRU_CIPHERTEXT_SIZE = 1047;

	/// <summary>
	/// The P dimension
	/// </summary>
	static const int NTRU_P = 761;

	/// <summary>
	/// The modulus factor
	/// </summary>
	static const int NTRU_Q = 4591;

	/// <summary>
	/// The byte size of the private key polynomial
	/// </summary>
	static const size_t NTRU_PRIVATEKEY_SIZE = 1600;

	/// <summary>
	/// The byte size of the public key polynomial
	/// </summary>
	static const size_t NTRU_PUBLICKEY_SIZE = 1218;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	static const size_t NTRU_SEED_SIZE = 32;

	/// <summary>
	/// The W dimension
	/// </summary>
	static const int NTRU_W = 286;

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
	/// <param name="Rng">The random provider</param>
	static void Encrypt(std::vector<byte> &Secret, std::vector<byte> &CipherText, const std::vector<byte> &PublicKey, std::unique_ptr<Prng::IPrng> &Rng);

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	///
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Rng">The random provider</param>
	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);

private:

	static const int NTRU_QSHIFT = 2295;
	static const size_t NTRU_RQENCODE_SIZE = 1218;
	static const size_t NTRU_SMALLENCODE_SIZE = 191;

	template<typename Array>
	static void Swap(Array &X, size_t XOffset, Array &Y, size_t YOffset, size_t Length, int32_t Mask)
	{
		Array::value_type c;
		Array::value_type t;
		Array::value_type xi;
		Array::value_type yi;
		size_t i;

		c = Mask;

		for (i = 0; i < Length; ++i)
		{
			xi = X[XOffset + i];
			yi = Y[YOffset + i];
			t = c & (xi ^ yi);
			xi ^= t;
			yi ^= t;
			X[XOffset + i] = xi;
			Y[YOffset + i] = yi;
		}
	}

	static void MinMax(int32_t &X, int32_t &Y);

	static int8_t Mod3Freeze(int32_t a);

	static int8_t Mod3MinusProduct(int8_t A, int8_t B, int8_t C);

#if !defined(NTRU_SPRIME_SIMPLE)
	static void Mod3MinusProductVector(std::vector<int8_t> &Z, size_t ZOffset, const std::vector<int8_t> &X, size_t XOffset, const std::vector<int8_t> &Y, size_t YOffset, const int8_t C, size_t Length);
#endif

	static void Mod3MinusProductVector(std::vector<int8_t> &Z, const std::vector<int8_t> &X, const std::vector<int8_t> &Y, const int8_t C, size_t Length);

	static int32_t Mod3NonZeroMask(int8_t X);

	static int8_t Mod3PlusProduct(int8_t A, int8_t B, int8_t C);

	static int8_t Mod3Product(int8_t A, int8_t B);

	static void Mod3ProductVector(std::array<int8_t, NTRU_P> &Z, const std::vector<int8_t> &X, size_t XOffset, const int8_t C, size_t Length);

	static int8_t Mod3Quotient(int8_t Num, int8_t Den);

	static int8_t Mod3Reciprocal(int8_t A1);

	static void Mod3ShiftVector(std::vector<int8_t> &Z, size_t ZOffset, size_t Length);

	static int8_t Mod3Sum(int8_t A, int8_t B);

	static int16_t ModqFreeze(int32_t A);

	static int16_t ModqMinusProduct(int16_t A, int16_t B, int16_t C);

	static void ModqMinusProductVector(std::vector<int16_t> &Z, const std::vector<int16_t> &X, const std::vector<int16_t> &Y, size_t Length, const int16_t C);

#if !defined(NTRU_SPRIME_SIMPLE)
	static void ModqMinusProductVector(std::vector<int16_t> &Z, size_t ZOffset, const std::vector<int16_t> &X, size_t XOffset, const std::vector<int16_t> &Y, size_t YOffset, size_t Length, const int16_t C);
#endif

	static int ModqNonZeroMask(int16_t X);

	static int16_t ModqPlusProduct(int16_t A, int16_t B, int16_t C);

	static int16_t ModqProduct(int16_t A, int16_t B);

	static void ModqProductVector(std::array<int16_t, NTRU_P> &Z, const std::vector<int16_t> &X, size_t XOffset, size_t Length, const int16_t C);

	static int16_t ModqQuotient(int16_t Num, int16_t Den);

	static int16_t ModqReciprocal(int16_t A1);

	static void ModqShiftVector(std::vector<int16_t> &Z, size_t ZOffset, size_t Length);

	static int16_t ModqSquare(int16_t A);

	static int16_t ModqSum(int16_t A, int16_t B);

	static void R3Mult(std::array<int8_t, NTRU_P> &H, const std::array<int8_t, NTRU_P> &F, const std::array<int8_t, NTRU_P> &G);

	static int R3Recip(std::array<int8_t, NTRU_P> &R, const std::array<int8_t, NTRU_P> &S);

	static void RqDecode(std::array<int16_t, NTRU_P> &F, const std::vector<byte> &C, size_t COffset);

	static void RqDecode(std::array<int16_t, NTRU_P> &F, const std::vector<byte> &C);

	static void RqDecodeRounded(std::array<int16_t, NTRU_P> &F, const std::vector<byte> &C, size_t COffset);

	static void RqEncode(std::vector<byte> &C, const std::array<int16_t, NTRU_P> &F);

	static void RqEncodeRounded(std::vector<byte> &C, size_t COffset, const std::array<int16_t, NTRU_P> &F);

	static void RqMult(std::array<int16_t, NTRU_P> &H, const std::array<int16_t, NTRU_P> &F, const std::array<int8_t, NTRU_P> &G);

	static int RqRecip3(std::array<int16_t, NTRU_P> &R, const std::array<int8_t, NTRU_P> &S);

	static void RqRound3(std::array<int16_t, NTRU_P> &H, const std::array<int16_t, NTRU_P> &F);

	static void SmallDecode(std::array<int8_t, NTRU_P> &F, const std::vector<byte> &C, size_t COffset);

	static void SmallEncode(std::vector<byte> &C, size_t COffset, const std::array<int8_t, NTRU_P> &F);

	static int SmallerMask(int32_t X, int32_t Y);

	static void SmallRandom(std::array<int8_t, NTRU_P> &G, std::unique_ptr<Prng::IPrng> &Rng);

	static void SmallRandomWeightW(std::array<int8_t, NTRU_P> &F, std::unique_ptr<Prng::IPrng> &Rng);

	static void Sort(std::array<int32_t, NTRU_P> &X);

	static void Swap32(int32_t &X, int32_t &Y, int32_t Mask);

	static int32_t Verify32(const std::vector<byte> &X, const std::vector<byte> &Y);
};

NAMESPACE_NTRUEND
#endif
