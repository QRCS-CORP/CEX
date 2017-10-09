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

#ifndef _CEX_FFTM12T62_H
#define _CEX_FFTM12T62_H

#include "CexDomain.h"
#include "IPrng.h"

NAMESPACE_MCELIECE

using Prng::IPrng;

/**
* \internal
*/

/// <summary>
/// The McEliece M12T62 FFT
/// </summary>
class FFTM12T62
{
public:

	FFTM12T62() = delete;
	FFTM12T62(const FFTM12T62&) = delete;
	FFTM12T62& operator=(const FFTM12T62&) = delete;
	FFTM12T62& operator=(FFTM12T62&&) = delete;

	static const size_t M = 12;
	static const size_t T = 62; 
	static const ulong ButterflyConsts[63][12];

private:

	static const size_t PKN_ROWS = (T * M);
	static const size_t PKN_COLS = (((size_t)1 << M) - T * M);
	static const size_t IRR_SIZE = (M * 8);
	static const size_t CND_SIZE = ((PKN_ROWS - 8) * 8);
	static const size_t GEN_MAXR = 10000;

public:

	static const size_t SECRET_SIZE = (PKN_ROWS / 8);
	static const size_t PRIKEY_SIZE = CND_SIZE + IRR_SIZE;
	static const size_t PUBKEY_SIZE = (PKN_ROWS * ((64 - M) * 8)) + (PKN_ROWS * (8 - ((PKN_ROWS & 63) >> 3)));

	static bool Decrypt(std::vector<byte> &E, const std::vector<byte> &PrivateKey, const std::vector<byte> &S);

	static void Encrypt(std::vector<byte> &S, std::vector<byte> &E, const std::vector<byte> &PublicKey, std::unique_ptr<IPrng> &Random);

	static bool Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<IPrng> &Random);

private:

	//~~~Decrypt~~~//

	static void BerlekampMassey(std::array<ulong, M> &Output, std::array<std::array<ulong, M>, 2> &Input);

	static void PreProcess(std::vector<ulong> &Received, const std::vector<byte> &S);

	static void Scaling(std::array<std::array<ulong, M>, 64> &Output, std::array<std::array<ulong, M>, 64> &Inverse, const std::vector<byte> &PrivateKey, std::vector<ulong> &Received);

	static void ScalingInverse(std::array<std::array<ulong, M>, 64> &Output, std::array<std::array<ulong, M>, 64> &Inverse, std::array<ulong, 64> &Received);

	static void SyndromeAdjust(std::array<std::array<ulong, M>, 2> &Output);

	//~~~Encrypt~~~//

	static void GenE(std::vector<byte> &E, std::unique_ptr<IPrng> &Random);

	static void Syndrome(std::vector<byte> &S, const std::vector<byte> &PublicKey, const std::vector<byte> &E);

	//~~~KeyGen~~~//

	static int IrrGen(std::array<ushort, T + 1> &Output, std::vector<ushort> &F);

	static void SkGen(std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Random);

	static int PkGen(std::vector<byte> &PublicKey, const std::vector<byte> &PrivateKey);

	//~~~Utils~~~//

	static void Invert(std::array<ulong, M> &Output, const std::array<ulong, M> &Input);

	static void MatrixMultiply(std::array<ushort, T> &Output, std::array<ushort, T> &A, std::vector<ushort> &B);

	static void Square(std::array<ulong, M> &Output, std::array<ulong, M> &Input);

	//~~~FFT~~~//

	class AdditiveFFT
	{
	public:

		static void Transform(std::array<std::array<ulong, M>, 64> &Output, std::array<ulong, M> &Input);

	private:

		static void Butterflies(std::array<std::array<ulong, M>, 64> &Output, std::array<ulong, M> &Input);

		static void RadixConversions(std::array<ulong, M> &Output);
	};

	class TransposedFFT
	{
	public:

		static void Transform(std::array<std::array<ulong, M>, 2> &Output, std::array<std::array<ulong, M>, 64> &Input);

	private:

		static void Butterflies(std::array<std::array<ulong, M>, 2> &Output, std::array<std::array<ulong, M>, 64> &Input);

		static void RadixConversions(std::array<std::array<ulong, M>, 2> &Output);
	};
};

NAMESPACE_MCELIECEEND
#endif