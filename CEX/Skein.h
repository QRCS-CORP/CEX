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

#ifndef CEX_SKEIN_H
#define CEX_SKEIN_H

#include "CexDomain.h"

#if defined(__AVX2__)
#	include "ULong256.h"
#endif
#if defined(__AVX512__)
#	include "ULong512.h"
#endif

NAMESPACE_DIGEST

#if defined(__AVX2__)
	using Numeric::ULong256;
#endif
#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

	/// <summary>
	/// Contains the Skein 256, 512, and 1024bit permutation functions.
	/// <para>The function names are in the format; Permute-rounds-bits-suffix, ex. PemuteR72P256C, 72 rounds, permutes 256 bits, using the compact form of the function. \n
	/// The compact forms of the permutations have the suffix C, and are optimized for performance and low memory consumption 
	/// (enabled in the hash function by adding the CEX_DIGEST_COMPACT to the CexConfig file). \n
	/// The Unrolled forms are optimized for speed and timing neutrality (suffix U), and the vertically vectorized functions have the V suffix.</para>
	/// </summary>
class Skein
{
public:

	const static size_t SKEIN_RATE256_SIZE = 32;
	const static size_t SKEIN_RATE512_SIZE = 64;
	const static size_t SKEIN_RATE1024_SIZE = 128;
	const static size_t SKEIN_MESSAGE256_SIZE = 32;
	const static size_t SKEIN_MESSAGE512_SIZE = 64;
	const static size_t SKEIN_MESSAGE1024_SIZE = 128;

	//~~~Skein-256~~~//

	/// <summary>
	/// The compact form of the Skein-256 variable rounds permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 72</param>
	static void PemuteP256C(const std::array<ulong, 4> &Input, const std::array<ulong, 2> &Tweak, std::array<ulong, 4> &State, size_t Rounds);

	/// <summary>
	/// The unrolled form of the Skein-256 72 round permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	static void PemuteR72P256U(const std::array<ulong, 4> &Input, const std::array<ulong, 2> &Tweak, std::array<ulong, 4> &State);

	//~~~Skein-512~~~//

	/// <summary>
	/// The compact form of the Skein-512 variable rounds permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 72</param>
	static void PemuteP512C(const std::array<ulong, 8> &Input, const std::array<ulong, 2> &Tweak, std::array<ulong, 8> &State, size_t Rounds);

	/// <summary>
	/// The unrolled form of the Skein-512 72 round permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	static void PemuteR72P512U(const std::array<ulong, 8> &Input, const std::array<ulong, 2> &Tweak, std::array<ulong, 8> &State);

	/// <summary>
	/// The unrolled form of the Skein-512 96 round permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	static void PemuteR96P512U(const std::array<ulong, 8> &Input, const std::array<ulong, 2> &Tweak, std::array<ulong, 8> &State);

#if defined(__AVX2__)

	/// <summary>
	/// The vertically vectorized form of the Skein-512 72 round permutation function.
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	static void PemuteR72P512V(const std::array<ulong, 8> &Input, const std::array<ulong, 2> &Tweak, std::array<ulong, 8> &State);

#endif

	//~~~Skein-1024~~~//

	/// <summary>
	/// The compact form of the Skein-1024 variable rounds permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 80</param>
	static void PemuteP1024C(const std::array<ulong, 16> &Input, const std::array<ulong, 2> &Tweak, std::array<ulong, 16> &State, size_t Rounds);

	/// <summary>
	/// The unrolled form of the Skein-1024 80 round permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	static void PemuteR80P1024U(const std::array<ulong, 16> &Input, const std::array<ulong, 2> &Tweak, std::array<ulong, 16> &State);

	/// <summary>
	/// The unrolled form of the Skein-1024 120 round permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	static void PemuteR120P1024U(const std::array<ulong, 16> &Input, const std::array<ulong, 2> &Tweak, std::array<ulong, 16> &State);
};

NAMESPACE_DIGESTEND
#endif
