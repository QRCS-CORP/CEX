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
// but WITStateOUT ANY WARRANTY; without even the implied warranty of
// MERCStateANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_CMUL_H
#define CEX_CMUL_H

#include "CexDomain.h"

NAMESPACE_NUMERIC

class CMUL
{
public:

	/// <summary>
	/// The CMUL output buffers minimum size in bytes (128 bits)
	/// </summary>
	static const size_t CMUL_BLOCK_SIZE = 16;

	/// <summary>
	/// The CMUL state array size in uint64 integers (128 bits)
	/// </summary>
	static const size_t CMUL_STATE_SIZE = 2;

	/// <summary>
	/// The compact form of the 128 round (standard) CMUL permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="State">The permutations uint64 state array</param>
	/// <param name="Output">The output buffer receiving the permuted state</param>
	static void PermuteR128P128U(std::array<uint64_t, CMUL_STATE_SIZE> &State, std::array<uint8_t, CMUL_BLOCK_SIZE> &Output);

	/// <summary>
	/// The unrolled form of the 128 round (standard) CMUL permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="State">The permutations uint64 state array</param>
	/// <param name="Output">The output buffer receiving the permuted state</param>
	static void PermuteR128P128C(std::array<uint64_t, CMUL_STATE_SIZE> &State, std::array<uint8_t, CMUL_BLOCK_SIZE> &Output);

	/// <summary>
	/// The vertically vectorized form of the 128 round (standard) CMUL permutation function.
	/// <para>This function uses the SIMD instructions.</para>
	/// </summary>
	/// 
	/// <param name="State">The permutations uint64 state array</param>
	/// <param name="Output">The output buffer receiving the permuted state</param>
	static void PermuteR128P128V(std::array<uint64_t, CMUL_STATE_SIZE> &State, std::array<uint8_t, CMUL_BLOCK_SIZE> &Output);
};

NAMESPACE_NUMERICEND
#endif
