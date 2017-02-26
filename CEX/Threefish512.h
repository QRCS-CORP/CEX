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
// along with this program.If not, see <http://www.gnu.org/licenses/>.

#ifndef _CEX_THREEFISH512_H
#define _CEX_THREEFISH512_H

#include "CexDomain.h"

/// <summary>
/// Part of Skein512: the Threefish cipher using a 512bit key size.
/// </summary> 
class Threefish512
{
private:
	const uint CipherSize = 512;
	const uint CipherQwords = CipherSize / 64;
	const uint ExpandedKeySize = CipherQwords + 1;
	const uint ExpandedTweakSize = 3;
	const ulong KeyScheduleConst = 0x1BD11BDAA9FC1A22;

	std::vector<ulong> m_expandedKey;
	std::vector<ulong> m_expandedTweak;

public:
	/// <summary>
	/// Threefish with a 512 bit block
	/// </summary>
	Threefish512()
		:
		m_expandedTweak(ExpandedTweakSize, 0),
		m_expandedKey(ExpandedKeySize, 0)
	{
		// Create the expanded key array
		m_expandedKey[ExpandedKeySize - 1] = KeyScheduleConst;
	}

	/// <summary>
	/// Reset the state
	/// </summary>
	void Clear();

	/// <summary>
	/// Encrypt a block
	/// </summary>
	/// 
	/// <param name="Input">Input array</param>
	/// <param name="Output">Processed bytes</param>
	void Encrypt(const std::vector<ulong> &Input, std::vector<ulong> &Output);

	/// <summary>
	/// Initialize the key
	/// </summary>
	/// 
	/// <param name="Key">The cipher key</param>
	void SetKey(const std::vector<ulong> &Key);

	/// <summary>
	/// Initialize the tweak
	/// </summary>
	/// 
	/// <param name="Tweak">The cipher tweak</param>
	void SetTweak(const std::vector<ulong> &Tweak);

private:
	static inline void Mix(ulong &A, ulong &B, uint R)
	{
		A += B;
		B = RotL64(B, R) ^ A;
	}

	static inline void Mix(ulong &A, ulong &B, uint R, ulong K0, ulong K1)
	{
		B += K1;
		A += B + K0;
		B = RotL64(B, R) ^ A;
	}

	static inline ulong RotL64(ulong V, uint B)
	{
		return (V << B) | (V >> (64 - B));
	}
};

#endif
