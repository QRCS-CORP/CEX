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

#ifndef _CEX_SKEINUBITWEAK_H
#define _CEX_SKEINUBITWEAK_H

#include "CexDomain.h"
#include "CryptoDigestException.h"
#include "SkeinStateType.h"
#include "SkeinUbiType.h"

NAMESPACE_DIGEST

/// <summary>
/// Part of Skein: the UBI Tweak structure.
/// </summary> 
struct SkeinUbiTweak
{
private:
	const ulong T1FlagFinal = (ulong)1 << 63;
	const ulong T1FlagFirst = (ulong)1 << 62;

	std::vector<ulong> m_tweak;

public:
	/// <summary>
	/// Instantiate this class
	/// </summary>
	SkeinUbiTweak()
		:
		m_tweak(2, 0)
	{
	}

	/// <summary>
	/// Clear the teak value
	/// </summary>
	void Clear()
	{
		memset(&m_tweak, 0, sizeof(m_tweak));
	}

	/// <summary>
	/// Gets the number of bits processed so far, inclusive.
	/// </summary>
	long GetBitsProcessed()
	{
		return (long)m_tweak[0];
	}

	/// <summary>
	/// Gets the current UBI block type.
	/// </summary>
	SkeinUbiType GetBlockType()
	{
		return (SkeinUbiType)(m_tweak[1] >> 56);
	}

	/// <summary>
	/// Gets the final block flag
	/// </summary>
	bool GetIsFinalBlock()
	{
		return (m_tweak[1] & T1FlagFinal) != 0;
	}

	/// <summary>
	/// Gets the first block flag
	/// </summary>
	bool GetIsFirstBlock()
	{
		return (m_tweak[1] & T1FlagFirst) != 0;
	}

	/// <summary>
	/// Gets the current tree level
	/// </summary>
	byte GetTreeLevel()
	{
		return (byte)((m_tweak[1] >> 48) & 0x3f);
	}

	/// <summary>
	/// Gets the tweak value array
	/// </summary>
	std::vector<ulong> GetTweak()
	{
		return m_tweak;
	}

	/// <summary>
	/// Sets the number of bits processed so far, inclusive
	/// </summary>
	void SetBitsProcessed(const ulong Value)
	{
		m_tweak[0] = Value;
	}

	/// <summary>
	/// Sets the current UBI block type
	/// </summary>
	void SetBlockType(const SkeinUbiType Value)
	{
		m_tweak[1] = (ulong)Value << 56;
	}

	/// <summary>
	/// Sets the first block flag
	/// </summary>
	void SetIsFirstBlock(const bool Value)
	{
		long mask = Value ? 1 : 0;
		m_tweak[1] = (m_tweak[1] & ~T1FlagFirst) | ((ulong)-mask & T1FlagFirst);
	}

	/// <summary>
	/// Sets the final block flag
	/// </summary>
	void SetIsFinalBlock(const ulong Value)
	{
		long mask = Value ? 1 : 0;
		m_tweak[1] = (m_tweak[1] & ~T1FlagFinal) | ((ulong)-mask & T1FlagFinal);
	}

	/// <summary>
	/// Sets the current tree level
	/// </summary>
	void SetTreeLevel(const byte Value)
	{
		if (Value > 63)
			throw Exception::CryptoDigestException("Skein:TreeLevel", "Tree level must be between 0 and 63, inclusive.");

		m_tweak[1] &= ~((ulong)0x3f << 48);
		m_tweak[1] |= (ulong)Value << 48;
	}

	/// <summary>
	/// Sets the tweak value array
	/// </summary>
	void SetTweak(const std::vector<ulong> &Value)
	{
		m_tweak = Value;
	}

	/// <summary>
	/// Starts a new UBI block type by setting BitsProcessed to zero, setting the first flag, and setting the block type
	/// </summary>
	///
	/// <param name="Value">The UBI block type of the new block</param>
	void StartNewBlockType(const SkeinUbiType Value)
	{
		SetBitsProcessed(0);
		SetBlockType(Value);
		SetIsFirstBlock(true);
	}
};

NAMESPACE_DIGESTEND
#endif