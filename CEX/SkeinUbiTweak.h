// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef _CEXENGINE_SKEINUBITWEAK_H
#define _CEXENGINE_SKEINUBITWEAK_H

#include "Common.h"
#include "SkeinStateType.h"
#include "SkeinUbiType.h"

/// <summary>
/// Part of Skein: the UBI Tweak structure.
/// </summary> 
struct SkeinUbiTweak
{
private:
	static constexpr ulong T1FlagFinal = (ulong)1 << 63;
	static constexpr ulong T1FlagFirst = (ulong)1 << 62;

	std::vector<ulong> m_tweak;

public:
	/// <summary>
	/// Initialize this class
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
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Value > 63)
			throw CEX::Exception::CryptoDigestException("Skein:TreeLevel", "Tree level must be between 0 and 63, inclusive.");
#endif

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

#endif