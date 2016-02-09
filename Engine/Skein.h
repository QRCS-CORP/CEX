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

#ifndef _CEXENGINE_SKEIN_H
#define _CEXENGINE_SKEIN_H

#include "Common.h"
#include "UbiType.h"
#include "SkeinInitializationType.h"

/// <summary>
/// Part of Skein: the UBI Tweak structure.
/// </summary> 
struct UbiTweak
{
private:
	static constexpr ulong T1FlagFinal = (ulong)1 << 63;
	static constexpr ulong T1FlagFirst = (ulong)1 << 62;

	std::vector<ulong> _tweak;

public:
	/// <summary>
	/// Initialize this class
	/// </summary>
	UbiTweak()
		:
		_tweak(2, 0)
	{
	}

	/// <summary>
	/// Clear the teak value
	/// </summary>
	void Clear()
	{
		memset(&_tweak, 0, sizeof(_tweak));
	}

	/// <summary>
	/// Gets the number of bits processed so far, inclusive.
	/// </summary>
	long GetBitsProcessed()
	{
		return (long)_tweak[0];
	}

	/// <summary>
	/// Gets the current UBI block type.
	/// </summary>
	UbiType GetBlockType()
	{
		return (UbiType)(_tweak[1] >> 56);
	}

	/// <summary>
	/// Gets the final block flag
	/// </summary>
	bool GetIsFinalBlock()
	{
		return (_tweak[1] & T1FlagFinal) != 0;
	}

	/// <summary>
	/// Gets the first block flag
	/// </summary>
	bool GetIsFirstBlock()
	{
		return (_tweak[1] & T1FlagFirst) != 0;
	}

	/// <summary>
	/// Gets the current tree level
	/// </summary>
	byte GetTreeLevel()
	{
		return (byte)((_tweak[1] >> 48) & 0x3f);
	}

	/// <summary>
	/// Gets the tweak value array
	/// </summary>
	std::vector<ulong> GetTweak()
	{
		return _tweak;
	}

	/// <summary>
	/// Sets the number of bits processed so far, inclusive
	/// </summary>
	void SetBitsProcessed(const ulong Value)
	{
		_tweak[0] = (ulong)Value;
	}

	/// <summary>
	/// Sets the current UBI block type
	/// </summary>
	void SetBlockType(const UbiType Value)
	{
		_tweak[1] = (ulong)Value << 56;
	}

	/// <summary>
	/// Sets the first block flag
	/// </summary>
	void SetIsFirstBlock(const bool Value)
	{
		long mask = Value ? 1 : 0;
		_tweak[1] = (_tweak[1] & ~T1FlagFirst) | ((ulong)-mask & T1FlagFirst);
	}

	/// <summary>
	/// Sets the final block flag
	/// </summary>
	void SetIsFinalBlock(const ulong Value)
	{
		long mask = Value ? 1 : 0;
		_tweak[1] = (_tweak[1] & ~T1FlagFinal) | ((ulong)-mask & T1FlagFinal);
	}

	/// <summary>
	/// Sets the current tree level
	/// </summary>
	void SetTreeLevel(const byte Value)
	{
		if (Value > 63)
			throw CEX::Exception::CryptoDigestException("Skein:TreeLevel", "Tree level must be between 0 and 63, inclusive.");

		_tweak[1] &= ~((ulong)0x3f << 48);
		_tweak[1] |= (ulong)Value << 48;
	}

	/// <summary>
	/// Sets the tweak value array
	/// </summary>
	void SetTweak(const std::vector<ulong> Value)
	{
		_tweak = Value;
	}

	/// <summary>
	/// Starts a new UBI block type by setting BitsProcessed to zero, setting the first flag, and setting the block type
	/// </summary>
	///
	/// <param name="Value">The UBI block type of the new block</param>
	void StartNewBlockType(const UbiType Value)
	{
		SetBitsProcessed(0);
		SetBlockType(Value);
		SetIsFirstBlock(true);
	}
};

#endif