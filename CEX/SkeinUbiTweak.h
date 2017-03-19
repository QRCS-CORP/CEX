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

NAMESPACE_DIGEST

/// <summary>
/// Specifies the Skein Ubi type
/// </summary>
enum class SkeinUbiType : ulong
{
	/// <summary>
	/// A key that turns Skein into a MAC or KDF function.
	/// </summary>
	Key = 0,
	/// <summary>
	/// The configuration block.
	/// </summary>
	Config = 4,
	/// <summary>
	/// A string that applications can use to create different functions for different uses.
	/// </summary>
	Personalization = 8,
	/// <summary>
	/// Used to hash the public key when hashing a message for signing.
	/// </summary>
	PublicKey = 12,
	/// <summary>
	/// Used for key derivation.
	/// </summary>
	KeyIdentifier = 16,
	/// <summary>
	/// Nonce value for use in stream cipher mode and randomized hashing.
	/// </summary>
	Nonce = 20,
	/// <summary>
	/// The normal message input of the hash function.
	/// </summary>
	Message = 48,
	/// <summary>
	/// The output transform.
	/// </summary>
	Out = 63
};

/// <summary>
/// The UBI Tweak structure
/// </summary> 
class SkeinUbiTweak
{
private:
	static const ulong T1_FINAL = (ulong)1 << 63;
	static const ulong T1_FIRST = (ulong)1 << 62;

public:

	/// <summary>
	/// Gets the number of bits processed so far, inclusive.
	/// </summary>
	static ulong BitsProcessed(const std::vector<ulong> &Tweak)
	{
		return Tweak[0];
	}

	/// <summary>
	/// Gets the current UBI block type.
	/// </summary>
	static SkeinUbiType BlockType(const std::vector<ulong> &Tweak)
	{
		return (SkeinUbiType)(Tweak[1] >> 56);
	}

	/// <summary>
	/// Sets the current UBI block type
	/// </summary>
	static void BlockType(std::vector<ulong> &Tweak, SkeinUbiType Value)
	{
		Tweak[1] = (ulong)Value << 56;
	}

	/// <summary>
	/// Gets the final block flag
	/// </summary>
	static bool IsFinalBlock(const std::vector<ulong> &Tweak)
	{
		return (Tweak[1] & T1_FINAL) != 0;
	}

	/// <summary>
	/// Sets the final block flag
	/// </summary>
	static void IsFinalBlock(std::vector<ulong> &Tweak, ulong Value)
	{
		long mask = Value ? 1 : 0;
		Tweak[1] = (Tweak[1] & ~T1_FINAL) | ((ulong)-mask & T1_FINAL);
	}

	/// <summary>
	/// Gets the first block flag
	/// </summary>
	static bool IsFirstBlock(const std::vector<ulong> &Tweak)
	{
		return (Tweak[1] & T1_FIRST) != 0;
	}

	/// <summary>
	/// Sets the first block flag
	/// </summary>
	static void IsFirstBlock(std::vector<ulong> &Tweak, bool Value)
	{
		long mask = Value ? 1 : 0;
		Tweak[1] = (Tweak[1] & ~T1_FIRST) | ((ulong)-mask & T1_FIRST);
	}

	/// <summary>
	/// Gets the current tree level
	/// </summary>
	static byte TreeLevel(const std::vector<ulong> &Tweak)
	{
		return (byte)((Tweak[1] >> 48) & 0x3f);
	}

	/// <summary>
	/// Sets the current tree level
	/// </summary>
	static void TreeLevel(std::vector<ulong> &Tweak, byte Value)
	{
		if (Value > 63)
			throw Exception::CryptoDigestException("Skein:TreeLevel", "Tree level must be between 0 and 63, inclusive.");

		Tweak[1] &= ~((ulong)0x3f << 48);
		Tweak[1] |= (ulong)Value << 48;
	}

	/// <summary>
	/// Sets the tweak value array
	/// </summary>
	static void SetTweak(std::vector<ulong> &Tweak, const std::vector<ulong> &Value)
	{
		Tweak = Value;
	}

	/// <summary>
	/// Starts a new UBI block type by setting BitsProcessed to zero, setting the first flag, and setting the block type
	/// </summary>
	///
	/// <param name="Value">The UBI block type of the new block</param>
	static void StartNewBlockType(std::vector<ulong> &Tweak, const SkeinUbiType Value)
	{
		Tweak[0] = 0;
		BlockType(Tweak, Value);
		IsFirstBlock(Tweak, true);
	}

	/// <summary>
	/// Sets the number of bits processed so far, inclusive
	/// </summary>
	static void SetBitsProcessed(std::vector<ulong> &Tweak, ulong Value)
	{
		Tweak[0] = Value;
	}

};

NAMESPACE_DIGESTEND
#endif