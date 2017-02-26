#ifndef _CEX_BLOCKCIPHERS_H
#define _CEX_BLOCKCIPHERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Symmetric block cipher enmumeration names
/// </summary>
enum class BlockCiphers : uint8_t
{
	/// <summary>
	/// No block cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// An AES-NI implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF key schedule
	/// </summary>
	AHX = 1,
	/// <summary>
	/// An implementation based on the Rijndael Block Cipher
	/// </summary>
	Rijndael = 2,
	/// <summary>
	/// An implementation based on the Rijndael Block Cipher extended with an HKDF key schedule
	/// </summary>
	RHX = 4,
	/// <summary>
	/// An implementation based on the Serpent Block Cipher
	/// </summary>
	Serpent = 8,
	/// <summary>
	/// An implementation based on the Serpent Block Cipher extended with an HKDF key schedule
	/// </summary>
	SHX = 16,
	/// <summary>
	/// An implementation based on the Twofish Block Cipher
	/// </summary>
	Twofish = 32,
	/// <summary>
	/// An implementation based on the Twofish Block Cipher extended with an HKDF key schedule
	/// </summary>
	THX = 64
};

NAMESPACE_ENUMERATIONEND
#endif

