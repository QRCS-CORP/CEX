#ifndef CEX_BLOCKCIPHERS_H
#define CEX_BLOCKCIPHERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric block cipher enmumeration names
/// <para>Note: HX ciphers are always ordinally higher in value than standard ciphers.</para>
/// </summary>
enum class BlockCiphers : byte
{
	/// <summary>
	/// No block cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// An implementation based on the Rijndael Block Cipher
	/// </summary>
	Rijndael = 1,
	/// <summary>
	/// An implementation based on the Serpent Block Cipher
	/// </summary>
	Serpent = 2,
	/// <summary>
	/// An AES-NI implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF key schedule
	/// </summary>
	AHX = 32,
	/// <summary>
	/// An implementation based on the Rijndael Block Cipher extended with an HKDF key schedule
	/// </summary>
	RHX = 33,
	/// <summary>
	/// An implementation based on the Serpent Block Cipher extended with an HKDF key schedule
	/// </summary>
	SHX = 34
};

NAMESPACE_ENUMERATIONEND
#endif

