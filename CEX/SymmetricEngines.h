#ifndef CEX_SYMMETRICENGINES_H
#define CEX_SYMMETRICENGINES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric encryption ciphers enumeration names
/// </summary>
enum class SymmetricEngines : byte
{
	/// <summary>
	/// No symmetric cipher is specified
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
	/// An implementation based on the Twofish Block Cipher
	/// </summary>
	Twofish = 3,
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
	SHX = 34,
	/// <summary>
	/// An implementation based on the Twofish Block Cipher extended with an HKDF key schedule
	/// </summary>
	THX = 35,
	/// <summary>
	/// An implementation of the ChaCha stream cipher
	/// </summary>
	ChaCha20 = 64,
	/// <summary>
	/// An implementation of the Salsa stream cipher
	/// </summary>
	Salsa = 65
};

NAMESPACE_ENUMERATIONEND
#endif
